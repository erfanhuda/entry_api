use actix_web::dev::{Service, Transform, ServiceRequest, ServiceResponse};
use actix_web::Error;
use futures::future::{ok, Ready};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct Metrics {
    pub requests_total: usize,
    pub requests_success: usize,
    pub requests_error: usize,
    pub requests_by_path: HashMap<String, usize>,
    pub average_response_time_ms: f64,
    pub uptime_seconds: u64,
}

pub struct MetricsCollector {
    requests_total: AtomicUsize,
    requests_success: AtomicUsize,
    requests_error: AtomicUsize,
    requests_by_path: dashmap::DashMap<String, usize>,
    response_time_sum: AtomicUsize,
    response_time_count: AtomicUsize,
    start_time: Instant,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            requests_total: AtomicUsize::new(0),
            requests_success: AtomicUsize::new(0),
            requests_error: AtomicUsize::new(0),
            requests_by_path: dashmap::DashMap::new(),
            response_time_sum: AtomicUsize::new(0),
            response_time_count: AtomicUsize::new(0),
            start_time: Instant::now(),
        }
    }
    
    pub fn collect(&self) -> Metrics {
        let requests_by_path = self.requests_by_path
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect();
        
        let response_time_sum = self.response_time_sum.load(Ordering::Relaxed) as f64;
        let response_time_count = self.response_time_count.load(Ordering::Relaxed) as f64;
        let average_response_time = if response_time_count > 0.0 {
            response_time_sum / response_time_count
        } else {
            0.0
        };
        
        Metrics {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_success: self.requests_success.load(Ordering::Relaxed),
            requests_error: self.requests_error.load(Ordering::Relaxed),
            requests_by_path,
            average_response_time_ms: average_response_time,
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Arc<MetricsCollector>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = MetricsMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(MetricsMiddleware {
            service,
            metrics: self.clone(),
        })
    }
}

pub struct MetricsMiddleware<S> {
    service: S,
    metrics: Arc<MetricsCollector>,
}

impl<S, B> Service<ServiceRequest> for MetricsMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let metrics = self.metrics.clone();
        let path = req.path().to_owned();
        let start = Instant::now();
        
        metrics.requests_total.fetch_add(1, Ordering::Relaxed);
        
        let fut = self.service.call(req);
        
        Box::pin(async move {
            let res = fut.await;
            let elapsed = start.elapsed();
            let elapsed_ms = elapsed.as_millis() as usize;
            
            metrics.response_time_sum.fetch_add(elapsed_ms, Ordering::Relaxed);
            metrics.response_time_count.fetch_add(1, Ordering::Relaxed);
            
            // Update path counter
            metrics.requests_by_path
                .entry(path)
                .and_modify(|count| *count += 1)
                .or_insert(1);
            
            match &res {
                Ok(response) => {
                    if response.status().is_success() {
                        metrics.requests_success.fetch_add(1, Ordering::Relaxed);
                    } else {
                        metrics.requests_error.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    metrics.requests_error.fetch_add(1, Ordering::Relaxed);
                }
            }
            
            res
        })
    }
}