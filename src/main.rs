use actix_web::{web, App, HttpServer, Middleware, HttpResponse, Error};
use actix_web::dev::{Service, Transform, ServiceRequest, ServiceResponse};
use futures::future::{ok, Ready};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use config::{Config, ConfigError, File};
use log::{info, error, debug};
use env_logger::Env;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

mod saml;
mod identity;
mod error;
mod config;
mod metrics;

use crate::saml::SamlProcessor;
use crate::identity::IdentityStore;
use crate::error::ServiceError;
use crate::config::AppConfig;
use crate::metrics::MetricsCollector;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("Starting SAML Identity Provider Service");

    // Load configuration
    let config = match AppConfig::load() {
        Ok(config) => {
            info!("Configuration loaded successfully");
            config
        },
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Configuration error"));
        }
    };

    // Initialize identity store
    let identity_store = Arc::new(RwLock::new(IdentityStore::new(&config).await?));
    
    // Initialize SAML processor
    let saml_processor = Arc::new(SamlProcessor::new(&config)?);
    
    // Initialize metrics collector
    let metrics_collector = Arc::new(MetricsCollector::new());

    // Configure SSL if enabled
    let server = if config.use_ssl {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder.set_private_key_file(&config.ssl_key, SslFiletype::PEM).unwrap();
        builder.set_certificate_chain_file(&config.ssl_cert).unwrap();
        
        HttpServer::new(move || {
            App::new()
                .wrap(RequestLogger)
                .wrap(metrics_collector.clone())
                .app_data(web::Data::new(identity_store.clone()))
                .app_data(web::Data::new(saml_processor.clone()))
                .app_data(web::Data::new(config.clone()))
                .configure(routes::configure)
        })
        .bind_openssl(&config.bind_address, builder)?
    } else {
        HttpServer::new(move || {
            App::new()
                .wrap(RequestLogger)
                .wrap(metrics_collector.clone())
                .app_data(web::Data::new(identity_store.clone()))
                .app_data(web::Data::new(saml_processor.clone()))
                .app_data(web::Data::new(config.clone()))
                .configure(routes::configure)
        })
        .bind(&config.bind_address)?
    };

    info!("Server running at {}", config.bind_address);
    server.workers(config.workers).run().await
}

// Request logger middleware
struct RequestLogger;

impl<S, B> Transform<S, ServiceRequest> for RequestLogger
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestLoggerMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RequestLoggerMiddleware { service })
    }
}

struct RequestLoggerMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestLoggerMiddleware<S>
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
        let start = std::time::Instant::now();
        let method = req.method().clone();
        let path = req.path().to_owned();

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            let elapsed = start.elapsed();
            info!(
                "{} {} {} {}ms",
                method,
                path,
                res.status().as_u16(),
                elapsed.as_millis()
            );
            Ok(res)
        })
    }
}

mod routes {
    use super::*;
    use actix_web::{web, HttpResponse, Responder};

    pub fn configure(cfg: &mut web::ServiceConfig) {
        cfg.service(
            web::scope("/saml")
                .route("/metadata", web::get().to(metadata))
                .route("/sso", web::post().to(handle_sso_request))
                .route("/sso", web::get().to(handle_sso_request))
                .route("/slo", web::post().to(handle_slo_request))
                .route("/slo", web::get().to(handle_slo_request))
        )
        .service(
            web::scope("/api")
                .route("/health", web::get().to(health_check))
                .route("/metrics", web::get().to(metrics))
                .service(
                    web::scope("/identity")
                        .route("", web::get().to(get_identities))
                        .route("", web::post().to(create_identity))
                        .route("/{id}", web::get().to(get_identity))
                        .route("/{id}", web::put().to(update_identity))
                        .route("/{id}", web::delete().to(delete_identity))
                )
        );
    }

    async fn metadata(
        saml_processor: web::Data<Arc<SamlProcessor>>,
        config: web::Data<AppConfig>,
    ) -> Result<HttpResponse, ServiceError> {
        let metadata = saml_processor.generate_metadata(&config)?;
        Ok(HttpResponse::Ok()
            .content_type("application/xml")
            .body(metadata))
    }

    async fn handle_sso_request(
        saml_processor: web::Data<Arc<SamlProcessor>>,
        identity_store: web::Data<Arc<RwLock<IdentityStore>>>,
        config: web::Data<AppConfig>,
        req: actix_web::HttpRequest,
        body: web::Bytes,
    ) -> Result<HttpResponse, ServiceError> {
        let response = saml_processor.handle_sso_request(
            &req, 
            body, 
            &identity_store, 
            &config
        ).await?;
        
        Ok(response)
    }

    async fn handle_slo_request(
        saml_processor: web::Data<Arc<SamlProcessor>>,
        identity_store: web::Data<Arc<RwLock<IdentityStore>>>,
        config: web::Data<AppConfig>,
        req: actix_web::HttpRequest,
        body: web::Bytes,
    ) -> Result<HttpResponse, ServiceError> {
        let response = saml_processor.handle_slo_request(
            &req, 
            body, 
            &identity_store, 
            &config
        ).await?;
        
        Ok(response)
    }

    async fn health_check() -> impl Responder {
        HttpResponse::Ok().json(serde_json::json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION")
        }))
    }

    async fn metrics(
        metrics_collector: web::Data<Arc<MetricsCollector>>,
    ) -> impl Responder {
        let metrics = metrics_collector.collect();
        HttpResponse::Ok().json(metrics)
    }

    async fn get_identities(
        identity_store: web::Data<Arc<RwLock<IdentityStore>>>,
        query: web::Query<identity::IdentityQuery>,
    ) -> Result<HttpResponse, ServiceError> {
        let store = identity_store.read().await;
        let identities = store.list(&query).await?;
        Ok(HttpResponse::Ok().json(identities))
    }

    async fn create_identity(
        identity_store: web::Data<Arc<RwLock<IdentityStore>>>,
        identity: web::Json<identity::Identity>,
    ) -> Result<HttpResponse, ServiceError> {
        let mut store = identity_store.write().await;
        let id = store.create(identity.into_inner()).await?;
        Ok(HttpResponse::Created().json(serde_json::json!({ "id": id })))
    }

    async fn get_identity(
        identity_store: web::Data<Arc<RwLock<IdentityStore>>>,
        id: web::Path<String>,
    ) -> Result<HttpResponse, ServiceError> {
        let store = identity_store.read().await;
        let identity = store.get(&id).await?;
        Ok(HttpResponse::Ok().json(identity))
    }

    async fn update_identity(
        identity_store: web::Data<Arc<RwLock<IdentityStore>>>,
        id: web::Path<String>,
        identity: web::Json<identity::Identity>,
    ) -> Result<HttpResponse, ServiceError> {
        let mut store = identity_store.write().await;
        store.update(&id, identity.into_inner()).await?;
        Ok(HttpResponse::Ok().finish())
    }

    async fn delete_identity(
        identity_store: web::Data<Arc<RwLock<IdentityStore>>>,
        id: web::Path<String>,
    ) -> Result<HttpResponse, ServiceError> {
        let mut store = identity_store.write().await;
        store.delete(&id).await?;
        Ok(HttpResponse::NoContent().finish())
    }
}