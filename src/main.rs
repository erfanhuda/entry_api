use actix_web::{web, HttpServer};

mod handlers;
mod identity;
mod metrics;
mod saml;
mod error;
mod config;

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