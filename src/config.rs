use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use crate::error::ServiceError;
use crate::saml::ServiceProvider;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub bind_address: String,
    pub workers: usize,
    pub use_ssl: bool,
    pub ssl_cert: String,
    pub ssl_key: String,
    pub log_level: String,
    pub saml: SamlConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    pub entity_id: String,
    pub base_url: String,
    pub private_key_path: String,
    pub certificate_path: String,
    pub service_providers: Vec<ServiceProvider>,
}

impl AppConfig {
    pub fn load() -> Result<Self, ServiceError> {
        // Try to load from environment variables first
        if let Ok(config) = Self::from_env() {
            return Ok(config);
        }
        
        // Then try to load from config file
        let config_path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.json".to_string());
        Self::from_file(&config_path)
    }
    
    fn from_env() -> Result<Self, ServiceError> {
        let bind_address = std::env::var("BIND_ADDRESS")
            .map_err(|_| ServiceError::ConfigurationError("BIND_ADDRESS not set".to_string()))?;
        
        let workers = std::env::var("WORKERS")
            .unwrap_or_else(|_| num_cpus::get().to_string())
            .parse::<usize>()
            .map_err(|e| ServiceError::ConfigurationError(format!("Invalid WORKERS: {}", e)))?;
        
        let use_ssl = std::env::var("USE_SSL")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .map_err(|e| ServiceError::  "false".to_string())
            .parse::<bool>()
            .map_err(|e| ServiceError::ConfigurationError(format!("Invalid USE_SSL: {}", e)))?;
        
        let ssl_cert = if use_ssl {
            std::env::var("SSL_CERT")
                .map_err(|_| ServiceError::ConfigurationError("SSL_CERT not set".to_string()))?
        } else {
            String::new()
        };
        
        let ssl_key = if use_ssl {
            std::env::var("SSL_KEY")
                .map_err(|_| ServiceError::ConfigurationError("SSL_KEY not set".to_string()))?
        } else {
            String::new()
        };
        
        let log_level = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
        
        let entity_id = std::env::var("SAML_ENTITY_ID")
            .map_err(|_| ServiceError::ConfigurationError("SAML_ENTITY_ID not set".to_string()))?;
        
        let base_url = std::env::var("SAML_BASE_URL")
            .map_err(|_| ServiceError::ConfigurationError("SAML_BASE_URL not set".to_string()))?;
        
        let private_key_path = std::env::var("SAML_PRIVATE_KEY_PATH")
            .map_err(|_| ServiceError::ConfigurationError("SAML_PRIVATE_KEY_PATH not set".to_string()))?;
        
        let certificate_path = std::env::var("SAML_CERTIFICATE_PATH")
            .map_err(|_| ServiceError::ConfigurationError("SAML_CERTIFICATE_PATH not set".to_string()))?;
        
        // Service providers would typically be loaded from a database or a separate config file
        // For simplicity, we'll just create an empty list here
        let service_providers = Vec::new();
        
        Ok(Self {
            bind_address,
            workers,
            use_ssl,
            ssl_cert,
            ssl_key,
            log_level,
            saml: SamlConfig {
                entity_id,
                base_url,
                private_key_path,
                certificate_path,
                service_providers,
            },
        })
    }
    
    fn from_file(path: &str) -> Result<Self, ServiceError> {
        let mut file = File::open(path)
            .map_err(|e| ServiceError::ConfigurationError(format!("Failed to open config file: {}", e)))?;
        
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| ServiceError::ConfigurationError(format!("Failed to read config file: {}", e)))?;
        
        serde_json::from_str(&contents)
            .map_err(|e| ServiceError::ConfigurationError(format!("Failed to parse config file: {}", e)))
    }
}