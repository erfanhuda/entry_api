use crate::config::AppConfig;
use crate::error::ServiceError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use tokio::sync::RwLock;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub username: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub attributes: HashMap<String, Vec<String>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityQuery {
    pub username: Option<String>,
    pub email: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub struct IdentityStore {
    identities: HashMap<String, Identity>,
    config: AppConfig,
}

impl IdentityStore {
    pub async fn new(config: &AppConfig) -> Result<Self, std::io::Error> {
        // In a real implementation, you would load identities from a database
        // For this example, we'll just create an empty store
        Ok(Self {
            identities: HashMap::new(),
            config: config.clone(),
        })
    }
    
    pub async fn list(&self, query: &IdentityQuery) -> Result<Vec<Identity>, ServiceError> {
        let mut result: Vec<Identity> = self.identities.values().cloned().collect();
        
        // Apply filters
        if let Some(username) = &query.username {
            result.retain(|identity| identity.username.contains(username));
        }
        
        if let Some(email) = &query.email {
            result.retain(|identity| identity.email.contains(email));
        }
        
        // Apply pagination
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(100);
        
        if offset < result.len() {
            let end = std::cmp::min(offset + limit, result.len());
            result = result[offset..end].to_vec();
        } else {
            result = Vec::new();
        }
        
        Ok(result)
    }
    
    pub async fn get(&self, id: &str) -> Result<Identity, ServiceError> {
        self.identities.get(id)
            .cloned()
            .ok_or_else(|| ServiceError::NotFound(format!("Identity not found: {}", id)))
    }
    
    pub async fn create(&mut self, mut identity: Identity) -> Result<String, ServiceError> {
        let now = chrono::Utc::now();
        
        // Generate ID if not provided
        if identity.id.is_empty() {
            identity.id = Uuid::new_v4().to_string();
        }
        
        // Set timestamps
        identity.created_at = now;
        identity.updated_at = now;
        
        // Validate
        if identity.username.is_empty() {
            return Err(ServiceError::ValidationError("Username cannot be empty".to_string()));
        }
        
        if identity.email.is_empty() {
            return Err(ServiceError::ValidationError("Email cannot be empty".to_string()));
        }
        
        // Check for duplicates
        for existing in self.identities.values() {
            if existing.username == identity.username {
                return Err(ServiceError::ValidationError(format!("Username already exists: {}", identity.username)));
            }
            
            if existing.email == identity.email {
                return Err(ServiceError::ValidationError(format!("Email already exists: {}", identity.email)));
            }
        }
        
        let id = identity.id.clone();
        self.identities.insert(id.clone(), identity);
        
        Ok(id)
    }
    
    pub async fn update(&mut self, id: &str, mut identity: Identity) -> Result<(), ServiceError> {
        let existing = self.identities.get(id)
            .ok_or_else(|| ServiceError::NotFound(format!("Identity not found: {}", id)))?;
        
        // Preserve ID and created_at
        identity.id = existing.id.clone();
        identity.created_at = existing.created_at;
        identity.updated_at = chrono::Utc::now();
        
        // Validate
        if identity.username.is_empty() {
            return Err(ServiceError::ValidationError("Username cannot be empty".to_string()));
        }
        
        if identity.email.is_empty() {
            return Err(ServiceError::ValidationError("Email cannot be empty".to_string()));
        }
        
        // Check for duplicates (excluding self)
        for (existing_id, existing) in &self.identities {
            if existing_id != id {
                if existing.username == identity.username {
                    return Err(ServiceError::ValidationError(format!("Username already exists: {}", identity.username)));
                }
                
                if existing.email == identity.email {
                    return Err(ServiceError::ValidationError(format!("Email already exists: {}", identity.email)));
                }
            }
        }
        
        self.identities.insert(id.to_string(), identity);
        
        Ok(())
    }
    
    pub async fn delete(&mut self, id: &str) -> Result<(), ServiceError> {
        if self.identities.remove(id).is_none() {
            return Err(ServiceError::NotFound(format!("Identity not found: {}", id)));
        }
        
        Ok(())
    }
}