use actix_web::{error::ResponseError, HttpResponse};
use derive_more::Display;
use serde::Serialize;

#[derive(Debug, Display)]
pub enum ServiceError {
    #[display(fmt = "Internal Server Error: {}", _0)]
    InternalServerError(String),
    
    #[display(fmt = "Bad Request: {}", _0)]
    BadRequest(String),
    
    #[display(fmt = "Unauthorized: {}", _0)]
    Unauthorized(String),
    
    #[display(fmt = "Forbidden: {}", _0)]
    Forbidden(String),
    
    #[display(fmt = "Not Found: {}", _0)]
    NotFound(String),
    
    #[display(fmt = "Validation Error: {}", _0)]
    ValidationError(String),
    
    #[display(fmt = "Configuration Error: {}", _0)]
    ConfigurationError(String),
    
    #[display(fmt = "SAML Error: {}", _0)]
    SamlError(String),
}

#[derive(Serialize)]
struct ErrorResponse {
    code: u16,
    message: String,
}

impl ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        
        HttpResponse::build(status_code).json(ErrorResponse {
            code: status_code.as_u16(),
            message: self.to_string(),
        })
    }
    
    fn status_code(&self) -> actix_web::http::StatusCode {
        match *self {
            ServiceError::InternalServerError(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            ServiceError::BadRequest(_) => actix_web::http::StatusCode::BAD_REQUEST,
            ServiceError::Unauthorized(_) => actix_web::http::StatusCode::UNAUTHORIZED,
            ServiceError::Forbidden(_) => actix_web::http::StatusCode::FORBIDDEN,
            ServiceError::NotFound(_) => actix_web::http::StatusCode::NOT_FOUND,
            ServiceError::ValidationError(_) => actix_web::http::StatusCode::BAD_REQUEST,
            ServiceError::ConfigurationError(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            ServiceError::SamlError(_) => actix_web::http::StatusCode::BAD_REQUEST,
        }
    }
}

impl From<std::io::Error> for ServiceError {
    fn from(err: std::io::Error) -> Self {
        ServiceError::InternalServerError(err.to_string())
    }
}