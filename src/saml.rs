use crate::config::AppConfig;
use crate::error::ServiceError;
use crate::identity::IdentityStore;
use actix_web::{HttpRequest, HttpResponse};
use chrono::{DateTime, Duration, Utc};
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::x509::X509;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use xml::writer::{EventWriter, XmlEvent};
use xml::reader::{EventReader, XmlEvent as XmlReadEvent};
use base64::{engine::general_purpose, Engine as _};
use std::io::Cursor;
use log::{debug, error, info, warn};
use zlib::{Compression, Deflater};

pub struct SamlProcessor {
    private_key: PKey<Private>,
    certificate: X509,
    service_providers: HashMap<String, ServiceProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceProvider {
    pub entity_id: String,
    pub assertion_consumer_service_url: String,
    pub single_logout_service_url: Option<String>,
    pub name_id_format: String,
    pub signing_cert: Option<String>,
    pub encryption_cert: Option<String>,
    pub want_assertions_signed: bool,
    pub want_response_signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlRequest {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub assertion_consumer_service_url: String,
    pub issuer: String,
    pub name_id_policy_format: String,
    pub relay_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlResponse {
    pub id: String,
    pub in_response_to: String,
    pub issue_instant: DateTime<Utc>,
    pub destination: String,
    pub issuer: String,
    pub status_code: String,
    pub assertion: Option<SamlAssertion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    pub id: String,
    pub issue_instant: DateTime<Utc>,
    pub issuer: String,
    pub subject: SamlSubject,
    pub conditions: SamlConditions,
    pub authentication_statement: SamlAuthenticationStatement,
    pub attribute_statement: Option<SamlAttributeStatement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubject {
    pub name_id: String,
    pub name_id_format: String,
    pub subject_confirmation_method: String,
    pub subject_confirmation_data: SamlSubjectConfirmationData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlSubjectConfirmationData {
    pub not_on_or_after: DateTime<Utc>,
    pub recipient: String,
    pub in_response_to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConditions {
    pub not_before: DateTime<Utc>,
    pub not_on_or_after: DateTime<Utc>,
    pub audience_restriction: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthenticationStatement {
    pub authn_instant: DateTime<Utc>,
    pub session_index: String,
    pub authn_context_class_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAttributeStatement {
    pub attributes: HashMap<String, Vec<String>>,
}

impl SamlProcessor {
    pub fn new(config: &AppConfig) -> Result<Self, ServiceError> {
        // Load private key
        let mut key_file = File::open(&config.saml.private_key_path)
            .map_err(|e| ServiceError::ConfigurationError(format!("Failed to open private key file: {}", e)))?;
        let mut key_content = Vec::new();
        key_file.read_to_end(&mut key_content)
            .map_err(|e| ServiceError::ConfigurationError(format!("Failed to read private key file: {}", e)))?;
        let private_key = PKey::private_key_from_pem(&key_content)
            .map_err(|e| ServiceError::ConfigurationError(format!("Failed to parse private key: {}", e)))?;

        // Load certificate
        let mut cert_file = File::open(&config.saml.certificate_path)
            .map_err(|e| ServiceError::ConfigurationError(format!("Failed to open certificate file: {}", e)))?;
        let mut cert_content = Vec::new();
        cert_file.read_to_end(&mut cert_content)
            .map_err(|e| ServiceError::ConfigurationError(format!("Failed to read certificate file: {}", e)))?;
        let certificate = X509::from_pem(&cert_content)
            .map_err(|e| ServiceError::ConfigurationError(format!("Failed to parse certificate: {}", e)))?;

        // Load service providers
        let mut service_providers = HashMap::new();
        for sp_config in &config.saml.service_providers {
            service_providers.insert(sp_config.entity_id.clone(), sp_config.clone());
        }

        Ok(Self {
            private_key,
            certificate,
            service_providers,
        })
    }

    pub fn generate_metadata(&self, config: &AppConfig) -> Result<String, ServiceError> {
        let mut writer = EventWriter::new(Vec::new());
        
        // XML declaration
        writer.write(XmlEvent::StartDocument {
            version: xml::common::XmlVersion::Version10,
            encoding: Some("UTF-8"),
            standalone: None,
        }).map_err(|e| ServiceError::SamlError(format!("Failed to write XML declaration: {}", e)))?;
        
        // EntityDescriptor
        let ns_md = "urn:oasis:names:tc:SAML:2.0:metadata";
        let ns_ds = "http://www.w3.org/2000/09/xmldsig#";
        let ns_saml = "urn:oasis:names:tc:SAML:2.0:assertion";
        
        writer.write(XmlEvent::start_element("EntityDescriptor")
            .default_ns(ns_md)
            .ns("ds", ns_ds)
            .ns("saml", ns_saml)
            .attr("entityID", &config.saml.entity_id)
        ).map_err(|e| ServiceError::SamlError(format!("Failed to write EntityDescriptor: {}", e)))?;
        
        // IDPSSODescriptor
        writer.write(XmlEvent::start_element("IDPSSODescriptor")
            .attr("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol")
            .attr("WantAuthnRequestsSigned", "true")
        ).map_err(|e| ServiceError::SamlError(format!("Failed to write IDPSSODescriptor: {}", e)))?;
        
        // KeyDescriptor for signing
        writer.write(XmlEvent::start_element("KeyDescriptor")
            .attr("use", "signing")
        ).map_err(|e| ServiceError::SamlError(format!("Failed to write KeyDescriptor: {}", e)))?;
        
        writer.write(XmlEvent::start_element("ds:KeyInfo"))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write KeyInfo: {}", e)))?;
        
        writer.write(XmlEvent::start_element("ds:X509Data"))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write X509Data: {}", e)))?;
        
        writer.write(XmlEvent::start_element("ds:X509Certificate"))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write X509Certificate: {}", e)))?;
        
        // Get certificate data without header and footer
        let cert_pem = self.certificate.to_pem()
            .map_err(|e| ServiceError::SamlError(format!("Failed to convert certificate to PEM: {}", e)))?;
        let cert_str = String::from_utf8_lossy(&cert_pem);
        let cert_data = cert_str
            .lines()
            .filter(|line| !line.contains("BEGIN CERTIFICATE") && !line.contains("END CERTIFICATE"))
            .collect::<Vec<&str>>()
            .join("");
        
        writer.write(XmlEvent::Characters(&cert_data))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write certificate data: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // ds:X509Certificate
            .map_err(|e| ServiceError::SamlError(format!("Failed to end X509Certificate: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // ds:X509Data
            .map_err(|e| ServiceError::SamlError(format!("Failed to end X509Data: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // ds:KeyInfo
            .map_err(|e| ServiceError::SamlError(format!("Failed to end KeyInfo: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // KeyDescriptor
            .map_err(|e| ServiceError::SamlError(format!("Failed to end KeyDescriptor: {}", e)))?;
        
        // KeyDescriptor for encryption (same as signing in this case)
        writer.write(XmlEvent::start_element("KeyDescriptor")
            .attr("use", "encryption")
        ).map_err(|e| ServiceError::SamlError(format!("Failed to write KeyDescriptor: {}", e)))?;
        
        writer.write(XmlEvent::start_element("ds:KeyInfo"))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write KeyInfo: {}", e)))?;
        
        writer.write(XmlEvent::start_element("ds:X509Data"))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write X509Data: {}", e)))?;
        
        writer.write(XmlEvent::start_element("ds:X509Certificate"))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write X509Certificate: {}", e)))?;
        
        writer.write(XmlEvent::Characters(&cert_data))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write certificate data: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // ds:X509Certificate
            .map_err(|e| ServiceError::SamlError(format!("Failed to end X509Certificate: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // ds:X509Data
            .map_err(|e| ServiceError::SamlError(format!("Failed to end X509Data: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // ds:KeyInfo
            .map_err(|e| ServiceError::SamlError(format!("Failed to end KeyInfo: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // KeyDescriptor
            .map_err(|e| ServiceError::SamlError(format!("Failed to end KeyDescriptor: {}", e)))?;
        
        // NameIDFormat
        writer.write(XmlEvent::start_element("NameIDFormat"))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write NameIDFormat: {}", e)))?;
        
        writer.write(XmlEvent::Characters("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write NameIDFormat value: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // NameIDFormat
            .map_err(|e| ServiceError::SamlError(format!("Failed to end NameIDFormat: {}", e)))?;
        
        // SingleSignOnService
        writer.write(XmlEvent::start_element("SingleSignOnService")
            .attr("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
            .attr("Location", &format!("{}/saml/sso", config.saml.base_url))
        ).map_err(|e| ServiceError::SamlError(format!("Failed to write SingleSignOnService: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // SingleSignOnService
            .map_err(|e| ServiceError::SamlError(format!("Failed to end SingleSignOnService: {}", e)))?;
        
        // SingleSignOnService (POST binding)
        writer.write(XmlEvent::start_element("SingleSignOnService")
            .attr("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
            .attr("Location", &format!("{}/saml/sso", config.saml.base_url))
        ).map_err(|e| ServiceError::SamlError(format!("Failed to write SingleSignOnService: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // SingleSignOnService
            .map_err(|e| ServiceError::SamlError(format!("Failed to end SingleSignOnService: {}", e)))?;
        
        // SingleLogoutService
        writer.write(XmlEvent::start_element("SingleLogoutService")
            .attr("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
            .attr("Location", &format!("{}/saml/slo", config.saml.base_url))
        ).map_err(|e| ServiceError::SamlError(format!("Failed to write SingleLogoutService: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // SingleLogoutService
            .map_err(|e| ServiceError::SamlError(format!("Failed to end SingleLogoutService: {}", e)))?;
        
        // SingleLogoutService (POST binding)
        writer.write(XmlEvent::start_element("SingleLogoutService")
            .attr("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
            .attr("Location", &format!("{}/saml/slo", config.saml.base_url))
        ).map_err(|e| ServiceError::SamlError(format!("Failed to write SingleLogoutService: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // SingleLogoutService
            .map_err(|e| ServiceError::SamlError(format!("Failed to end SingleLogoutService: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // IDPSSODescriptor
            .map_err(|e| ServiceError::SamlError(format!("Failed to end IDPSSODescriptor: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // EntityDescriptor
            .map_err(|e| ServiceError::SamlError(format!("Failed to end EntityDescriptor: {}", e)))?;
        
        let result = writer.into_inner();
        let xml_string = String::from_utf8(result)
            .map_err(|e| ServiceError::SamlError(format!("Failed to convert XML to string: {}", e)))?;
        
        Ok(xml_string)
    }

    pub async fn handle_sso_request(
        &self,
        req: &HttpRequest,
        body: web::Bytes,
        identity_store: &Arc<RwLock<IdentityStore>>,
        config: &AppConfig,
    ) -> Result<HttpResponse, ServiceError> {
        let method = req.method();
        let saml_request = if method == actix_web::http::Method::GET {
            // Handle HTTP-Redirect binding
            let query_params = req.query_string();
            let params: HashMap<_, _> = url::form_urlencoded::parse(query_params.as_bytes()).into_owned().collect();
            
            let saml_request = params.get("SAMLRequest")
                .ok_or_else(|| ServiceError::SamlError("Missing SAMLRequest parameter".to_string()))?;
            
            let relay_state = params.get("RelayState").map(|s| s.to_string());
            
            // Decode and inflate the request
            let decoded = general_purpose::STANDARD.decode(saml_request)
                .map_err(|e| ServiceError::SamlError(format!("Failed to decode SAMLRequest: {}", e)))?;
            
            let mut decoder = Deflater::new();
            let inflated = decoder.decompress_vec(&decoded)
                .map_err(|e| ServiceError::SamlError(format!("Failed to inflate SAMLRequest: {}", e)))?;
            
            let xml_str = String::from_utf8(inflated)
                .map_err(|e| ServiceError::SamlError(format!("Failed to convert inflated data to string: {}", e)))?;
            
            self.parse_authn_request(&xml_str, relay_state)?
        } else {
            // Handle HTTP-POST binding
            let params: HashMap<_, _> = url::form_urlencoded::parse(&body).into_owned().collect();
            
            let saml_request = params.get("SAMLRequest")
                .ok_or_else(|| ServiceError::SamlError("Missing SAMLRequest parameter".to_string()))?;
            
            let relay_state = params.get("RelayState").map(|s| s.to_string());
            
            // Decode the request
            let decoded = general_purpose::STANDARD.decode(saml_request)
                .map_err(|e| ServiceError::SamlError(format!("Failed to decode SAMLRequest: {}", e)))?;
            
            let xml_str = String::from_utf8(decoded)
                .map_err(|e| ServiceError::SamlError(format!("Failed to convert decoded data to string: {}", e)))?;
            
            self.parse_authn_request(&xml_str, relay_state)?
        };
        
        // Validate the request
        let sp = self.service_providers.get(&saml_request.issuer)
            .ok_or_else(|| ServiceError::SamlError(format!("Unknown service provider: {}", saml_request.issuer)))?;
        
        // In a real implementation, you would authenticate the user here
        // For this example, we'll just create a dummy user
        let user_id = "user123".to_string();
        let user_email = "user@example.com".to_string();
        
        // Generate SAML response
        let response = self.generate_saml_response(&saml_request, &user_id, &user_email, sp, config)?;
        
        // Convert response to XML
        let response_xml = self.serialize_saml_response(&response, sp)?;
        
        // Encode response for POST binding
        let encoded_response = general_purpose::STANDARD.encode(response_xml.as_bytes());
        
        // Generate HTML form for auto-submission
        let html = format!(
            r#"<!DOCTYPE html>
            <html>
            <head>
                <title>SAML Response</title>
                <script>
                    window.onload = function() {
                        document.forms[0].submit();
                    };
                </script>
            </head>
            <body>
                <form method="post" action="{}" autocomplete="off">
                    <input type="hidden" name="SAMLResponse" value="{}" />
                    {}
                    <noscript>
                        <p>JavaScript is disabled. Click the button below to continue.</p>
                        <input type="submit" value="Continue" />
                    </noscript>
                </form>
            </body>
            </html>"#,
            sp.assertion_consumer_service_url,
            encoded_response,
            if let Some(relay_state) = saml_request.relay_state {
                format!(r#"<input type="hidden" name="RelayState" value="{}" />"#, relay_state)
            } else {
                String::new()
            }
        );
        
        Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html))
    }

    pub async fn handle_slo_request(
        &self,
        req: &HttpRequest,
        body: web::Bytes,
        identity_store: &Arc<RwLock<IdentityStore>>,
        config: &AppConfig,
    ) -> Result<HttpResponse, ServiceError> {
        // Implementation for Single Logout
        // This would parse the logout request, validate it, and generate a logout response
        
        // For simplicity, we'll just return a success response
        Ok(HttpResponse::Ok().body("Logout successful"))
    }

    fn parse_authn_request(&self, xml_str: &str, relay_state: Option<String>) -> Result<SamlRequest, ServiceError> {
        let reader = EventReader::from_str(xml_str);
        
        let mut id = None;
        let mut issue_instant = None;
        let mut assertion_consumer_service_url = None;
        let mut issuer = None;
        let mut name_id_policy_format = None;
        
        for event in reader {
            match event {
                Ok(XmlReadEvent::StartElement { name, attributes, .. }) => {
                    if name.local_name == "AuthnRequest" {
                        for attr in attributes {
                            match attr.name.local_name.as_str() {
                                "ID" => id = Some(attr.value),
                                "IssueInstant" => {
                                    issue_instant = Some(
                                        chrono::DateTime::parse_from_rfc3339(&attr.value)
                                            .map_err(|e| ServiceError::SamlError(format!("Invalid IssueInstant: {}", e)))?
                                            .with_timezone(&Utc)
                                    );
                                },
                                "AssertionConsumerServiceURL" => assertion_consumer_service_url = Some(attr.value),
                                _ => {}
                            }
                        }
                    } else if name.local_name == "Issuer" {
                        // Read the text content of the Issuer element
                        if let Ok(XmlReadEvent::Characters(content)) = reader.next().unwrap() {
                            issuer = Some(content);
                        }
                    } else if name.local_name == "NameIDPolicy" {
                        for attr in attributes {
                            if attr.name.local_name == "Format" {
                                name_id_policy_format = Some(attr.value);
                            }
                        }
                    }
                },
                Err(e) => return Err(ServiceError::SamlError(format!("XML parsing error: {}", e))),
                _ => {}
            }
        }
        
        Ok(SamlRequest {
            id: id.ok_or_else(|| ServiceError::SamlError("Missing ID in AuthnRequest".to_string()))?,
            issue_instant: issue_instant.ok_or_else(|| ServiceError::SamlError("Missing IssueInstant in AuthnRequest".to_string()))?,
            assertion_consumer_service_url: assertion_consumer_service_url
                .ok_or_else(|| ServiceError::SamlError("Missing AssertionConsumerServiceURL in AuthnRequest".to_string()))?,
            issuer: issuer.ok_or_else(|| ServiceError::SamlError("Missing Issuer in AuthnRequest".to_string()))?,
            name_id_policy_format: name_id_policy_format
                .unwrap_or_else(|| "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_string()),
            relay_state,
        })
    }

    fn generate_saml_response(
        &self,
        request: &SamlRequest,
        user_id: &str,
        user_email: &str,
        sp: &ServiceProvider,
        config: &AppConfig,
    ) -> Result<SamlResponse, ServiceError> {
        let now = Utc::now();
        let response_id = format!("_response_{}", Uuid::new_v4());
        let assertion_id = format!("_assertion_{}", Uuid::new_v4());
        let session_index = format!("_session_{}", Uuid::new_v4());
        
        // Create subject with confirmation data
        let subject = SamlSubject {
            name_id: user_id.to_string(),
            name_id_format: request.name_id_policy_format.clone(),
            subject_confirmation_method: "urn:oasis:names:tc:SAML:2.0:cm:bearer".to_string(),
            subject_confirmation_data: SamlSubjectConfirmationData {
                not_on_or_after: now + Duration::minutes(5),
                recipient: sp.assertion_consumer_service_url.clone(),
                in_response_to: request.id.clone(),
            },
        };
        
        // Create conditions
        let conditions = SamlConditions {
            not_before: now - Duration::minutes(5),
            not_on_or_after: now + Duration::minutes(5),
            audience_restriction: vec![sp.entity_id.clone()],
        };
        
        // Create authentication statement
        let authentication_statement = SamlAuthenticationStatement {
            authn_instant: now,
            session_index,
            authn_context_class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".to_string(),
        };
        
        // Create attribute statement
        let mut attributes = HashMap::new();
        attributes.insert("email".to_string(), vec![user_email.to_string()]);
        
        let attribute_statement = SamlAttributeStatement {
            attributes,
        };
        
        // Create assertion
        let assertion = SamlAssertion {
            id: assertion_id,
            issue_instant: now,
            issuer: config.saml.entity_id.clone(),
            subject,
            conditions,
            authentication_statement,
            attribute_statement: Some(attribute_statement),
        };
        
        // Create response
        let response = SamlResponse {
            id: response_id,
            in_response_to: request.id.clone(),
            issue_instant: now,
            destination: sp.assertion_consumer_service_url.clone(),
            issuer: config.saml.entity_id.clone(),
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string(),
            assertion: Some(assertion),
        };
        
        Ok(response)
    }

    fn serialize_saml_response(&self, response: &SamlResponse, sp: &ServiceProvider) -> Result<String, ServiceError> {
        let mut writer = EventWriter::new(Vec::new());
        
        // XML declaration
        writer.write(XmlEvent::StartDocument {
            version: xml::common::XmlVersion::Version10,
            encoding: Some("UTF-8"),
            standalone: None,
        }).map_err(|e| ServiceError::SamlError(format!("Failed to write XML declaration: {}", e)))?;
        
        // Response
        let ns_samlp = "urn:oasis:names:tc:SAML:2.0:protocol";
        let ns_saml = "urn:oasis:names:tc:SAML:2.0:assertion";
        let ns_ds = "http://www.w3.org/2000/09/xmldsig#";
        
        writer.write(XmlEvent::start_element("samlp:Response")
            .ns("samlp", ns_samlp)
            .ns("saml", ns_saml)
            .ns("ds", ns_ds)
            .attr("ID", &response.id)
            .attr("Version", "2.0")
            .attr("IssueInstant", &response.issue_instant.to_rfc3339())
            .attr("Destination", &response.destination)
            .attr("InResponseTo", &response.in_response_to)
        ).map_err(|e| ServiceError::SamlError(format!("Failed to write Response: {}", e)))?;
        
        // Issuer
        writer.write(XmlEvent::start_element("saml:Issuer"))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write Issuer: {}", e)))?;
        
        writer.write(XmlEvent::Characters(&response.issuer))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write Issuer value: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // saml:Issuer
            .map_err(|e| ServiceError::SamlError(format!("Failed to end Issuer: {}", e)))?;
        
        // Status
        writer.write(XmlEvent::start_element("samlp:Status"))
            .map_err(|e| ServiceError::SamlError(format!("Failed to write Status: {}", e)))?;
        
        writer.write(XmlEvent::start_element("samlp:StatusCode")
            .attr("Value", &response.status_code)
        ).map_err(|e| ServiceError::SamlError(format!("Failed to write StatusCode: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // samlp:StatusCode
            .map_err(|e| ServiceError::SamlError(format!("Failed to end StatusCode: {}", e)))?;
        
        writer.write(XmlEvent::end_element()) // samlp:Status
            .map_err(|e| ServiceError::SamlError(format!("Failed to end Status: {}", e)))?;
        
        // Assertion
        if let Some(assertion) = &response.assertion {
            writer.write(XmlEvent::start_element("saml:Assertion")
                .attr("ID", &assertion.id)
                .attr("Version", "2.0")
                .attr("IssueInstant", &assertion.issue_instant.to_rfc3339())
            ).map_err(|e| ServiceError::SamlError(format!("Failed to write Assertion: {}", e)))?;
            
            // Assertion Issuer
            writer.write(XmlEvent::start_element("saml:Issuer"))
                .map_err(|e| ServiceError::SamlError(format!("Failed to write Assertion Issuer: {}", e)))?;
            
            writer.write(XmlEvent::Characters(&assertion.issuer))
                .map_err(|e| ServiceError::SamlError(format!("Failed to write Assertion Issuer value: {}", e)))?;
            
            writer.write(XmlEvent::end_element()) // saml:Issuer
                .map_err(|e| ServiceError::SamlError(format!("Failed to end Assertion Issuer: {}", e)))?;
            
            // Subject
            writer.write(XmlEvent::start_element("saml:Subject"))
                .map_err(|e| ServiceError::SamlError(format!("Failed to write Subject: {}", e)))?;
            
            writer.write(XmlEvent::start_element("saml:NameID")
                .attr("Format", &assertion.subject.name_id_format)
            ).map_err(|e| ServiceError::SamlError(format!("Failed to write NameID: {}", e)))?;
            
            writer.write(XmlEvent::Characters(&assertion.subject.name_id))
                .map_err(|e| ServiceError::SamlError(format!("Failed to write NameID value: {}", e)))?;
            
            writer.write(XmlEvent::end_element()) // saml:NameID
                .map_err(|e| ServiceError::SamlError(format!("Failed to end NameID: {}", e)))?;
            
            writer.write(XmlEvent::start_element("saml:SubjectConfirmation")
                .attr("Method", &assertion.subject.subject_confirmation_method)
            ).map_err(|e| ServiceError::SamlError(format!("Failed to write SubjectConfirmation: {}", e)))?;
            
            writer.write(XmlEvent::start_element("saml:SubjectConfirmationData")
                .attr("NotOnOrAfter", &assertion.subject.subject_confirmation_data.not_on_or_after.to_rfc3339())
                .attr("Recipient", &assertion.subject.subject_confirmation_data.recipient)
                .attr("InResponseTo", &assertion.subject.subject_confirmation_data.in_response_to)
            ).map_err(|e| ServiceError::SamlError(format!("Failed to write SubjectConfirmationData: {}", e)))?;
            
            writer.write(XmlEvent::end_element()) // saml:SubjectConfirmationData
                .map_err(|e| ServiceError::SamlError(format!("Failed to end SubjectConfirmationData: {}", e)))?;
            
            writer.write(XmlEvent::end_element()) // saml:SubjectConfirmation
                .map_err(|e| ServiceError::SamlError(format!("Failed to end SubjectConfirmation: {}", e)))?;
            
            writer.write(XmlEvent::end_element()) // saml:Subject
                .map_err(|e| ServiceError::SamlError(format!("Failed to end Subject: {}", e)))?;
            
            // Conditions
            writer.write(XmlEvent::start_element("saml:Conditions")
                .attr("NotBefore", &assertion.conditions.not_before.to_rfc3339())
                .attr("NotOnOrAfter", &assertion.conditions.not_on_or_after.to_rfc3339())
            ).map_err(|e| ServiceError::SamlError(format!("Failed to write Conditions: {}", e)))?;
            
            writer.write(XmlEvent::start_element("saml:AudienceRestriction"))
                .map_err(|e| ServiceError::SamlError(format!("Failed to write AudienceRestriction: {}", e)))?;
            
            for audience in &assertion.conditions.audience_restriction {
                writer.write(XmlEvent::start_element("saml:Audience"))
                    .map_err(|e| ServiceError::SamlError(format!("Failed to write Audience: {}", e)))?;
                
                writer.write(XmlEvent::Characters(audience))
                    .map_err(|e| ServiceError::SamlError(format!("Failed to write Audience value: {}", e)))?;
                
                writer.write(XmlEvent::end_element()) // saml:Audience
                    .map_err(|e| ServiceError::SamlError(format!("Failed to end Audience: {}", e)))?;
            }
            
            writer.write(XmlEvent::end_element()) // saml:AudienceRestriction
                .map_err(|e| ServiceError::SamlError(format!("Failed to end AudienceRestriction: {}", e)))?;
            
            writer.write(XmlEvent::end_element()) // saml:Conditions
                .map_err(|e| ServiceError::SamlError(format!("Failed to end Conditions: {}", e)))?;
            
            // AuthnStatement
            writer.write(XmlEvent::start_element("saml:AuthnStatement")
                .attr("AuthnInstant", &assertion.authentication_statement.authn_instant.to_rfc3339())
                .attr("SessionIndex", &assertion.authentication_statement.session_index)
            ).map_err(|e| ServiceError::SamlError(format!("Failed to write AuthnStatement: {}", e)))?;
            
            writer.write(XmlEvent::start_element("saml:AuthnContext"))
                .map_err(|e| ServiceError::SamlError(format!("Failed to write AuthnContext: {}", e)))?;
            
            writer.write(XmlEvent::start_element("saml:AuthnContextClassRef"))
                .map_err(|e| ServiceError::SamlError(format!("Failed to write AuthnContextClassRef: {}", e)))?;
            
            writer.write(XmlEvent::Characters(&assertion.authentication_statement.authn_context_class_ref))
                .map_err(|e| ServiceError::SamlError(format!("Failed to write AuthnContextClassRef value: {}", e)))?;
            
            writer.write(XmlEvent::end_element()) // saml:AuthnContextClassRef
                .map_err(|e| ServiceError::SamlError(format!("Failed to end AuthnContextClassRef: {}", e)))?;
            
            writer.write(XmlEvent::end_element()) // saml:AuthnContext
                .map_err(|e| ServiceError::SamlError(format!("Failed to end AuthnContext: {}", e)))?;
            
            writer.write(XmlEvent::end_element()) // saml:AuthnStatement
                .map_err(|e| ServiceError::SamlError(format!("Failed to end AuthnStatement: {}", e)))?;
            
            // AttributeStatement
            if let Some(attr_statement) = &assertion.attribute_statement {
                writer.write(XmlEvent::start_element("saml:AttributeStatement"))
                    .map_err(|e| ServiceError::SamlError(format!("Failed to write AttributeStatement: {}", e)))?;
                
                for (name, values) in &attr_statement.attributes {
                    writer.write(XmlEvent::start_element("saml:Attribute")
                        .attr("Name", name)
                        .attr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
                    ).map_err(|e| ServiceError::SamlError(format!("Failed to write Attribute: {}", e)))?;
                    
                    for value in values {
                        writer.write(XmlEvent::start_element("saml:AttributeValue"))
                            .map_err(|e| ServiceError::SamlError(format!("Failed to write AttributeValue: {}", e)))?;
                        
                        writer.write(XmlEvent::Characters(value))
                            .map_err(|e| ServiceError::SamlError(format!("Failed to write AttributeValue value: {}", e)))?;
                        
                        writer.write(XmlEvent::end_element()) // saml:AttributeValue
                            .map_err(|e| ServiceError::SamlError(format!("Failed to end AttributeValue: {}", e)))?;
                    }
                    
                    writer.write(XmlEvent::end_element()) // saml:Attribute
                        .map_err(|e| ServiceError::SamlError(format!("Failed to end Attribute: {}", e)))?;
                }
                
                writer.write(XmlEvent::end_element()) // saml:AttributeStatement
                    .map_err(|e| ServiceError::SamlError(format!("Failed to end AttributeStatement: {}", e)))?;
            }
            
            writer.write(XmlEvent::end_element()) // saml:Assertion
                .map_err(|e| ServiceError::SamlError(format!("Failed to end Assertion: {}", e)))?;
        }
        
        writer.write(XmlEvent::end_element()) // samlp:Response
            .map_err(|e| ServiceError::SamlError(format!("Failed to end Response: {}", e)))?;
        
        let result = writer.into_inner();
        let xml_string = String::from_utf8(result)
            .map_err(|e| ServiceError::SamlError(format!("Failed to convert XML to string: {}", e)))?;
        
        // In a real implementation, you would sign the XML here
        // For simplicity, we'll skip that step in this example
        
        Ok(xml_string)
    }
}