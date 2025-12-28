//! BOINC Proxy for handling BOINC client requests
//!
//! Endpoints:
//!   GET / -> BOINC master file (HTML with scheduler link)
//!   POST /cgi -> Proxy scheduler requests to real BOINC projects
//!
//! Security features:
//!   - HTTPS enforcement for all external communications
//!   - URL validation and domain whitelisting  
//!   - XML input validation and sanitization
//!   - Secure error handling without information disclosure

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::get,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::api::SecureHttpClient;
use crate::config::{PoiConfig, sanitize_for_logging};
use crate::pouw::aggregator::PoUWAggregator;
use crate::pouw::boinc::client::BoincClient;
use crate::pouw::boinc::xml::{BoincXmlProcessor, SecureXmlValidator, validate_xml_wellformed};

/// Configuration for a proxied BOINC project
#[derive(Clone, Debug)]
pub struct ProxiedProject {
    pub name: String,
    pub scheduler_url: String,
    pub master_url: String,
}

#[derive(Clone)]
pub struct BoincProxyState {
    pub aggregator: Arc<RwLock<PoUWAggregator>>,
    pub boinc_client: Arc<RwLock<BoincClient>>,
    pub accounts: Arc<RwLock<HashMap<String, String>>>, // auth -> user_id mapping
    pub http_client: SecureHttpClient,
    pub server_url: String, // Base server URL for building scheduler links
    pub xml_processor: Arc<RwLock<BoincXmlProcessor>>, // XML processing for auth replacement
    pub xml_validator: SecureXmlValidator, // Secure XML validation
    pub config: Arc<PoiConfig>, // Security configuration
    pub active_project: ProxiedProject, // Currently active project (configurable)
}

// BOINC master file handler
pub async fn get_master_file_handler(
    State(state): State<BoincProxyState>,
) -> (StatusCode, HeaderMap, String) {
    info!("Serving BOINC master file");
    let scheduler_url = format!("{}/boinc/cgi", state.server_url);
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
<!-- <scheduler>{0}</scheduler> -->
<link rel="boinc_scheduler" href="{0}">
</head>
<body>
<h1>Chert BOINC Proxy</h1>
<p>Scheduler: {0}</p>
</body>
</html>"#,
        scheduler_url
    );

    let mut headers = HeaderMap::new();
    headers.insert("content-type", "text/html".parse().unwrap());
    (StatusCode::OK, headers, html)
}

// BOINC scheduler proxy handler with security validation
pub async fn proxy_cgi(
    State(state): State<BoincProxyState>,
    _headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, HeaderMap, String) {
    // Input validation - check body size
    if body.len() > 1024 * 1024 {
        error!("Request body too large: {} bytes", body.len());
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            HeaderMap::new(),
            "Request too large".to_string(),
        );
    }

    let body_str = String::from_utf8_lossy(&body);

    // XML security validation BEFORE processing
    match validate_xml_wellformed(&body_str) {
        Ok(_) => {
            info!("XML well-formedness validation passed");
        }
        Err(e) => {
            error!("XML validation failed: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                "Malformed XML request".to_string(),
            );
        }
    }

    // Secure XML validation and sanitization
    let sanitized_xml: String = match state.xml_validator.validate_and_sanitize(&body_str) {
        Ok(sanitized_string) => {
            info!("XML security validation passed");
            sanitized_string
        }
        Err(e) => {
            error!("XML security validation failed: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                "Invalid or unsafe XML request".to_string(),
            );
        }
    };

    // Sanitize logging to prevent credential exposure
    if state.config.logging.sanitize_logs {
        let _sanitized_body = sanitize_for_logging(&body_str);
        info!("Received scheduler request: {} bytes", body.len());
    } else {
        info!("Received scheduler request: {} bytes", body.len());
    }

    // XML validation and processing using sanitized XML
    let (modified_xml, original_user_auth) = {
        let mut xml_processor = state.xml_processor.write().await;
        match xml_processor.process_outbound_request(&sanitized_xml) {
            Ok(result) => {
                // Check for extracted results (completed work submissions)
                let extracted_results = xml_processor.get_extracted_results();
                if !extracted_results.is_empty() {
                    info!(
                        "Extracted {} result submissions from request",
                        extracted_results.len()
                    );

                    // Update aggregator with completed work
                    if let Some(ref user_auth) = result.1 {
                        let project_name = state.active_project.name.clone();
                        for result_data in extracted_results.values() {
                            // Convert to BoincWork and update in aggregator
                            let completed_work = crate::pouw::models::BoincWork {
                                project_name: project_name.clone(),
                                user_id: user_auth.clone(),
                                task_id: result_data.wu_name.clone(),
                                cpu_time: result_data.cpu_time,
                                credit_granted: result_data.cpu_time * 10.0, // Simple credit calculation
                                completion_time: result_data.submitted_at,
                                validation_state: Some(
                                    crate::pouw::models::ValidationState::Pending,
                                ),
                            };

                            // Add completed work to cache for PoI calculations
                            if let Err(e) = state
                                .aggregator
                                .read()
                                .await
                                .add_work_to_cache(user_auth, vec![completed_work])
                                .await
                            {
                                error!("Failed to add completed work to aggregator: {}", e);
                            }
                        }
                    }
                }

                result
            }
            Err(e) => {
                error!("XML processing failed: {}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    HeaderMap::new(),
                    "Invalid XML request".to_string(),
                );
            }
        }
    };

    // Track user mapping if we have an original auth
    if let Some(ref user_auth) = original_user_auth {
        let mut accounts = state.accounts.write().await;
        let len = accounts.len();
        let user_id = accounts
            .entry(user_auth.clone())
            .or_insert_with(|| format!("user_{}", len))
            .clone();

        // Secure logging with sanitization
        let sanitized_auth = sanitize_for_logging(user_auth);
        info!("Mapped auth {} to user {}", sanitized_auth, user_id);
    }

    // Secure forwarding to real BOINC project (from config, not hardcoded)
    let real_url = &state.active_project.scheduler_url;

    // Validate URL is HTTPS in production
    if state.config.security.require_https && !real_url.starts_with("https://") {
        error!("Refusing to forward to non-HTTPS URL: {}", real_url);
        return (
            StatusCode::BAD_GATEWAY,
            HeaderMap::new(),
            "Security policy requires HTTPS".to_string(),
        );
    }

    match state
        .http_client
        .post_xml_secure(real_url, &modified_xml)
        .await
    {
        Ok(resp_body) => {
            info!(
                "Securely forwarded to {}: {} bytes response",
                real_url,
                resp_body.len()
            );

            // Process the response through XML processor
            let processed_response = {
                let mut xml_processor = state.xml_processor.write().await;
                match xml_processor
                    .process_inbound_response(&resp_body, original_user_auth.as_deref())
                {
                    Ok(processed) => {
                        // Extract work units and add to aggregator if available
                        let extracted_wus = xml_processor.get_extracted_work_units();
                        if !extracted_wus.is_empty() {
                            info!(
                                "Extracted {} work units from scheduler response",
                                extracted_wus.len()
                            );

                            // Convert extracted work units to BoincWork for the aggregator
                            if let Some(ref user_auth) = original_user_auth {
                                let project_name = state.active_project.name.clone();
                                let boinc_works: Vec<crate::pouw::models::BoincWork> =
                                    extracted_wus
                                        .values()
                                        .map(|wu| crate::pouw::models::BoincWork {
                                            project_name: project_name.clone(),
                                            user_id: user_auth.clone(),
                                            task_id: wu.name.clone(),
                                            cpu_time: wu.rsc_fpops_est / 1e9, // Convert FLOPS to estimated CPU time
                                            credit_granted: 0.0, // Will be set when work is completed
                                            completion_time: wu.extracted_at,
                                            validation_state: None,
                                        })
                                        .collect();

                                // Add to aggregator cache
                                if let Err(e) = state
                                    .aggregator
                                    .read()
                                    .await
                                    .add_work_to_cache(user_auth, boinc_works)
                                    .await
                                {
                                    error!("Failed to add work to aggregator cache: {}", e);
                                }
                            }
                        }

                        processed
                    }
                    Err(e) => {
                        error!("Failed to process XML response: {}", e);
                        resp_body // Fall back to original response
                    }
                }
            };

            let mut resp_headers = HeaderMap::new();
            resp_headers.insert("content-type", "text/xml".parse().unwrap());
            (StatusCode::OK, resp_headers, processed_response)
        }
        Err(e) => {
            error!("Secure HTTP request failed: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                HeaderMap::new(),
                "Service temporarily unavailable".to_string(),
            )
        }
    }
}

/// Create the BOINC proxy router with all endpoints
pub fn create_boinc_proxy_router(state: BoincProxyState) -> Router {
    info!(
        "Creating BOINC proxy router with server URL: {}",
        state.server_url
    );
    Router::new()
        .route("/", get(get_master_file_handler))
        .route("/cgi", get(proxy_cgi).post(proxy_cgi))
        .route("/get_project_config.php", get(get_project_config))
        .fallback(get(get_master_file_handler))
        .with_state(state)
}

/// Handle BOINC project configuration requests
/// This is crucial for BOINC client project attachment
pub async fn get_project_config(State(state): State<BoincProxyState>) -> (StatusCode, String) {
    info!("BOINC client requesting project configuration");

    // Return a project config that points to our proxy
    let config_xml = format!(
        r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<project_config>
    <name>Chert BOINC Proxy (MilkyWay@Home)</name>
    <master_url>{}/boinc/</master_url>
    <web_rpc_url_base>{}/boinc/</web_rpc_url_base>
    <server_version>1.4.2</server_version>
    <web_stopped>0</web_stopped>
    <min_passwd_length>6</min_passwd_length>
    <sched_stopped>0</sched_stopped>
    <platforms>
        <platform>
            <platform_name>x86_64-pc-linux-gnu</platform_name>
            <user_friendly_name>Linux running on an AMD x86_64 or Intel EM64T CPU</user_friendly_name>
        </platform>
        <platform>
            <platform_name>x86_64-pc-linux-gnu</platform_name>
            <user_friendly_name>Linux running on an AMD x86_64 or Intel EM64T CPU</user_friendly_name>
            <plan_class>mt</plan_class>
        </platform>
    </platforms>
</project_config>"#,
        state.server_url, state.server_url
    );

    info!("Returning project config XML to BOINC client");
    (StatusCode::OK, config_xml)
}
