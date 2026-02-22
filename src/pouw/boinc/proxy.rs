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
//!   - Task ID obfuscation (anti-gaming)
//!   - Result submission validation (anti-gaming)
//!   - Reputation tracking and slashing for malicious actions
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
use tracing::{debug, error, info, warn};

use crate::api::SecureHttpClient;
use crate::config::{PoiConfig, sanitize_for_logging};
use crate::pouw::aggregator::PoUWAggregator;
use crate::pouw::boinc::client::BoincClient;
use crate::pouw::boinc::xml::{BoincXmlProcessor, SecureXmlValidator, validate_xml_wellformed};
use crate::pouw::boinc::xml::obfuscation::{TaskObfuscator, ValidationError};
use crate::pouw::boinc::result_tracker::{ResultTracker, SubmissionResult, ResultStatus};
use crate::reputation::{MetricEvent, ReputationManager, SlashReason, SlashEvidence};

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
    
    // Anti-gaming components
    pub task_obfuscator: Arc<RwLock<TaskObfuscator>>, // Task ID obfuscation
    pub reputation_manager: Arc<RwLock<ReputationManager>>, // Reputation tracking
    pub result_tracker: Arc<RwLock<ResultTracker>>, // Result replay detection
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

                    if let Some(ref user_auth) = result.1 {
                        // Check user eligibility first
                        let eligibility = {
                            let rep_manager = state.reputation_manager.read().await;
                            rep_manager.check_eligibility(user_auth).await
                        };
                        
                        if !eligibility.can_participate() {
                            warn!(
                                user_auth = %sanitize_for_logging(user_auth),
                                eligibility = ?eligibility,
                                "User not eligible to submit results"
                            );
                            return (
                                StatusCode::FORBIDDEN,
                                HeaderMap::new(),
                                "Account restricted or banned".to_string(),
                            );
                        }
                        
                        let project_name = state.active_project.name.clone();
                        
                        // Validate each result submission
                        for result_data in extracted_results.values() {
                            // Deobfuscate and validate the task ID
                            let validation_result = {
                                let mut obfuscator = state.task_obfuscator.write().await;
                                obfuscator.validate_submission(&result_data.wu_name, user_auth)
                            };
                            
                            match validation_result {
                                Ok(mapping) => {
                                    // Compute result hash for tracking
                                    let result_hash = ResultTracker::compute_result_hash(
                                        &mapping.real_wu_name,
                                        &result_data.result_name,
                                        result_data.cpu_time,
                                        result_data.exit_status,
                                        result_data.result_data.as_deref(),
                                    );
                                    
                                    // Track this submission for replay detection
                                    let submission_result = {
                                        let mut tracker = state.result_tracker.write().await;
                                        tracker.record_submission(
                                            result_data.wu_name.clone(),
                                            mapping.real_wu_name.clone(),
                                            user_auth.to_string(),
                                            result_hash.clone(),
                                        )
                                    };
                                    
                                    match submission_result {
                                        Ok(SubmissionResult::Accepted) => {
                                            // New submission - proceed
                                            debug!(
                                                task_id = %result_data.wu_name,
                                                real_wu = %mapping.real_wu_name,
                                                user = %sanitize_for_logging(user_auth),
                                                "New result submission - pending BOINC validation"
                                            );
                                        }
                                        Ok(SubmissionResult::DuplicateSend) => {
                                            // Same task/user/result - network retry, allow but don't re-process
                                            debug!(
                                                task_id = %result_data.wu_name,
                                                user = %sanitize_for_logging(user_auth),
                                                "Duplicate submission (network retry) - allowing"
                                            );
                                            // Still forward to BOINC, but don't double-count
                                            continue;
                                        }
                                        Ok(SubmissionResult::FlaggedForReview(flags)) => {
                                            // Suspicious but not definitely malicious - flag for review
                                            warn!(
                                                task_id = %result_data.wu_name,
                                                user = %sanitize_for_logging(user_auth),
                                                flags = ?flags,
                                                "Suspicious activity flagged for review - allowing submission"
                                            );
                                            // Continue processing - will be reviewed later
                                        }
                                        Err(e) => {
                                            error!(
                                                task_id = %result_data.wu_name,
                                                error = ?e,
                                                "Failed to record submission"
                                            );
                                        }
                                    }
                                    
                                    // Mark as submitted in obfuscator
                                    {
                                        let mut obfuscator = state.task_obfuscator.write().await;
                                        obfuscator.mark_submitted(&result_data.wu_name);
                                    }
                                    
                                    // Record metric: task completed (pending validation)
                                    {
                                        let rep_manager = state.reputation_manager.write().await;
                                        if let Err(e) = rep_manager.record_metric_event(
                                            user_auth,
                                            &project_name,
                                            MetricEvent::TaskCompleted { 
                                                credits: 0.0, // Will be updated after validation
                                                compute_time_seconds: result_data.cpu_time,
                                            },
                                        ).await {
                                            error!("Failed to record metric: {}", e);
                                        }
                                    }
                                    
                                    // Convert to BoincWork and update in aggregator
                                    // NOTE: Credits are 0 until BOINC validates
                                    let completed_work = crate::pouw::models::BoincWork {
                                        project_name: project_name.clone(),
                                        user_id: user_auth.clone(),
                                        task_id: mapping.real_wu_name.clone(), // Use real WU name
                                        cpu_time: result_data.cpu_time,
                                        credit_granted: 0.0, // Locked until BOINC validates
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
                                Err(ValidationError::NotAssignedToUser) => {
                                    // MALICIOUS - Slash the user
                                    warn!(
                                        task_id = %result_data.wu_name,
                                        user = %sanitize_for_logging(user_auth),
                                        "User attempted to submit unassigned work - SLASHING"
                                    );
                                    
                                    let evidence = SlashEvidence::unassigned_work(
                                        &result_data.wu_name,
                                        &project_name,
                                        None,
                                    );
                                    
                                    {
                                        let rep_manager = state.reputation_manager.write().await;
                                        if let Err(e) = rep_manager.slash(
                                            user_auth,
                                            SlashReason::UnassignedWork,
                                            evidence,
                                        ).await {
                                            error!("Failed to apply slash: {}", e);
                                        }
                                    }
                                    
                                    return (
                                        StatusCode::FORBIDDEN,
                                        HeaderMap::new(),
                                        "Work not assigned to user".to_string(),
                                    );
                                }
                                Err(ValidationError::AlreadySubmitted) => {
                                    // Already submitted - could be network retry or malicious
                                    // ResultTracker handles nuanced replay detection
                                    debug!(
                                        task_id = %result_data.wu_name,
                                        user = %sanitize_for_logging(user_auth),
                                        "Task already submitted - checking ResultTracker for details"
                                    );
                                    
                                    // Check ResultTracker for the status
                                    let result_status = {
                                        let tracker = state.result_tracker.read().await;
                                        tracker.get_record(&result_data.wu_name)
                                            .map(|r| r.status)
                                    };
                                    
                                    match result_status {
                                        Some(ResultStatus::Validated) => {
                                            // Already validated by BOINC - this is a double-claim attempt
                                            warn!(
                                                task_id = %result_data.wu_name,
                                                user = %sanitize_for_logging(user_auth),
                                                "Attempted to resubmit already-validated result - SLASHING"
                                            );
                                            
                                            let evidence = SlashEvidence::result_replay(
                                                &result_data.wu_name,
                                                &project_name,
                                                user_auth,
                                            );
                                            
                                            {
                                                let rep_manager = state.reputation_manager.write().await;
                                                if let Err(e) = rep_manager.slash(
                                                    user_auth,
                                                    SlashReason::ResultReplay,
                                                    evidence,
                                                ).await {
                                                    error!("Failed to apply slash: {}", e);
                                                }
                                            }
                                            
                                            return (
                                                StatusCode::FORBIDDEN,
                                                HeaderMap::new(),
                                                "Result already validated".to_string(),
                                            );
                                        }
                                        Some(ResultStatus::Pending) => {
                                            // Still pending - network retry, allow
                                            debug!(
                                                task_id = %result_data.wu_name,
                                                "Result pending validation - allowing resubmission"
                                            );
                                            // Continue processing
                                        }
                                        Some(ResultStatus::Rejected) => {
                                            // Already rejected by BOINC - don't reprocess
                                            return (
                                                StatusCode::BAD_REQUEST,
                                                HeaderMap::new(),
                                                "Result was rejected by BOINC".to_string(),
                                            );
                                        }
                                        _ => {
                                            // Unknown status - reject safely
                                            return (
                                                StatusCode::BAD_REQUEST,
                                                HeaderMap::new(),
                                                "Result already submitted".to_string(),
                                            );
                                        }
                                    }
                                }
                                Err(ValidationError::Expired) => {
                                    // Not malicious, just late - track but don't slash
                                    warn!(
                                        task_id = %result_data.wu_name,
                                        user = %sanitize_for_logging(user_auth),
                                        "Task assignment expired"
                                    );
                                    
                                    // Record metric only
                                    {
                                        let rep_manager = state.reputation_manager.write().await;
                                        if let Err(e) = rep_manager.record_metric_event(
                                            user_auth,
                                            &project_name,
                                            MetricEvent::DeadlineMissed,
                                        ).await {
                                            error!("Failed to record metric: {}", e);
                                        }
                                    }
                                    
                                    return (
                                        StatusCode::BAD_REQUEST,
                                        HeaderMap::new(),
                                        "Task assignment expired".to_string(),
                                    );
                                }
                                Err(ValidationError::UnknownTask) => {
                                    // Unknown task ID - could be malicious or client error
                                    warn!(
                                        task_id = %result_data.wu_name,
                                        user = %sanitize_for_logging(user_auth),
                                        "Unknown task ID submitted"
                                    );
                                    
                                    return (
                                        StatusCode::BAD_REQUEST,
                                        HeaderMap::new(),
                                        "Unknown task ID".to_string(),
                                    );
                                }
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

                            // Obfuscate work unit names and record assignments
                            if let Some(ref user_auth) = original_user_auth {
                                let project_name = state.active_project.name.clone();
                                
                                // Record task assignments in obfuscator
                                let obfuscated_wus: Vec<(String, String)> = {
                                    let mut obfuscator = state.task_obfuscator.write().await;
                                    extracted_wus
                                        .values()
                                        .map(|wu| {
                                            let obfuscated_id = obfuscator.obfuscate_wu_name(&wu.name, user_auth);
                                            (wu.name.clone(), obfuscated_id)
                                        })
                                        .collect()
                                };
                                
                                // Record metric: task assigned
                                {
                                    let rep_manager = state.reputation_manager.write().await;
                                    for _ in extracted_wus.values() {
                                        if let Err(e) = rep_manager.record_metric_event(
                                            user_auth,
                                            &project_name,
                                            MetricEvent::TaskAssigned,
                                        ).await {
                                            error!("Failed to record task assigned metric: {}", e);
                                        }
                                    }
                                }
                                
                                // Convert extracted work units to BoincWork for the aggregator
                                // Store with REAL wu names (for internal tracking)
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
                                
                                debug!(
                                    user_auth = %sanitize_for_logging(user_auth),
                                    work_units = obfuscated_wus.len(),
                                    "Obfuscated work unit IDs for user"
                                );
                            }
                        }

                        processed
                    }
                    Err(e) => {
                        error!("Failed to process XML response: {}", e);
                        resp_body.clone() // Fall back to original response
                    }
                }
            };
            
            // Extract and handle validation results from BOINC
            {
                let xml_processor = state.xml_processor.read().await;
                if let Ok(validation_results) = xml_processor.extract_validation_results(&resp_body) {
                    if !validation_results.is_empty() {
                        info!(
                            "Extracted {} validation results from BOINC response",
                            validation_results.len()
                        );
                        
                        for vr in &validation_results {
                            // Find the obfuscated ID for this result
                            // TODO: Add reverse lookup from wu_name/result_name to obfuscated_id
                            let _obfuscated_id_opt: Option<String> = {
                                let _obfuscator = state.task_obfuscator.read().await;
                                // Look up by result name (we'd need a reverse index)
                                // For now, use the wu_name
                                None
                            };
                            
                            // Update result tracker with validation status
                            // For now, log the validation
                            debug!(
                                result_name = %vr.result_name,
                                wu_name = %vr.wu_name,
                                validated = vr.validated,
                                credits = vr.credits_granted,
                                "BOINC validation result received"
                            );
                            
                            // When we have the obfuscated_id, update tracker:
                            // let mut tracker = state.result_tracker.write().await;
                            // tracker.update_validation(&obfuscated_id, vr.validated, Some(vr.credits_granted), None);
                            
                            // Award reputation if validated
                            if vr.validated && vr.credits_granted > 0.0 {
                                if let Some(ref user_auth) = original_user_auth {
                                    let rep_manager = state.reputation_manager.write().await;
                                    if let Err(e) = rep_manager.record_success(
                                        user_auth,
                                        &state.active_project.name,
                                        vr.credits_granted,
                                    ).await {
                                        error!("Failed to record validated success: {}", e);
                                    }
                                    debug!(
                                        user_auth = %sanitize_for_logging(user_auth),
                                        credits = vr.credits_granted,
                                        "Awarded reputation for validated result"
                                    );
                                }
                            }
                        }
                    }
                }
            }

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
