use anyhow::{Context, Result};
use axum::{Router, middleware, routing::get};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{Level, error, info, warn};
use tracing_subscriber::fmt::format::FmtSpan;

use silica_oracle::{
    BoincClient, PoUWAggregator, PoUWOracle, ProjectConfig, ProjectManager,
    ReputationManager, ReputationThresholds,
    ObfuscationConfig, TaskObfuscator, ResultTracker,
    api::http::HttpSecurityConfig,
    api::{
        MinerApiState, OracleApiState, SecureHttpClient, SecurityMiddlewareConfig, SecurityState,
        WebApiState, NuwApiState, ReputationApiState, create_nuw_router, create_reputation_router,
        auth_middleware, body_size_middleware, create_miner_router,
        create_oracle_router, create_web_router, security_headers_middleware,
    },
    config::{CredentialManager, PoiConfig, sanitize_for_logging},
    pouw::boinc::{
        BoincProxyState, BoincXmlProcessor, ProxiedProject, SecureXmlValidator,
        create_boinc_proxy_router,
    },
    pouw::oracle::ProviderProjectConfig,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration first - this validates all security requirements
    let config = Arc::new(PoiConfig::from_env().map_err(|e| {
        eprintln!("Configuration error: {}", e);
        eprintln!("Please check environment variables and security settings.");
        e
    })?);

    // Initialize secure logging based on configuration
    init_secure_logging(&config)?;

    info!("Starting Chert PoUW (Proof of Useful Work) Oracle Server");
    info!(
        "Security settings: HTTPS required: {}, Auth enabled: {}",
        config.security.require_https, config.security.enable_auth
    );

    // Initialize components
    let project_manager = Arc::new(RwLock::new(ProjectManager::new()));
    let aggregator = Arc::new(RwLock::new(PoUWAggregator::new()));
    let boinc_client = Arc::new(RwLock::new(BoincClient::new()));
    let oracle = Arc::new(RwLock::new(PoUWOracle::new()));
    
    // Initialize reputation system (anti-gaming)
    let reputation_thresholds = config.reputation.to_thresholds();
    let reputation_manager = Arc::new(RwLock::new(ReputationManager::new(reputation_thresholds)));
    info!(
        "Reputation system initialized: temp_ban_threshold={}, perm_ban_threshold={}, slash_decay_days={}",
        config.reputation.temp_ban_threshold,
        config.reputation.perm_ban_threshold,
        config.reputation.slash_decay_days
    );
    
    // Initialize task obfuscator (anti-gaming)
    let obfuscation_config = ObfuscationConfig::from_secret(
        config.reputation.obfuscation_secret.as_bytes()
    );
    let task_obfuscator = Arc::new(RwLock::new(TaskObfuscator::new(obfuscation_config)));
    info!("Task obfuscation initialized for anti-gaming");
    
    // Initialize result tracker (anti-gaming)
    let result_tracker = Arc::new(RwLock::new(ResultTracker::new()));
    info!("Result tracker initialized for replay detection");

    // Initialize credential manager and validate credentials
    let mut credential_manager = CredentialManager::new();
    credential_manager.load_from_env()?;

    // Validate all loaded credentials
    for project_name in config.get_project_names() {
        credential_manager.validate_credential(&project_name)?;
    }

    // Check if credentials need rotation
    if credential_manager.needs_rotation() {
        warn!("Credentials are due for rotation - consider updating environment variables");
    }

    // Load projects from secure configuration (no hardcoded credentials)
    load_projects_from_secure_config(
        project_manager.clone(),
        oracle.clone(),
        &config,
        &credential_manager,
    )
    .await?;

    // Initialize XML processor with secure configuration
    let xml_processor = create_secure_xml_processor(&config, project_manager.clone()).await?;

    // Get the first configured project for the BOINC proxy
    let active_project = get_active_project(&config)?;
    info!(
        "Active BOINC project: {} ({})",
        active_project.name, active_project.scheduler_url
    );

    // Initialize security middleware
    let security_config = SecurityMiddlewareConfig {
        enable_auth: config.security.enable_auth,
        api_keys: get_api_keys_from_env(),
        rate_limit_per_minute: config.security.rate_limit_per_minute,
        max_request_size: config.security.max_request_size,
        log_requests: config.logging.log_requests,
        sanitize_logs: config.logging.sanitize_logs,
        public_paths: vec![
            "/health".to_string(),
            "/boinc/".to_string(), // BOINC proxy must be accessible
        ],
    };
    let security_state = SecurityState::new(security_config);

    // Build the application with routes and security middleware
    let app = Router::new()
        // BOINC proxy routes (handles / and /cgi)
        .nest(
            "/boinc",
            create_boinc_proxy_router(BoincProxyState {
                aggregator: aggregator.clone(),
                boinc_client: boinc_client.clone(),
                accounts: Arc::new(RwLock::new(HashMap::new())),
                http_client: create_secure_http_client(&config)?,
                server_url: config.server.base_url.clone(),
                xml_processor: xml_processor.clone(),
                xml_validator: SecureXmlValidator::new_boinc_safe(),
                config: config.clone(),
                active_project,
                task_obfuscator: task_obfuscator.clone(),
                reputation_manager: reputation_manager.clone(),
                result_tracker: result_tracker.clone(),
            }),
        )
        // Oracle API routes (work verification, proof generation, challenges)
        .nest(
            "/oracle",
            create_oracle_router(OracleApiState::new(
                oracle.clone(),
                aggregator.clone(),
                project_manager.clone(),
            )),
        )
        // Web API routes (human-readable)
        .nest(
            "/api",
            create_web_router(WebApiState {
                aggregator: aggregator.clone(),
                boinc_client: boinc_client.clone(),
                accounts: Arc::new(RwLock::new(HashMap::new())),
                project_manager: project_manager.clone(),
            }),
        )
        // Miner API routes
        .nest(
            "/miner",
            create_miner_router(MinerApiState::new(
                aggregator.clone(),
                project_manager.clone(),
            )),
        )
        // Reputation API routes (monitoring & governance)
        .nest(
            "/reputation",
            create_reputation_router(ReputationApiState {
                reputation_manager: reputation_manager.clone(),
                result_tracker: result_tracker.clone(),
                admin_api_key: std::env::var("CHERT_ADMIN_API_KEY").ok(),
            }),
        )
        // Health check
        .route("/health", get(|| async { "OK" }))
        // Apply security middleware layers (order matters!)
        .layer(middleware::from_fn_with_state(
            security_state.clone(),
            body_size_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            security_state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(TraceLayer::new_for_http());

    // Start the server on configured host/port
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {}: {}", bind_addr, e))?;

    info!("PoUW Oracle server listening on {}", bind_addr);
    info!(
        "Security middleware: Auth={}, Rate limit={}/min, Max body={}KB",
        config.security.enable_auth,
        config.security.rate_limit_per_minute,
        config.security.max_request_size / 1024
    );
    if config.security.require_https {
        info!("HTTPS enforcement enabled - all external communications require TLS");
    }

    // Serve with connect info for client IP extraction
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Initialize secure logging with sanitization
fn init_secure_logging(config: &PoiConfig) -> Result<()> {
    let log_level = match config.logging.level.to_lowercase().as_str() {
        "error" => Level::ERROR,
        "warn" => Level::WARN,
        "info" => Level::INFO,
        "debug" => Level::DEBUG,
        "trace" => Level::TRACE,
        _ => Level::INFO,
    };

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_span_events(if config.logging.log_requests {
            FmtSpan::NEW | FmtSpan::CLOSE
        } else {
            FmtSpan::NONE
        })
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| anyhow::anyhow!("Failed to set logging subscriber: {}", e))?;

    if config.logging.sanitize_logs {
        info!("Secure logging initialized with data sanitization enabled");
    }

    Ok(())
}

/// Create XML processor with secure configuration
async fn create_secure_xml_processor(
    config: &PoiConfig,
    _project_manager: Arc<RwLock<ProjectManager>>,
) -> Result<Arc<RwLock<BoincXmlProcessor>>> {
    // Try to get MilkyWay@Home authenticator from secure config
    let milkyway_auth = if let Some(project_config) = config.get_project("MilkyWay@Home") {
        project_config.authenticator.clone()
    } else {
        error!("MilkyWay@Home project not found in configuration");
        return Err(anyhow::anyhow!(
            "MilkyWay@Home project configuration is required but not found. \
             Please set CHERT_BOINC_MILKYWAY_AUTHENTICATOR environment variable."
        ));
    };

    info!("Initializing XML processor with secure MilkyWay@Home configuration");

    // Create XML processor with sanitized logging
    let xml_processor = if config.logging.sanitize_logs {
        let sanitized_auth = sanitize_for_logging(&milkyway_auth);
        info!("XML processor auth: {}", sanitized_auth);
        BoincXmlProcessor::new(milkyway_auth)
    } else {
        warn!("Log sanitization disabled - sensitive data may be logged");
        BoincXmlProcessor::new(milkyway_auth)
    };

    Ok(Arc::new(RwLock::new(xml_processor)))
}

/// Create HTTP client with security configuration
fn create_secure_http_client(config: &PoiConfig) -> Result<SecureHttpClient> {
    let http_config = HttpSecurityConfig {
        require_https: config.security.require_https,
        verify_certificates: config.security.verify_certificates,
        timeout_secs: config.boinc.timeout_secs,
        max_response_size: config.security.max_request_size,
        allowed_domains: vec![
            "milkyway.cs.rpi.edu".to_string(),
            "boinc.bakerlab.org".to_string(),
            "setiathome.berkeley.edu".to_string(),
            "einstein.phys.uwm.edu".to_string(),
        ],
    };

    SecureHttpClient::new(http_config).context("Failed to create secure HTTP client")
}

/// Load projects from secure configuration (no hardcoded credentials)
async fn load_projects_from_secure_config(
    project_manager: Arc<RwLock<ProjectManager>>,
    oracle: Arc<RwLock<PoUWOracle>>,
    config: &PoiConfig,
    credential_manager: &CredentialManager,
) -> Result<()> {
    let project_names = config.get_project_names();
    if project_names.is_empty() {
        return Err(anyhow::anyhow!(
            "No BOINC projects configured. Please set project authenticators in environment variables."
        ));
    }

    info!(
        "Loading {} projects from secure configuration...",
        project_names.len()
    );

    for project_name in &project_names {
        if let Some(project_config) = config.get_project(project_name) {
            // Get authenticator from credential manager (more secure)
            let authenticator = credential_manager
                .get_authenticator(project_name)
                .ok_or_else(|| {
                    anyhow::anyhow!("No authenticator found for project: {}", project_name)
                })?
                .clone();

            let pouw_project_config = ProjectConfig {
                name: project_config.name.clone(),
                project_url: project_config.master_url.clone(),
                api_endpoint: project_config.scheduler_url.clone(),
                user_id: "chert_miner".to_string(), // Standard user ID
                authenticator,
                credit_multiplier: 1.0,    // Default
                min_cpu_time: 1800.0,      // Default
                max_daily_credits: 1000.0, // Default
                priority: 1,               // Default
                enabled: true,
            };

            // Register with project manager
            {
                let pm = project_manager.write().await;
                pm.register_project(pouw_project_config.clone()).await?;
            }

            // Also register with the Oracle for verification
            {
                let mut oracle_guard = oracle.write().await;
                oracle_guard.register_project(ProviderProjectConfig {
                    name: project_config.name.clone(),
                    api_endpoint: project_config.scheduler_url.clone(),
                    scheduler_url: project_config.scheduler_url.clone(),
                    credit_multiplier: 1.0,
                    verification_required: true,
                    min_cpu_time: 1800.0,
                    max_daily_credits: 10000.0,
                    enabled: true,
                });
            }

            // Log with sanitization
            if config.logging.sanitize_logs {
                let sanitized_auth = sanitize_for_logging(&project_config.authenticator);
                info!(
                    "Registered project {} with sanitized auth: {}",
                    project_name, sanitized_auth
                );
            } else {
                warn!(
                    "Log sanitization disabled - authenticator for {} may be logged",
                    project_name
                );
                info!("Registered project {}", project_name);
            }
        }
    }

    info!(
        "Successfully loaded {} projects from secure configuration",
        project_names.len()
    );
    Ok(())
}

/// Get the active project configuration for the BOINC proxy
fn get_active_project(config: &PoiConfig) -> Result<ProxiedProject> {
    // Get the first configured project
    let project_names = config.get_project_names();
    let project_name = project_names
        .first()
        .ok_or_else(|| anyhow::anyhow!("No BOINC projects configured"))?;

    let project_config = config
        .get_project(project_name)
        .ok_or_else(|| anyhow::anyhow!("Project configuration not found: {}", project_name))?;

    Ok(ProxiedProject {
        name: project_config.name.clone(),
        scheduler_url: project_config.scheduler_url.clone(),
        master_url: project_config.master_url.clone(),
    })
}

/// Load API keys from environment variables
fn get_api_keys_from_env() -> Vec<String> {
    let mut keys = Vec::new();

    // Primary API key
    if let Ok(key) = std::env::var("CHERT_API_KEY") {
        if !key.is_empty() {
            keys.push(key);
        }
    }

    // Additional API keys (comma-separated)
    if let Ok(extra_keys) = std::env::var("CHERT_API_KEYS") {
        for key in extra_keys.split(',') {
            let key = key.trim();
            if !key.is_empty() {
                keys.push(key.to_string());
            }
        }
    }

    if keys.is_empty() {
        warn!("No API keys configured - authentication will fail if enabled");
    } else {
        info!("Loaded {} API key(s) for authentication", keys.len());
    }

    keys
}
