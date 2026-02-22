use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use tracing::{info, warn};

/// Configuration for the PoI (Proof of Intelligence) module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoiConfig {
    /// Server configuration
    pub server: ServerConfig,
    /// Security configuration  
    pub security: SecurityConfig,
    /// BOINC project configurations
    pub boinc: BoincConfig,
    /// Oracle configuration
    pub oracle: OracleConfig,
    /// Database configuration
    pub database: DatabaseConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Reputation system configuration
    pub reputation: ReputationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server host to bind to
    pub host: String,
    /// Server port to bind to
    pub port: u16,
    /// Base server URL for building links
    pub base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Require HTTPS for all external communications
    pub require_https: bool,
    /// Verify TLS certificates
    pub verify_certificates: bool,
    /// Enable API authentication
    pub enable_auth: bool,
    /// Rate limit per minute per IP
    pub rate_limit_per_minute: u32,
    /// Maximum request body size in bytes
    pub max_request_size: usize,
    /// Enable CORS
    pub enable_cors: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoincConfig {
    /// Project configurations - NO DEFAULT AUTHENTICATORS
    pub projects: HashMap<String, ProjectConfig>,
    /// Default timeout for BOINC requests
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    /// Project name
    pub name: String,
    /// Project scheduler URL
    pub scheduler_url: String,
    /// Project authenticator - MUST be from environment
    pub authenticator: String,
    /// Project master URL
    pub master_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleConfig {
    /// Oracle service URL
    pub service_url: String,
    /// Oracle API key
    pub api_key: String,
    /// Oracle timeout in seconds
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (error, warn, info, debug)
    pub level: String,
    /// Enable log sanitization to prevent sensitive data exposure
    pub sanitize_logs: bool,
    /// Enable request/response logging
    pub log_requests: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// TigerBeetle cluster addresses (comma-separated)
    pub tigerbeetle_addresses: String,
    /// TigerBeetle cluster ID
    pub tigerbeetle_cluster_id: u32,
    /// PostgreSQL connection string
    pub postgres_url: String,
    /// Enable PostgreSQL (if false, uses in-memory fallback)
    pub postgres_enabled: bool,
}

/// Configuration for the reputation/anti-gaming system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationConfig {
    /// Points awarded per successful submission
    pub good_behavior_reward: u32,
    /// Score below which user is restricted (lower priority tasks)
    pub restricted_threshold: i32,
    /// Score below which user is temporarily banned
    pub temp_ban_threshold: i32,
    /// Days for temp ban duration
    pub temp_ban_days: u32,
    /// Score below which user is permanently banned
    pub perm_ban_threshold: i32,
    /// Days before a slash decays (forgiveness period)
    pub slash_decay_days: u32,
    /// Secret key for task ID obfuscation (loaded from env)
    pub obfuscation_secret: String,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            good_behavior_reward: 1,
            restricted_threshold: -50,
            temp_ban_threshold: -100,
            temp_ban_days: 30,
            perm_ban_threshold: -200,
            slash_decay_days: 90,
            obfuscation_secret: String::new(), // Must be set via environment
        }
    }
}

impl ReputationConfig {
    /// Convert to ReputationThresholds for use by ReputationManager
    pub fn to_thresholds(&self) -> crate::reputation::ReputationThresholds {
        crate::reputation::ReputationThresholds {
            good_behavior_reward: self.good_behavior_reward,
            restricted_threshold: self.restricted_threshold,
            temp_ban_threshold: self.temp_ban_threshold,
            temp_ban_days: self.temp_ban_days,
            perm_ban_threshold: self.perm_ban_threshold,
            slash_decay_days: self.slash_decay_days,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            tigerbeetle_addresses: "127.0.0.1:3001".to_string(),
            tigerbeetle_cluster_id: 0,
            postgres_url: "postgresql://localhost:5432/nuw_oracle".to_string(),
            postgres_enabled: false,
        }
    }
}

impl Default for PoiConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8765,
                base_url: "https://oracle.chert.network".to_string(), // Default to HTTPS
            },
            security: SecurityConfig {
                require_https: true,
                verify_certificates: true,
                enable_auth: true,
                rate_limit_per_minute: 60,
                max_request_size: 1024 * 1024, // 1MB
                enable_cors: false,
            },
            boinc: BoincConfig {
                projects: HashMap::new(), // NO DEFAULT PROJECTS - must be configured
                timeout_secs: 30,
            },
            oracle: OracleConfig {
                service_url: "https://oracle.chert.network".to_string(),
                api_key: "".to_string(), // MUST be configured
                timeout_secs: 30,
            },
            database: DatabaseConfig::default(),
            logging: LoggingConfig {
                level: "info".to_string(),
                sanitize_logs: true,
                log_requests: false, // Disabled by default for security
            },
            reputation: ReputationConfig::default(),
        }
    }
}

impl PoiConfig {
    /// Load configuration from environment variables and validate security requirements
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();

        // Server configuration
        if let Ok(host) = env::var("CHERT_POI_HOST") {
            config.server.host = host;
        }

        if let Ok(port) = env::var("CHERT_POI_PORT") {
            config.server.port = port.parse().context("Invalid CHERT_POI_PORT value")?;
        }

        if let Ok(base_url) = env::var("CHERT_POI_BASE_URL") {
            // Security validation for HTTPS
            if config.security.require_https && !base_url.starts_with("https://") {
                return Err(anyhow::anyhow!(
                    "HTTPS is required but base URL is not HTTPS: {}",
                    base_url
                ));
            }
            config.server.base_url = base_url;
        }

        // Security configuration
        if let Ok(require_https) = env::var("CHERT_POI_REQUIRE_HTTPS") {
            config.security.require_https = require_https
                .parse()
                .context("Invalid CHERT_POI_REQUIRE_HTTPS value")?;
        }

        if let Ok(enable_auth) = env::var("CHERT_POI_ENABLE_AUTH") {
            config.security.enable_auth = enable_auth
                .parse()
                .context("Invalid CHERT_POI_ENABLE_AUTH value")?;
        }

        if let Ok(rate_limit) = env::var("CHERT_POI_RATE_LIMIT_PER_MINUTE") {
            config.security.rate_limit_per_minute = rate_limit
                .parse()
                .context("Invalid CHERT_POI_RATE_LIMIT_PER_MINUTE value")?;
        }

        // BOINC project configuration - SECURITY CRITICAL
        config.boinc.projects = Self::load_boinc_projects()?;

        // Oracle configuration
        if let Ok(oracle_url) = env::var("CHERT_ORACLE_URL") {
            if config.security.require_https && !oracle_url.starts_with("https://") {
                return Err(anyhow::anyhow!(
                    "HTTPS is required but oracle URL is not HTTPS: {}",
                    oracle_url
                ));
            }
            config.oracle.service_url = oracle_url;
        }

        config.oracle.api_key = env::var("CHERT_ORACLE_API_KEY")
            .context("CHERT_ORACLE_API_KEY environment variable is required")?;

        // Database configuration
        if let Ok(addresses) = env::var("CHERT_TIGERBEETLE_ADDRESSES") {
            config.database.tigerbeetle_addresses = addresses;
        }

        if let Ok(cluster_id) = env::var("CHERT_TIGERBEETLE_CLUSTER_ID") {
            config.database.tigerbeetle_cluster_id = cluster_id
                .parse()
                .context("Invalid CHERT_TIGERBEETLE_CLUSTER_ID value")?;
        }

        if let Ok(url) = env::var("CHERT_POSTGRES_URL") {
            config.database.postgres_url = url;
        }

        if let Ok(enabled) = env::var("CHERT_POSTGRES_ENABLED") {
            config.database.postgres_enabled = enabled
                .parse()
                .context("Invalid CHERT_POSTGRES_ENABLED value")?;
        }

        // Logging configuration
        if let Ok(log_level) = env::var("CHERT_LOG_LEVEL") {
            config.logging.level = log_level;
        }

        if let Ok(sanitize_logs) = env::var("CHERT_SANITIZE_LOGS") {
            config.logging.sanitize_logs = sanitize_logs
                .parse()
                .context("Invalid CHERT_SANITIZE_LOGS value")?;
        }

        // Reputation configuration
        if let Ok(reward) = env::var("CHERT_REPUTATION_GOOD_BEHAVIOR_REWARD") {
            config.reputation.good_behavior_reward = reward
                .parse()
                .context("Invalid CHERT_REPUTATION_GOOD_BEHAVIOR_REWARD value")?;
        }

        if let Ok(threshold) = env::var("CHERT_REPUTATION_RESTRICTED_THRESHOLD") {
            config.reputation.restricted_threshold = threshold
                .parse()
                .context("Invalid CHERT_REPUTATION_RESTRICTED_THRESHOLD value")?;
        }

        if let Ok(threshold) = env::var("CHERT_REPUTATION_TEMP_BAN_THRESHOLD") {
            config.reputation.temp_ban_threshold = threshold
                .parse()
                .context("Invalid CHERT_REPUTATION_TEMP_BAN_THRESHOLD value")?;
        }

        if let Ok(days) = env::var("CHERT_REPUTATION_TEMP_BAN_DAYS") {
            config.reputation.temp_ban_days = days
                .parse()
                .context("Invalid CHERT_REPUTATION_TEMP_BAN_DAYS value")?;
        }

        if let Ok(threshold) = env::var("CHERT_REPUTATION_PERM_BAN_THRESHOLD") {
            config.reputation.perm_ban_threshold = threshold
                .parse()
                .context("Invalid CHERT_REPUTATION_PERM_BAN_THRESHOLD value")?;
        }

        if let Ok(days) = env::var("CHERT_REPUTATION_SLASH_DECAY_DAYS") {
            config.reputation.slash_decay_days = days
                .parse()
                .context("Invalid CHERT_REPUTATION_SLASH_DECAY_DAYS value")?;
        }

        // Task obfuscation secret (required for anti-gaming)
        config.reputation.obfuscation_secret = env::var("CHERT_OBFUSCATION_SECRET")
            .unwrap_or_else(|_| {
                warn!("CHERT_OBFUSCATION_SECRET not set, using default (not recommended for production)");
                "default_obfuscation_secret_change_in_production".to_string()
            });

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Load BOINC projects from environment variables
    /// Each project requires: CHERT_BOINC_{PROJECT}_AUTHENTICATOR, CHERT_BOINC_{PROJECT}_URL
    fn load_boinc_projects() -> Result<HashMap<String, ProjectConfig>> {
        let mut projects = HashMap::new();

        // Define all supported BOINC projects with their default configurations
        let supported_projects = vec![
            (
                "MilkyWay@Home",
                "CHERT_BOINC_MILKYWAY_AUTHENTICATOR",
                "https://milkyway.cs.rpi.edu/milkyway_cgi/cgi",
                "https://milkyway.cs.rpi.edu/milkyway/",
            ),
            (
                "Rosetta@Home",
                "CHERT_BOINC_ROSETTA_AUTHENTICATOR",
                "https://boinc.bakerlab.org/rosetta/cgi-bin/cgi",
                "https://boinc.bakerlab.org/rosetta/",
            ),
            (
                "World Community Grid",
                "CHERT_BOINC_WCG_AUTHENTICATOR",
                "https://www.worldcommunitygrid.org/boinc-client/cgi/cgi",
                "https://www.worldcommunitygrid.org/",
            ),
            (
                "GPUGRID",
                "CHERT_BOINC_GPUGRID_AUTHENTICATOR",
                "https://www.gpugrid.net/cgi-bin/cgi",
                "https://www.gpugrid.net/",
            ),
        ];

        // Load each project if authenticator is provided
        for (project_name, auth_env_var, default_scheduler_url, default_master_url) in
            supported_projects
        {
            if let Ok(authenticator) = env::var(auth_env_var) {
                // Allow override of URLs via environment variables
                let scheduler_url_env = format!(
                    "CHERT_BOINC_{}_URL",
                    project_name
                        .replace("@", "")
                        .replace(" ", "")
                        .to_uppercase()
                );
                let master_url_env = format!(
                    "CHERT_BOINC_{}_MASTER_URL",
                    project_name
                        .replace("@", "")
                        .replace(" ", "")
                        .to_uppercase()
                );

                let scheduler_url = env::var(&scheduler_url_env)
                    .unwrap_or_else(|_| default_scheduler_url.to_string());
                let master_url =
                    env::var(&master_url_env).unwrap_or_else(|_| default_master_url.to_string());

                // Validate URLs are HTTPS if required
                if env::var("CHERT_POI_REQUIRE_HTTPS").unwrap_or_else(|_| "true".to_string())
                    == "true"
                {
                    if !scheduler_url.starts_with("https://") {
                        return Err(anyhow::anyhow!(
                            "HTTPS is required but {} scheduler URL is not HTTPS: {}",
                            project_name,
                            scheduler_url
                        ));
                    }
                    if !master_url.starts_with("https://") {
                        return Err(anyhow::anyhow!(
                            "HTTPS is required but {} master URL is not HTTPS: {}",
                            project_name,
                            master_url
                        ));
                    }
                }

                projects.insert(
                    project_name.to_string(),
                    ProjectConfig {
                        name: project_name.to_string(),
                        scheduler_url,
                        authenticator,
                        master_url,
                    },
                );

                info!("Configured BOINC project: {}", project_name);
            }
        }

        // Require at least one project to be configured
        if projects.is_empty() {
            return Err(anyhow::anyhow!(
                "No BOINC projects configured. At least one project authenticator is required.\n\
                 Supported projects and their environment variables:\n\
                 - MilkyWay@Home: CHERT_BOINC_MILKYWAY_AUTHENTICATOR\n\
                 - Rosetta@Home: CHERT_BOINC_ROSETTA_AUTHENTICATOR\n\
                 - World Community Grid: CHERT_BOINC_WCG_AUTHENTICATOR\n\
                 - GPUGRID: CHERT_BOINC_GPUGRID_AUTHENTICATOR"
            ));
        }

        info!(
            "Successfully configured {} BOINC project(s)",
            projects.len()
        );
        for project_name in projects.keys() {
            info!("  - {}", project_name);
        }

        Ok(projects)
    }

    /// Validate configuration for security and consistency
    fn validate(&self) -> Result<()> {
        // Validate server configuration
        if self.server.host.is_empty() {
            return Err(anyhow::anyhow!("Server host cannot be empty"));
        }

        if self.server.port == 0 {
            return Err(anyhow::anyhow!("Server port must be non-zero"));
        }

        // Validate base URL
        if self.server.base_url.is_empty() {
            return Err(anyhow::anyhow!("Base URL cannot be empty"));
        }

        // Security validations
        if self.security.require_https {
            if !self.server.base_url.starts_with("https://") {
                return Err(anyhow::anyhow!(
                    "HTTPS is required but base URL is not HTTPS: {}",
                    self.server.base_url
                ));
            }

            if !self.oracle.service_url.starts_with("https://") {
                return Err(anyhow::anyhow!(
                    "HTTPS is required but oracle URL is not HTTPS: {}",
                    self.oracle.service_url
                ));
            }

            // Validate BOINC project URLs
            for (name, project) in &self.boinc.projects {
                if !project.scheduler_url.starts_with("https://") {
                    return Err(anyhow::anyhow!(
                        "HTTPS is required but {} scheduler URL is not HTTPS: {}",
                        name,
                        project.scheduler_url
                    ));
                }
            }
        }

        // Validate Oracle API key
        if self.oracle.api_key.is_empty() {
            return Err(anyhow::anyhow!("Oracle API key is required"));
        }

        // Validate BOINC projects
        if self.boinc.projects.is_empty() {
            return Err(anyhow::anyhow!(
                "At least one BOINC project must be configured"
            ));
        }

        for (name, project) in &self.boinc.projects {
            if project.authenticator.is_empty() {
                return Err(anyhow::anyhow!(
                    "Authenticator for project {} cannot be empty",
                    name
                ));
            }

            if project.scheduler_url.is_empty() {
                return Err(anyhow::anyhow!(
                    "Scheduler URL for project {} cannot be empty",
                    name
                ));
            }

            // Additional security validation for authenticators
            if project.authenticator.len() < 16 {
                return Err(anyhow::anyhow!(
                    "Authenticator for project {} is too short (minimum 16 characters)",
                    name
                ));
            }

            // Validate authenticator format (should be alphanumeric)
            if !project.authenticator.chars().all(|c| c.is_alphanumeric()) {
                return Err(anyhow::anyhow!(
                    "Authenticator for project {} contains invalid characters (only alphanumeric allowed)",
                    name
                ));
            }
        }

        // Validate Oracle API key security
        if self.oracle.api_key.len() < 32 {
            return Err(anyhow::anyhow!(
                "Oracle API key is too short (minimum 32 characters for security)"
            ));
        }

        Ok(())
    }

    /// Get project configuration by name
    pub fn get_project(&self, name: &str) -> Option<&ProjectConfig> {
        self.boinc.projects.get(name)
    }

    /// Get all configured project names
    pub fn get_project_names(&self) -> Vec<String> {
        self.boinc.projects.keys().cloned().collect()
    }
}

/// Sanitize sensitive data for logging
pub fn sanitize_for_logging(data: &str) -> String {
    // Common patterns for sensitive data
    let sensitive_patterns = [
        "authenticator",
        "auth",
        "key",
        "token",
        "password",
        "secret",
        "credential",
        "api_key",
        "apikey",
    ];

    let data_lower = data.to_lowercase();
    for pattern in &sensitive_patterns {
        if data_lower.contains(pattern) {
            // For very long strings, show more context but mask the middle
            if data.len() > 20 {
                return format!("{}***{}", &data[..6], &data[data.len().saturating_sub(6)..]);
            } else {
                return format!(
                    "{}***{}",
                    &data[..data.len().min(2)],
                    &data[data.len().saturating_sub(2)..]
                );
            }
        }
    }

    data.to_string()
}

/// Secure credential management for BOINC authenticators
pub struct CredentialManager {
    /// In-memory credential cache (never persisted)
    credentials: HashMap<String, String>,
    /// Last rotation timestamp
    last_rotation: std::time::SystemTime,
}

impl CredentialManager {
    /// Create a new credential manager
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
            last_rotation: std::time::SystemTime::now(),
        }
    }

    /// Load credentials from environment variables
    pub fn load_from_env(&mut self) -> Result<()> {
        let project_auth_vars = [
            ("MilkyWay@Home", "CHERT_BOINC_MILKYWAY_AUTHENTICATOR"),
            ("Rosetta@Home", "CHERT_BOINC_ROSETTA_AUTHENTICATOR"),
            ("World Community Grid", "CHERT_BOINC_WCG_AUTHENTICATOR"),
            ("GPUGRID", "CHERT_BOINC_GPUGRID_AUTHENTICATOR"),
        ];

        for (project_name, env_var) in &project_auth_vars {
            if let Ok(auth) = env::var(env_var) {
                self.credentials.insert(project_name.to_string(), auth);
                info!("Loaded credentials for project: {}", project_name);
            }
        }

        if self.credentials.is_empty() {
            return Err(anyhow::anyhow!(
                "No BOINC project credentials found in environment variables"
            ));
        }

        Ok(())
    }

    /// Get authenticator for a project
    pub fn get_authenticator(&self, project_name: &str) -> Option<&String> {
        self.credentials.get(project_name)
    }

    /// Check if credentials need rotation (placeholder for future implementation)
    pub fn needs_rotation(&self) -> bool {
        // Simple time-based rotation check (rotate every 30 days)
        let thirty_days = std::time::Duration::from_secs(30 * 24 * 60 * 60);
        self.last_rotation.elapsed().unwrap_or(thirty_days) > thirty_days
    }

    /// Rotate credentials (placeholder for future implementation)
    pub fn rotate_credentials(&mut self) -> Result<()> {
        warn!("Credential rotation not yet implemented - manual rotation required");
        self.last_rotation = std::time::SystemTime::now();
        Ok(())
    }

    /// Validate credential strength
    pub fn validate_credential(&self, project_name: &str) -> Result<()> {
        let auth = self
            .get_authenticator(project_name)
            .ok_or_else(|| anyhow::anyhow!("No credentials found for project: {}", project_name))?;

        if auth.len() < 16 {
            return Err(anyhow::anyhow!(
                "Authenticator for {} is too short (minimum 16 characters)",
                project_name
            ));
        }

        if !auth.chars().all(|c| c.is_alphanumeric()) {
            return Err(anyhow::anyhow!(
                "Authenticator for {} contains invalid characters",
                project_name
            ));
        }

        Ok(())
    }
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_for_logging() {
        // For strings <= 20 chars with sensitive pattern, show first 2 and last 2
        assert_eq!(sanitize_for_logging("my_authenticator_123"), "my***23");
        assert_eq!(sanitize_for_logging("api_key_secret"), "ap***et");
        assert_eq!(sanitize_for_logging("normal_data"), "normal_data");
    }

    #[test]
    fn test_config_validation() {
        let mut config = PoiConfig::default();
        config.oracle.api_key = "testApiKey1234567890abcdefghijklm".to_string(); // At least 32 chars
        config.boinc.projects.insert(
            "Test".to_string(),
            ProjectConfig {
                name: "Test".to_string(),
                scheduler_url: "https://test.example.com".to_string(),
                authenticator: "testAuthenticator123456".to_string(), // At least 16 chars, alphanumeric only
                master_url: "https://test.example.com".to_string(),
            },
        );

        let result = config.validate();
        if result.is_err() {
            eprintln!("Validation error: {:?}", result);
        }
        assert!(result.is_ok());
    }
}
