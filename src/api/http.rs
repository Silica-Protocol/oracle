use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;
use tracing::{info, warn};
use url::Url;

/// Security requirements for HTTPS communications
#[derive(Debug, Clone)]
pub struct HttpSecurityConfig {
    /// Require HTTPS for all external communications
    pub require_https: bool,
    /// Verify TLS certificates
    pub verify_certificates: bool,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Maximum response size in bytes
    pub max_response_size: usize,
    /// Allowed BOINC project domains
    pub allowed_domains: Vec<String>,
}

impl Default for HttpSecurityConfig {
    fn default() -> Self {
        Self {
            require_https: true,
            verify_certificates: true,
            timeout_secs: 30,
            max_response_size: 10 * 1024 * 1024, // 10MB max
            allowed_domains: vec![
                "milkyway.cs.rpi.edu".to_string(),
                "boinc.bakerlab.org".to_string(),
                "setiathome.berkeley.edu".to_string(),
                "einstein.phys.uwm.edu".to_string(),
            ],
        }
    }
}

/// Secure HTTP client for BOINC communications
#[derive(Clone)]
pub struct SecureHttpClient {
    client: Client,
    config: HttpSecurityConfig,
}

impl SecureHttpClient {
    /// Create a new secure HTTP client with validation
    pub fn new(config: HttpSecurityConfig) -> Result<Self> {
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent("ChertPoI/1.0 (Secure BOINC Proxy)");

        if config.require_https {
            // Only allow HTTPS connections
            client_builder = client_builder.https_only(true);
            info!("HTTPS enforcement enabled for all external communications");
        }

        if config.verify_certificates {
            // Use system root certificates for validation
            client_builder = client_builder.tls_built_in_root_certs(true);
            info!("TLS certificate verification enabled");
        } else {
            warn!("TLS certificate verification disabled - this is insecure!");
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        let client = client_builder
            .build()
            .context("Failed to create secure HTTP client")?;

        Ok(Self { client, config })
    }

    /// Validate URL for security requirements
    fn validate_url(&self, url: &str) -> Result<Url> {
        let parsed_url = Url::parse(url).context("Invalid URL format")?;

        // Enforce HTTPS if required
        if self.config.require_https && parsed_url.scheme() != "https" {
            return Err(anyhow::anyhow!(
                "HTTPS is required but URL uses {}: {}",
                parsed_url.scheme(),
                url
            ));
        }

        // Validate against allowed domains
        if let Some(host) = parsed_url.host_str() {
            if !self
                .config
                .allowed_domains
                .iter()
                .any(|domain| host == domain || host.ends_with(&format!(".{}", domain)))
            {
                return Err(anyhow::anyhow!(
                    "Domain '{}' is not in the allowed list: {:?}",
                    host,
                    self.config.allowed_domains
                ));
            }
        } else {
            return Err(anyhow::anyhow!("URL must have a valid host: {}", url));
        }

        // Reject localhost and private IPs in production
        if let Some(host) = parsed_url.host_str()
            && (host == "localhost"
                || host == "127.0.0.1"
                || host.starts_with("192.168.")
                || host.starts_with("10.")
                || host.starts_with("172."))
        {
            warn!(
                "Allowing private/localhost URL: {} (should be disabled in production)",
                url
            );
        }

        Ok(parsed_url)
    }

    /// Securely POST XML data to a BOINC project
    pub async fn post_xml_secure(&self, url: &str, xml_data: &str) -> Result<String> {
        // Validate URL first
        let validated_url = self.validate_url(url)?;

        // Validate XML size
        if xml_data.len() > self.config.max_response_size {
            return Err(anyhow::anyhow!(
                "XML data too large: {} bytes (max: {})",
                xml_data.len(),
                self.config.max_response_size
            ));
        }

        info!("Securely posting XML to validated URL: {}", validated_url);

        // Make the secure request
        let response = self
            .client
            .post(validated_url.as_str())
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("Accept", "text/xml, application/xml")
            .body(xml_data.to_string())
            .send()
            .await
            .context("Failed to send HTTP request")?;

        // Validate response status
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "HTTP request failed with status {}: {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            ));
        }

        // Validate response size
        let content_length = response.content_length().unwrap_or(0);
        if content_length > self.config.max_response_size as u64 {
            return Err(anyhow::anyhow!(
                "Response too large: {} bytes (max: {})",
                content_length,
                self.config.max_response_size
            ));
        }

        // Get response text with size limit
        let response_text = response
            .text()
            .await
            .context("Failed to read response body")?;

        if response_text.len() > self.config.max_response_size {
            return Err(anyhow::anyhow!(
                "Response body too large: {} bytes (max: {})",
                response_text.len(),
                self.config.max_response_size
            ));
        }

        info!("Received secure response: {} bytes", response_text.len());
        Ok(response_text)
    }

    /// Securely GET data from a URL
    pub async fn get_secure(&self, url: &str) -> Result<String> {
        let validated_url = self.validate_url(url)?;

        info!("Securely fetching from validated URL: {}", validated_url);

        let response = self
            .client
            .get(validated_url.as_str())
            .header("Accept", "text/html, application/xml, text/xml")
            .send()
            .await
            .context("Failed to send HTTP request")?;

        let status = response.status();
        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "HTTP request failed with status {}: {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            ));
        }

        let content_length = response.content_length().unwrap_or(0);
        if content_length > self.config.max_response_size as u64 {
            return Err(anyhow::anyhow!(
                "Response too large: {} bytes (max: {})",
                content_length,
                self.config.max_response_size
            ));
        }

        let response_text = response
            .text()
            .await
            .context("Failed to read response body")?;

        if response_text.len() > self.config.max_response_size {
            return Err(anyhow::anyhow!(
                "Response body too large: {} bytes (max: {})",
                response_text.len(),
                self.config.max_response_size
            ));
        }

        Ok(response_text)
    }

    /// Get the underlying client for other operations
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Get the security configuration
    pub fn config(&self) -> &HttpSecurityConfig {
        &self.config
    }
}

/// Validate that a URL is safe for BOINC project communication
pub fn validate_boinc_project_url(url: &str, require_https: bool) -> Result<()> {
    let parsed = Url::parse(url).context("Invalid URL format")?;

    if require_https && parsed.scheme() != "https" {
        return Err(anyhow::anyhow!(
            "HTTPS is required for BOINC project URLs: {}",
            url
        ));
    }

    // Check for known BOINC project patterns
    if let Some(host) = parsed.host_str() {
        let known_patterns = [
            ".berkeley.edu",
            ".rpi.edu",
            ".uwm.edu",
            ".bakerlab.org",
            "boinc.",
        ];

        let is_known_boinc = known_patterns.iter().any(|pattern| host.contains(pattern));

        if !is_known_boinc {
            warn!("URL may not be a known BOINC project: {}", host);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_validation() {
        let config = HttpSecurityConfig::default();
        let client = SecureHttpClient::new(config).unwrap();

        // Valid HTTPS URL
        assert!(
            client
                .validate_url("https://milkyway.cs.rpi.edu/milkyway_cgi/cgi")
                .is_ok()
        );

        // Invalid HTTP URL when HTTPS required
        assert!(
            client
                .validate_url("http://milkyway.cs.rpi.edu/milkyway_cgi/cgi")
                .is_err()
        );

        // Disallowed domain
        assert!(client.validate_url("https://evil.example.com/").is_err());
    }

    #[test]
    fn test_boinc_project_validation() {
        assert!(validate_boinc_project_url("https://milkyway.cs.rpi.edu/milkyway/", true).is_ok());
        assert!(validate_boinc_project_url("http://milkyway.cs.rpi.edu/milkyway/", true).is_err());
        assert!(validate_boinc_project_url("https://boinc.bakerlab.org/rosetta/", true).is_ok());
    }
}
