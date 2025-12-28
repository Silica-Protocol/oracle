//! BOINC API Client
//!
//! HTTP-based client for communicating with BOINC project APIs.

use crate::pouw::models::{BoincWork, ValidationState};
use anyhow::{Result, anyhow};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoincApiProvider {
    pub name: String,
    pub project_url: String,
    /// Optional explicit API base (use this if the project exposes a separate API path)
    #[serde(default)]
    pub api_endpoint: Option<String>,
    pub user_id: String,
    pub auth_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoincApiConfig {
    pub providers: Vec<BoincApiProvider>,
}

pub struct BoincApiClient {
    client: Client,
    providers: HashMap<String, BoincApiProvider>,
}

impl BoincApiClient {
    pub fn from_config_file(path: &str) -> Result<Self> {
        let config_str = fs::read_to_string(path)?;
        let config: BoincApiConfig = serde_json::from_str(&config_str)?;
        let mut providers = HashMap::new();
        for provider in config.providers {
            // Warn early if user_id or auth_key is empty since many project RPCs require it
            if provider.user_id.trim().is_empty() {
                tracing::warn!(
                    "BOINC provider '{}' has an empty user_id in {}. RPC calls may fail.",
                    provider.name,
                    path
                );
            }
            if provider.auth_key.trim().is_empty() {
                tracing::warn!(
                    "BOINC provider '{}' has an empty auth_key in {}. RPC calls may fail.",
                    provider.name,
                    path
                );
            }
            providers.insert(provider.name.clone(), provider);
        }
        let client = Client::builder()
            .user_agent("Chert-Coin-PoI/1.0")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        Ok(Self { client, providers })
    }

    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Fetch work for any configured BOINC provider by name. User/task details are taken from config.
    pub async fn fetch_work(&self, provider_name: &str) -> Result<Vec<BoincWork>> {
        let provider = self
            .providers
            .get(provider_name)
            .ok_or_else(|| anyhow!("No provider config for {}", provider_name))?;

        // Choose API base: use project_url for consistency
        let base = provider.project_url.trim_end_matches('/');
        // Use the BOINC standard show_account.php endpoint with XML format
        let url = format!("{}/show_user.php", base);
        let mut params = vec![("auth", provider.auth_key.as_str()), ("format", "xml")];
        if !provider.user_id.is_empty() {
            params.push(("id", provider.user_id.as_str()));
        }

        debug!(
            "Fetching user data from BOINC API: {} -> {} (auth: {}...)",
            provider_name,
            url,
            if provider.auth_key.len() > 8 {
                &provider.auth_key[..8]
            } else {
                &provider.auth_key
            }
        );

        let response = self
            .client
            .get(&url)
            .query(&params)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to send request to {}: {}", url, e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "failed to read response body".to_string());
            return Err(anyhow!(
                "{} API returned HTTP {} for {}: {}",
                provider_name,
                status,
                url,
                body
            ));
        }
        let xml_content = response.text().await?;
        debug!(
            "Received XML response from {}: {} bytes",
            provider_name,
            xml_content.len()
        );

        // Check for API errors in the XML response
        if xml_content.contains("<error>") {
            // Parse the error message for better debugging
            if let Some(error_msg) = extract_xml_tag_content(&xml_content, "error_msg") {
                return Err(anyhow!(
                    "{} authentication failed: {}. Please check your account credentials in config.json",
                    provider_name,
                    error_msg
                ));
            }
            if let Some(error_num) = extract_xml_tag_content(&xml_content, "error_num") {
                return Err(anyhow!(
                    "{} API error {}: Please verify your authenticator key is correct",
                    provider_name,
                    error_num
                ));
            }
            return Err(anyhow!(
                "{} API returned error in XML response. Please check your account credentials.",
                provider_name
            ));
        }

        self.parse_boinc_xml(provider_name, &xml_content).await
    }

    /// Parse BOINC XML response from show_user.php endpoint
    async fn parse_boinc_xml(&self, provider_name: &str, xml: &str) -> Result<Vec<BoincWork>> {
        debug!(
            "Parsing BOINC XML for {}: {}",
            provider_name,
            &xml[..std::cmp::min(200, xml.len())]
        );

        // Parse XML response to extract user work data
        if xml.contains("<user>") && xml.contains("<id>") {
            // Extract user data from XML response
            let user_id =
                extract_xml_tag_content(xml, "id").unwrap_or_else(|| "unknown".to_string());
            let total_credit = extract_xml_tag_content(xml, "total_credit")
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0);
            let expavg_credit = extract_xml_tag_content(xml, "expavg_credit")
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0);

            debug!(
                "Parsed BOINC user data - ID: {}, Total Credit: {}, Avg Credit: {}",
                user_id, total_credit, expavg_credit
            );

            // Generate work entries based on user's credit history
            let work_count = if total_credit > 1000.0 {
                3
            } else if total_credit > 100.0 {
                2
            } else {
                1
            };
            let mut works = Vec::new();

            for i in 0..work_count {
                let work = BoincWork {
                    project_name: provider_name.to_string(),
                    user_id: user_id.clone(),
                    task_id: format!(
                        "{}_task_{}",
                        provider_name.to_lowercase().replace("@", "_"),
                        i + 1
                    ),
                    cpu_time: 3600.0 * (i as f64 + 1.0), // Variable CPU time
                    credit_granted: expavg_credit / work_count as f64,
                    completion_time: Utc::now() - chrono::Duration::days(i as i64),
                    validation_state: Some(ValidationState::Validated),
                };
                works.push(work);
            }

            debug!("Generated {} work entries from BOINC data", works.len());
            return Ok(works);
        }

        Err(anyhow!(
            "No valid user data found in BOINC XML response for {}",
            provider_name
        ))
    }

    // (Folding@Home and other project-specific code can be refactored similarly if needed)
}

/// Helper function to extract content between XML tags
fn extract_xml_tag_content(xml: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{}>", tag);
    let end_tag = format!("</{}>", tag);

    if let Some(start) = xml.find(&start_tag)
        && let Some(end) = xml.find(&end_tag)
    {
        let content_start = start + start_tag.len();
        if content_start < end {
            return Some(xml[content_start..end].trim().to_string());
        }
    }
    None
}
