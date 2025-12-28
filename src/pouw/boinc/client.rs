use anyhow::Result;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

/// Client-driven BOINC integration - no FFI required
/// Communicates with BOINC projects via XML-RPC API

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoincProject {
    pub name: String,
    pub url: String,
    pub user_id: String,
    pub authenticator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoincWorkUnit {
    pub name: String,
    pub project_name: String,
    pub user_id: String,
    pub task_id: String,
    pub cpu_time: f64,
    pub credit_granted: f64,
    pub completion_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoincResult {
    pub workunit_name: String,
    pub outcome: String,
    pub client_state: String,
    pub host_cpid: String,
    pub canonical_credit: f64,
}

#[derive(Debug)]
pub struct BoincClient {
    client: Client,
    projects: HashMap<String, BoincProject>,
}

impl BoincClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .user_agent("Chert-PoI-Oracle/1.0")
            .timeout(std::time::Duration::from_secs(30))
            // Enable TLS and enforce security
            .use_rustls_tls()
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            // Add additional security headers
            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::USER_AGENT,
                    reqwest::header::HeaderValue::from_static("Chert-PoI-Oracle/1.0"),
                );
                headers.insert(
                    "X-Requested-With",
                    reqwest::header::HeaderValue::from_static("XMLHttpRequest"),
                );
                headers
            })
            .build()
            .expect("Failed to create secure HTTP client");

        Self {
            client,
            projects: HashMap::new(),
        }
    }

    pub fn add_project(&mut self, project: BoincProject) {
        tracing::info!(
            "BoincClient: adding project to internal registry: {}",
            project.name
        );
        self.projects.insert(project.name.clone(), project);
    }

    /// Check if the account exists and is valid with input validation
    pub async fn check_account(&self, project_name: &str) -> Result<bool> {
        // Validate project name to prevent injection attacks
        if project_name.is_empty() || project_name.len() > 100 {
            return Err(anyhow::anyhow!("Invalid project name length"));
        }

        if project_name
            .chars()
            .any(|c| c.is_control() || c == '\'' || c == '"' || c == '\\')
        {
            return Err(anyhow::anyhow!("Project name contains invalid characters"));
        }

        let project = match self.projects.get(project_name) {
            Some(p) => p,
            None => {
                let configured: Vec<String> = self.projects.keys().cloned().collect();
                return Err(anyhow::anyhow!(
                    "Project '{}' not configured. Configured projects: {:?}",
                    project_name,
                    configured
                ));
            }
        };

        // Validate URL format and ensure HTTPS
        let base_url = project.url.clone();
        if !base_url.starts_with("https://") {
            return Err(anyhow::anyhow!("Project URL must use HTTPS for security"));
        }

        // Validate authenticator format (should be hex string)
        if project.authenticator.len() < 16 || project.authenticator.len() > 64 {
            return Err(anyhow::anyhow!("Invalid authenticator length"));
        }

        if !project
            .authenticator
            .chars()
            .all(|c| c.is_ascii_alphanumeric())
        {
            return Err(anyhow::anyhow!("Authenticator contains invalid characters"));
        }

        let lookup_url = format!("{}/lookup_account.php", base_url.trim_end_matches('/'));

        info!("🔍 BOINC ACCOUNT CHECK - URL: {}", lookup_url);
        info!("🔍 BOINC ACCOUNT CHECK - Method: POST");
        info!("🔍 BOINC ACCOUNT CHECK - Headers: Content-Type: application/x-www-form-urlencoded");

        // Account lookup parameters with proper escaping
        let lookup_params = format!(
            "authenticator={}&platform=linux&version=7.16.0",
            urlencoding::encode(&project.authenticator)
        );
        info!("🔍 BOINC ACCOUNT CHECK - Body: {}", lookup_params);

        let response = self
            .client
            .post(&lookup_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(lookup_params)
            .send()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                info!("🔍 BOINC ACCOUNT CHECK RESPONSE - Status: {}", status);

                match resp.text().await {
                    Ok(body) => {
                        info!("🔍 BOINC ACCOUNT CHECK RESPONSE - Body: {}", body);

                        if status.is_success() && !body.contains("error") {
                            info!(
                                "✅ Account validation successful for project: {}",
                                project_name
                            );
                            Ok(true)
                        } else {
                            info!(
                                "❌ Account validation failed for project: {} - Status: {}",
                                project_name, status
                            );
                            Ok(false)
                        }
                    }
                    Err(e) => {
                        info!(
                            "🔍 BOINC ACCOUNT CHECK RESPONSE - Failed to read body: {}",
                            e
                        );
                        Ok(false)
                    }
                }
            }
            Err(e) => {
                info!(
                    "❌ BOINC ACCOUNT CHECK REQUEST FAILED - URL: {} - Error: {}",
                    lookup_url, e
                );
                Err(anyhow::anyhow!("Account check failed: {}", e))
            }
        }
    }

    /// Get project status and statistics
    pub async fn get_project_status(&self, project_name: &str) -> Result<serde_json::Value> {
        let project = match self.projects.get(project_name) {
            Some(p) => p,
            None => {
                let configured: Vec<String> = self.projects.keys().cloned().collect();
                return Err(anyhow::anyhow!(
                    "Project '{}' not configured. Configured projects: {:?}",
                    project_name,
                    configured
                ));
            }
        };

        let stats_url = format!("{}/stats/", project.url);
        info!("🔍 BOINC PROJECT STATUS REQUEST - URL: {}", stats_url);
        info!("🔍 BOINC PROJECT STATUS REQUEST - Method: GET");

        let response = self.client.get(&stats_url).send().await?;

        let status = response.status();
        info!("🔍 BOINC PROJECT STATUS RESPONSE - Status: {}", status);
        info!(
            "🔍 BOINC PROJECT STATUS RESPONSE - Headers: {:?}",
            response.headers()
        );

        let json_data = response.json().await?;
        info!("🔍 BOINC PROJECT STATUS RESPONSE - Body: {:?}", json_data);

        Ok(json_data)
    }

    /// Get user profile and statistics
    pub async fn get_user_profile(&self, project_name: &str) -> Result<UserProfile> {
        let project = match self.projects.get(project_name) {
            Some(p) => p,
            None => return Err(anyhow::anyhow!("Project '{}' not configured", project_name)),
        };

        // This would typically call a BOINC API endpoint for user stats
        // For now, return mock data
        Ok(UserProfile {
            user_id: project.user_id.clone(),
            total_credit: 1000.0,
            recent_average_credit: 50.0,
            project_name: project_name.to_string(),
            join_date: Utc::now() - chrono::Duration::days(30),
        })
    }

    /// Get configured projects list
    pub async fn get_configured_projects(&self) -> Vec<String> {
        self.projects.keys().cloned().collect()
    }

    /// Get project authenticator by project name
    pub fn get_project_authenticator(&self, project_name: &str) -> Option<String> {
        self.projects
            .get(project_name)
            .map(|p| p.authenticator.clone())
    }

    /// Get project status information for all projects
    pub async fn get_all_project_status(&self) -> Vec<ProjectStatus> {
        let mut status = Vec::new();

        for (name, project) in &self.projects {
            // Check if project is reachable
            let is_online = self.check_project_online(name).await.unwrap_or(false);

            status.push(ProjectStatus {
                name: name.clone(),
                url: project.url.clone(),
                user_count: 0, // TODO: Get from project stats
                status: if is_online { "Online" } else { "Offline" }.to_string(),
            });
        }

        status
    }

    /// Check if project is online
    async fn check_project_online(&self, project_name: &str) -> Result<bool> {
        let project = match self.projects.get(project_name) {
            Some(p) => p,
            None => return Ok(false),
        };

        let response = self.client.get(&project.url).send().await?;

        Ok(response.status().is_success())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub user_id: String,
    pub total_credit: f64,
    pub recent_average_credit: f64,
    pub project_name: String,
    pub join_date: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectStatus {
    pub name: String,
    pub url: String,
    pub user_count: usize,
    pub status: String,
}

impl Default for BoincClient {
    fn default() -> Self {
        Self::new()
    }
}
