//! BOINC Compatibility Layer
//!
//! Provides unified API that can delegate to either client-driven or FFI approaches.

use crate::pouw::boinc::apis::BoincApiClient;
use crate::pouw::boinc::client::{BoincClient, BoincProject, BoincWorkUnit};
use crate::pouw::models::BoincWork;
use anyhow::Result;
use tracing::debug;

/// Compatibility shim for BOINC integration
/// Provides unified API that can delegate to either client-driven or FFI approaches
pub struct BoincCompatClient {
    client: BoincClient,
    api_client: Option<BoincApiClient>,
    use_client_mode: bool,
}

impl BoincCompatClient {
    pub fn new(use_client_mode: bool) -> Self {
        let api_client = if use_client_mode {
            None
        } else {
            Some(
                BoincApiClient::from_config_file("config.json").expect("Failed to load API config"),
            )
        };

        Self {
            client: BoincClient::new(),
            api_client,
            use_client_mode,
        }
    }

    pub fn add_project(&mut self, project: BoincProject) {
        if self.use_client_mode {
            self.client.add_project(project);
        } else {
            let api = self
                .api_client
                .as_ref()
                .expect("API client missing in FFI mode");
            debug!(
                "FFI mode: project '{}' registered via remote API provider count {}",
                project.name,
                api.provider_count()
            );
            debug!("FFI mode: project registration would happen here");
        }
    }

    pub async fn fetch_work(&self, project_name: &str) -> Result<Vec<BoincWork>> {
        if self.use_client_mode {
            let wus = vec![BoincWorkUnit {
                name: "example_wu".to_string(),
                project_name: project_name.to_string(),
                user_id: "user123".to_string(),
                task_id: "task456".to_string(),
                cpu_time: 3600.0,
                credit_granted: 1000.0,
                completion_time: chrono::Utc::now(),
            }];
            Ok(wus
                .into_iter()
                .map(|wu| self.convert_work_unit(wu))
                .collect())
        } else {
            let api = self
                .api_client
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("API client not configured"))?;
            let work_units = api.fetch_work(project_name).await?;
            Ok(work_units)
        }
    }

    /// Get project status
    pub async fn get_project_status(&self, project_name: &str) -> Result<serde_json::Value> {
        if self.use_client_mode {
            self.client.get_project_status(project_name).await
        } else {
            let api = self
                .api_client
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("API client not configured"))?;
            let works = api.fetch_work(project_name).await?;
            Ok(serde_json::json!({
                "project": project_name,
                "pending_work_units": works.len(),
            }))
        }
    }

    // Convert between internal and external work unit formats
    fn convert_work_unit(&self, wu: BoincWorkUnit) -> BoincWork {
        BoincWork {
            project_name: wu.project_name,
            user_id: wu.user_id,
            task_id: wu.task_id,
            cpu_time: wu.cpu_time,
            credit_granted: wu.credit_granted,
            completion_time: wu.completion_time,
            validation_state: Some(crate::pouw::models::ValidationState::Pending),
        }
    }
}

impl Default for BoincCompatClient {
    fn default() -> Self {
        Self::new(true) // Default to client mode
    }
}
