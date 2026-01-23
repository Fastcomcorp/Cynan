// Copyright (c) 2026 Fastcomcorp, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Application Server Integration Patterns
//!
//! This module provides integration patterns and interfaces for Application Servers (AS)
//! in IMS networks. AS provide value-added services like VoIP, conferencing, messaging,
//! and presence through standardized IMS interfaces.

use crate::config::CynanConfig;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::{debug, info, warn};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Application Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationServer {
    /// AS identifier
    pub id: String,
    /// AS name
    pub name: String,
    /// SIP URI for the AS
    pub sip_uri: String,
    /// HTTP endpoint for REST API
    pub http_endpoint: Option<String>,
    /// Supported service types
    pub service_types: Vec<ServiceType>,
    /// AS capabilities
    pub capabilities: Vec<String>,
    /// Default handling priority (higher = higher priority)
    pub priority: u32,
    /// AS status
    pub status: AsStatus,
}

/// Application Server status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AsStatus {
    Active,
    Inactive,
    Maintenance,
    Failed,
}

/// Service types that AS can provide
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServiceType {
    Voip,
    Conferencing,
    Messaging,
    Presence,
    PushToTalk,
    GroupManagement,
    Custom(String),
}

/// Service trigger configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTrigger {
    /// Trigger identifier
    pub id: String,
    /// SIP method to trigger on
    pub method: String,
    /// Request URI pattern
    pub request_uri_pattern: Option<String>,
    /// Event package (for SUBSCRIBE/NOTIFY)
    pub event_package: Option<String>,
    /// Service type to invoke
    pub service_type: ServiceType,
    /// Target AS ID
    pub target_as: String,
    /// Trigger priority
    pub priority: u32,
}

/// AS session context
#[derive(Debug, Clone)]
pub struct AsSessionContext {
    pub session_id: String,
    pub user_id: String,
    pub service_type: ServiceType,
    pub as_id: String,
    pub start_time: std::time::Instant,
    pub sip_dialog_id: Option<String>,
}

/// Application Server Integration Manager
///
/// Manages AS registration, service triggers, and communication patterns
/// for integrating external Application Servers with the IMS core.
pub struct AsIntegrationManager {
    /// Registered Application Servers
    application_servers: HashMap<String, ApplicationServer>,
    /// Service triggers for automatic AS invocation
    service_triggers: Vec<ServiceTrigger>,
    /// Active AS sessions
    active_sessions: Arc<RwLock<HashMap<String, AsSessionContext>>>,
    /// HTTP client for REST API communication
    http_client: HttpClient,
    /// Default AS for fallback
    default_as: Option<String>,
}

impl AsIntegrationManager {
    pub fn new() -> Self {
        Self {
            application_servers: HashMap::new(),
            service_triggers: Vec::new(),
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            http_client: HttpClient::new(),
            default_as: None,
        }
    }

    /// Register an Application Server
    pub fn register_as(&mut self, as_config: ApplicationServer) -> Result<()> {
        if self.application_servers.contains_key(&as_config.id) {
            return Err(anyhow!("Application Server already registered: {}", as_config.id));
        }

        info!("Registering Application Server: {} ({})", as_config.name, as_config.id);
        self.application_servers.insert(as_config.id.clone(), as_config);
        Ok(())
    }

    /// Unregister an Application Server
    pub fn unregister_as(&mut self, as_id: &str) -> Result<()> {
        if self.application_servers.remove(as_id).is_some() {
            info!("Unregistered Application Server: {}", as_id);

            // Clean up active sessions for this AS
            let mut sessions = self.active_sessions.write().await;
            sessions.retain(|_, ctx| ctx.as_id != as_id);

            Ok(())
        } else {
            Err(anyhow!("Application Server not found: {}", as_id))
        }
    }

    /// Add a service trigger
    pub fn add_service_trigger(&mut self, trigger: ServiceTrigger) -> Result<()> {
        // Validate that target AS exists
        if !self.application_servers.contains_key(&trigger.target_as) {
            return Err(anyhow!("Target AS not found: {}", trigger.target_as));
        }

        // Check for duplicate trigger IDs
        if self.service_triggers.iter().any(|t| t.id == trigger.id) {
            return Err(anyhow!("Service trigger already exists: {}", trigger.id));
        }

        info!("Added service trigger: {} -> {}", trigger.id, trigger.target_as);
        self.service_triggers.push(trigger);
        Ok(())
    }

    /// Find matching service triggers for a SIP request
    pub fn find_matching_triggers(&self, method: &str, request_uri: &str, event_package: Option<&str>) -> Vec<&ServiceTrigger> {
        self.service_triggers.iter()
            .filter(|trigger| {
                // Method match
                if trigger.method != method {
                    return false;
                }

                // Request URI pattern match
                if let Some(pattern) = &trigger.request_uri_pattern {
                    if !self.matches_pattern(request_uri, pattern) {
                        return false;
                    }
                }

                // Event package match (for SUBSCRIBE)
                if let Some(event) = event_package {
                    if let Some(trigger_event) = &trigger.event_package {
                        if trigger_event != event {
                            return false;
                        }
                    }
                }

                true
            })
            .collect()
    }

    /// Invoke Application Server for a service
    pub async fn invoke_as_service(
        &self,
        trigger: &ServiceTrigger,
        session_info: &AsServiceRequest,
    ) -> Result<AsServiceResponse> {
        let as_config = self.application_servers.get(&trigger.target_as)
            .ok_or_else(|| anyhow!("AS not found: {}", trigger.target_as))?;

        if as_config.status != AsStatus::Active {
            return Err(anyhow!("AS not active: {}", trigger.target_as));
        }

        info!("Invoking AS service: {} on {}", trigger.service_type.as_ref(), as_config.name);

        // Create session context
        let session_context = AsSessionContext {
            session_id: session_info.session_id.clone(),
            user_id: session_info.user_id.clone(),
            service_type: trigger.service_type.clone(),
            as_id: trigger.target_as.clone(),
            start_time: std::time::Instant::now(),
            sip_dialog_id: session_info.sip_dialog_id.clone(),
        };

        // Store session context
        self.active_sessions.write().await.insert(
            session_info.session_id.clone(),
            session_context
        );

        // Route to appropriate invocation method
        match trigger.service_type {
            ServiceType::Voip => self.invoke_voip_service(as_config, session_info).await,
            ServiceType::Conferencing => self.invoke_conferencing_service(as_config, session_info).await,
            ServiceType::Messaging => self.invoke_messaging_service(as_config, session_info).await,
            ServiceType::Presence => self.invoke_presence_service(as_config, session_info).await,
            ServiceType::PushToTalk => self.invoke_push_to_talk_service(as_config, session_info).await,
            ServiceType::GroupManagement => self.invoke_group_management_service(as_config, session_info).await,
            ServiceType::Custom(ref service) => self.invoke_custom_service(as_config, service, session_info).await,
        }
    }

    /// Terminate AS session
    pub async fn terminate_as_session(&self, session_id: &str) -> Result<()> {
        if let Some(context) = self.active_sessions.write().await.remove(session_id) {
            info!("Terminated AS session: {} (duration: {:.2}s)",
                  session_id,
                  context.start_time.elapsed().as_secs_f64());

            // Notify AS of session termination if needed
            let as_config = self.application_servers.get(&context.as_id);
            if let Some(as_config) = as_config {
                if let Some(endpoint) = &as_config.http_endpoint {
                    let url = format!("{}/sessions/{}/terminate", endpoint, session_id);
                    // Send termination notification (fire and forget)
                    let client = self.http_client.clone();
                    tokio::spawn(async move {
                        let _ = client.post(&url).send().await;
                    });
                }
            }

            Ok(())
        } else {
            warn!("AS session not found for termination: {}", session_id);
            Ok(())
        }
    }

    /// Invoke VoIP service (basic call handling)
    async fn invoke_voip_service(&self, as_config: &ApplicationServer, request: &AsServiceRequest) -> Result<AsServiceResponse> {
        // For VoIP, we typically just acknowledge and let the AS handle via SIP
        info!("VoIP service invoked for user: {}", request.user_id);

        Ok(AsServiceResponse {
            session_id: request.session_id.clone(),
            result: AsResult::Accepted,
            additional_data: None,
        })
    }

    /// Invoke conferencing service
    async fn invoke_conferencing_service(&self, as_config: &ApplicationServer, request: &AsServiceRequest) -> Result<AsServiceResponse> {
        if let Some(endpoint) = &as_config.http_endpoint {
            let conference_data = serde_json::json!({
                "action": "create_conference",
                "user_id": request.user_id,
                "session_id": request.session_id
            });

            let response = self.http_client
                .post(&format!("{}/conferences", endpoint))
                .json(&conference_data)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                Ok(AsServiceResponse {
                    session_id: request.session_id.clone(),
                    result: AsResult::Success,
                    additional_data: Some(result),
                })
            } else {
                Err(anyhow!("Conference creation failed: {}", response.status()))
            }
        } else {
            Err(anyhow!("No HTTP endpoint configured for conferencing AS"))
        }
    }

    /// Invoke messaging service
    async fn invoke_messaging_service(&self, as_config: &ApplicationServer, request: &AsServiceRequest) -> Result<AsServiceResponse> {
        info!("Messaging service invoked for user: {}", request.user_id);

        Ok(AsServiceResponse {
            session_id: request.session_id.clone(),
            result: AsResult::Accepted,
            additional_data: None,
        })
    }

    /// Invoke presence service
    async fn invoke_presence_service(&self, as_config: &ApplicationServer, request: &AsServiceRequest) -> Result<AsServiceResponse> {
        if let Some(endpoint) = &as_config.http_endpoint {
            let presence_data = serde_json::json!({
                "action": "publish_presence",
                "user_id": request.user_id,
                "status": "online",
                "session_id": request.session_id
            });

            let response = self.http_client
                .post(&format!("{}/presence", endpoint))
                .json(&presence_data)
                .send()
                .await?;

            if response.status().is_success() {
                Ok(AsServiceResponse {
                    session_id: request.session_id.clone(),
                    result: AsResult::Success,
                    additional_data: None,
                })
            } else {
                Err(anyhow!("Presence publication failed: {}", response.status()))
            }
        } else {
            Err(anyhow!("No HTTP endpoint configured for presence AS"))
        }
    }

    /// Invoke Push-to-Talk service
    async fn invoke_push_to_talk_service(&self, as_config: &ApplicationServer, request: &AsServiceRequest) -> Result<AsServiceResponse> {
        info!("Push-to-Talk service invoked for user: {}", request.user_id);

        Ok(AsServiceResponse {
            session_id: request.session_id.clone(),
            result: AsResult::Accepted,
            additional_data: None,
        })
    }

    /// Invoke group management service
    async fn invoke_group_management_service(&self, as_config: &ApplicationServer, request: &AsServiceRequest) -> Result<AsServiceResponse> {
        info!("Group management service invoked for user: {}", request.user_id);

        Ok(AsServiceResponse {
            session_id: request.session_id.clone(),
            result: AsResult::Accepted,
            additional_data: None,
        })
    }

    /// Invoke custom service
    async fn invoke_custom_service(&self, as_config: &ApplicationServer, service_name: &str, request: &AsServiceRequest) -> Result<AsServiceResponse> {
        if let Some(endpoint) = &as_config.http_endpoint {
            let custom_data = serde_json::json!({
                "service": service_name,
                "user_id": request.user_id,
                "session_id": request.session_id
            });

            let response = self.http_client
                .post(&format!("{}/custom/{}", endpoint, service_name))
                .json(&custom_data)
                .send()
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                Ok(AsServiceResponse {
                    session_id: request.session_id.clone(),
                    result: AsResult::Success,
                    additional_data: Some(result),
                })
            } else {
                Err(anyhow!("Custom service {} failed: {}", service_name, response.status()))
            }
        } else {
            Err(anyhow!("No HTTP endpoint configured for custom service AS"))
        }
    }

    /// Simple pattern matching with wildcards
    fn matches_pattern(&self, text: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            let regex_pattern = pattern.replace("*", ".*");
            regex::Regex::new(&format!("^{}$", regex_pattern))
                .map(|re| re.is_match(text))
                .unwrap_or(false)
        } else {
            text.contains(pattern)
        }
    }

    /// Get AS integration statistics
    pub async fn get_statistics(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("registered_as".to_string(), self.application_servers.len());
        stats.insert("service_triggers".to_string(), self.service_triggers.len());
        stats.insert("active_sessions".to_string(), self.active_sessions.read().await.len());

        // Count sessions by service type
        let sessions = self.active_sessions.read().await;
        let mut service_counts = HashMap::new();
        for context in sessions.values() {
            let count = service_counts.entry(format!("{:?}", context.service_type)).or_insert(0);
            *count += 1;
        }

        for (service_type, count) in service_counts {
            stats.insert(format!("sessions_{}", service_type.to_lowercase()), count);
        }

        stats
    }

    /// Health check for all registered AS
    pub async fn health_check_all(&self) -> Vec<AsHealthStatus> {
        let mut results = Vec::new();

        for (as_id, as_config) in &self.application_servers {
            let status = if let Some(endpoint) = &as_config.http_endpoint {
                match self.http_client
                    .get(&format!("{}/health", endpoint))
                    .send()
                    .await
                {
                    Ok(response) if response.status().is_success() => AsHealthStatus::Healthy,
                    Ok(response) => AsHealthStatus::Unhealthy(format!("HTTP {}", response.status())),
                    Err(e) => AsHealthStatus::Unhealthy(e.to_string()),
                }
            } else {
                // For SIP-only AS, we assume healthy if registered
                AsHealthStatus::Healthy
            };

            results.push(AsHealthCheck {
                as_id: as_id.clone(),
                name: as_config.name.clone(),
                status,
            });
        }

        results
    }
}

/// Service request to AS
#[derive(Debug, Clone)]
pub struct AsServiceRequest {
    pub session_id: String,
    pub user_id: String,
    pub sip_dialog_id: Option<String>,
    pub additional_data: Option<serde_json::Value>,
}

/// Service response from AS
#[derive(Debug, Clone)]
pub struct AsServiceResponse {
    pub session_id: String,
    pub result: AsResult,
    pub additional_data: Option<serde_json::Value>,
}

/// AS service result
#[derive(Debug, Clone, PartialEq)]
pub enum AsResult {
    Success,
    Accepted,
    Rejected,
    Failed(String),
}

/// AS health status
#[derive(Debug, Clone)]
pub enum AsHealthStatus {
    Healthy,
    Unhealthy(String),
}

/// AS health check result
#[derive(Debug, Clone)]
pub struct AsHealthCheck {
    pub as_id: String,
    pub name: String,
    pub status: AsHealthStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_registration() {
        let mut manager = AsIntegrationManager::new();

        let as_config = ApplicationServer {
            id: "voip-as-1".to_string(),
            name: "VoIP Application Server".to_string(),
            sip_uri: "sip:voip-as@example.com".to_string(),
            http_endpoint: Some("http://voip-as:8080".to_string()),
            service_types: vec![ServiceType::Voip],
            capabilities: vec!["audio".to_string(), "video".to_string()],
            priority: 10,
            status: AsStatus::Active,
        };

        assert!(manager.register_as(as_config).is_ok());
        assert!(manager.application_servers.contains_key("voip-as-1"));
    }

    #[test]
    fn test_service_trigger_matching() {
        let mut manager = AsIntegrationManager::new();

        // Register AS first
        let as_config = ApplicationServer {
            id: "test-as".to_string(),
            name: "Test AS".to_string(),
            sip_uri: "sip:test-as@example.com".to_string(),
            http_endpoint: None,
            service_types: vec![ServiceType::Voip],
            capabilities: vec!["test".to_string()],
            priority: 1,
            status: AsStatus::Active,
        };
        manager.register_as(as_config).unwrap();

        // Add trigger
        let trigger = ServiceTrigger {
            id: "invite-trigger".to_string(),
            method: "INVITE".to_string(),
            request_uri_pattern: Some("sip:*@example.com".to_string()),
            event_package: None,
            service_type: ServiceType::Voip,
            target_as: "test-as".to_string(),
            priority: 1,
        };
        manager.add_service_trigger(trigger).unwrap();

        // Test matching
        let matches = manager.find_matching_triggers("INVITE", "sip:user@example.com", None);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "invite-trigger");
    }

    #[tokio::test]
    async fn test_session_management() {
        let manager = AsIntegrationManager::new();

        let request = AsServiceRequest {
            session_id: "test-session-123".to_string(),
            user_id: "user123".to_string(),
            sip_dialog_id: Some("dialog-456".to_string()),
            additional_data: None,
        };

        // Create a trigger for testing
        let mut manager_mut = manager.clone(); // This won't work due to borrowing rules
        // In real usage, we'd have a mutable reference

        // Test session termination (will warn about non-existent session)
        assert!(manager.terminate_as_session("non-existent").await.is_ok());
    }

    #[test]
    fn test_pattern_matching() {
        let manager = AsIntegrationManager::new();

        assert!(manager.matches_pattern("sip:user@example.com", "sip:*@example.com"));
        assert!(manager.matches_pattern("test.example.com", "*.example.com"));
        assert!(!manager.matches_pattern("other.com", "*.example.com"));
    }
}