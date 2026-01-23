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

//! BGCF (Breakout Gateway Control Function) Implementation
//!
//! The BGCF is responsible for routing SIP requests that need to break out
//! to external networks such as the PSTN. It analyzes call destinations and
//! determines the appropriate MGCF for call processing.

use crate::config::CynanConfig;
use crate::core::{
    routing::{RouteAction, RouteContext},
    sip_utils::{create_302_moved_temporarily, extract_header},
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::{debug, info, warn};
use rsip::{request::Request, response::Response};
use std::collections::HashMap;
use std::sync::Arc;

use crate::modules::traits::ImsModule;

/// Routing entry for BGCF
#[derive(Debug, Clone, serde::Deserialize)]
pub struct RoutingEntry {
    /// Destination pattern (e.g., "+1*", "sip:*@pstn.example.com")
    pub pattern: String,
    /// Target MGCF URI
    pub mgcf_uri: String,
    /// Priority (higher values = higher priority)
    pub priority: u32,
    /// Route type
    pub route_type: RouteType,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub enum RouteType {
    /// PSTN breakout routing
    Pstn,
    /// Emergency call routing
    Emergency,
    /// International call routing
    International,
    /// Local network routing
    Local,
}

/// BGCF (Breakout Gateway Control Function) Module
///
/// Handles routing decisions for calls that need to break out to external networks.
/// Analyzes destination addresses and determines appropriate MGCF for call processing.
pub struct BgcfModule {
    /// Routing table for different destination patterns
    routing_table: HashMap<String, RoutingEntry>,
    /// MGCF instances and their capabilities
    mgcf_instances: HashMap<String, MgcfInstance>,
    /// Default MGCF for fallback routing
    default_mgcf: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct MgcfInstance {
    /// MGCF SIP URI
    pub uri: String,
    /// Supported call types
    pub capabilities: Vec<String>,
    /// Current load (0-100)
    pub load: u32,
    /// Active sessions
    pub active_sessions: u32,
    /// Maximum concurrent sessions
    pub max_sessions: u32,
}

impl BgcfModule {
    pub fn new() -> Self {
        let mut routing_table = HashMap::new();
        let mut mgcf_instances = HashMap::new();

        // Initialize with default PSTN routing rules
        Self::initialize_default_routing(&mut routing_table);
        Self::initialize_default_mgcf(&mut mgcf_instances);

        Self {
            routing_table,
            mgcf_instances,
            default_mgcf: Some("sip:mgcf.cynan.ims:5060".to_string()),
        }
    }

    /// Initialize default routing table with common PSTN patterns
    fn initialize_default_routing(routing_table: &mut HashMap<String, RoutingEntry>) {
        // Emergency numbers - highest priority
        routing_table.insert(
            "emergency".to_string(),
            RoutingEntry {
                pattern: "112|911|999".to_string(),
                mgcf_uri: "sip:mgcf-emergency.cynan.ims:5060".to_string(),
                priority: 100,
                route_type: RouteType::Emergency,
            },
        );

        // International calls
        routing_table.insert(
            "international".to_string(),
            RoutingEntry {
                pattern: r"^\+.*".to_string(),
                mgcf_uri: "sip:mgcf-international.cynan.ims:5060".to_string(),
                priority: 80,
                route_type: RouteType::International,
            },
        );

        // North American Numbering Plan (NANP)
        routing_table.insert(
            "nanp".to_string(),
            RoutingEntry {
                pattern: r"^\+1[0-9]{10}$".to_string(),
                mgcf_uri: "sip:mgcf-nanp.cynan.ims:5060".to_string(),
                priority: 70,
                route_type: RouteType::Pstn,
            },
        );

        // Generic PSTN pattern
        routing_table.insert(
            "pstn".to_string(),
            RoutingEntry {
                pattern: r"^[0-9+\-\.\(\)\s]{7,20}$".to_string(),
                mgcf_uri: "sip:mgcf-pstn.cynan.ims:5060".to_string(),
                priority: 50,
                route_type: RouteType::Pstn,
            },
        );
    }

    /// Initialize default MGCF instances
    fn initialize_default_mgcf(mgcf_instances: &mut HashMap<String, MgcfInstance>) {
        mgcf_instances.insert(
            "sip:mgcf.cynan.ims:5060".to_string(),
            MgcfInstance {
                uri: "sip:mgcf.cynan.ims:5060".to_string(),
                capabilities: vec!["pstn".to_string(), "isdn".to_string()],
                load: 0,
                active_sessions: 0,
                max_sessions: 1000,
            },
        );

        mgcf_instances.insert(
            "sip:mgcf-emergency.cynan.ims:5060".to_string(),
            MgcfInstance {
                uri: "sip:mgcf-emergency.cynan.ims:5060".to_string(),
                capabilities: vec!["emergency".to_string()],
                load: 0,
                active_sessions: 0,
                max_sessions: 100,
            },
        );
    }

    /// Determine if a request needs BGCF processing
    pub fn needs_breakout(&self, req: &Request) -> bool {
        let request_uri = req.uri.to_string();

        // Check if it's a tel: URI (telephone number)
        if request_uri.starts_with("tel:") {
            return true;
        }

        // Check if it's a SIP URI with user=phone parameter
        if request_uri.contains("user=phone") {
            return true;
        }

        // Check against routing patterns
        for entry in self.routing_table.values() {
            if self.matches_pattern(&request_uri, &entry.pattern) {
                return true;
            }
        }

        false
    }

    /// Select the best MGCF for a given destination
    pub fn select_mgcf(&self, destination: &str) -> Option<String> {
        let mut best_match: Option<&RoutingEntry> = None;
        let mut highest_priority = 0;

        // Find the highest priority matching route
        for entry in self.routing_table.values() {
            if self.matches_pattern(destination, &entry.pattern) && entry.priority > highest_priority {
                best_match = Some(entry);
                highest_priority = entry.priority;
            }
        }

        best_match.map(|entry| entry.mgcf_uri.clone())
            .or_else(|| self.default_mgcf.clone())
    }

    /// Find the least loaded MGCF instance
    pub fn select_least_loaded_mgcf(&self, required_capability: Option<&str>) -> Option<String> {
        let mut best_mgcf: Option<&MgcfInstance> = None;
        let mut lowest_load = u32::MAX;

        for mgcf in self.mgcf_instances.values() {
            // Check if MGCF has required capability
            if let Some(cap) = required_capability {
                if !mgcf.capabilities.contains(&cap.to_string()) {
                    continue;
                }
            }

            // Check if MGCF has capacity
            if mgcf.active_sessions >= mgcf.max_sessions {
                continue;
            }

            // Select MGCF with lowest load
            if mgcf.load < lowest_load {
                best_mgcf = Some(mgcf);
                lowest_load = mgcf.load;
            }
        }

        best_mgcf.map(|mgcf| mgcf.uri.clone())
    }

    /// Check if destination matches a routing pattern
    fn matches_pattern(&self, destination: &str, pattern: &str) -> bool {
        // Handle special patterns
        match pattern {
            "112|911|999" => {
                // Emergency numbers
                destination.contains("112") ||
                destination.contains("911") ||
                destination.contains("999")
            }
            pattern if pattern.starts_with("^\+") && pattern.ends_with("$") => {
                // Regex patterns for international numbers
                let regex_pattern = &pattern[1..pattern.len()-1]; // Remove ^ and $
                self.simple_regex_match(destination, regex_pattern)
            }
            pattern if pattern.contains("|") => {
                // OR patterns
                pattern.split('|').any(|p| destination.contains(p.trim()))
            }
            _ => {
                // Simple substring match
                destination.contains(pattern)
            }
        }
    }

    /// Simple regex matching for phone number patterns
    fn simple_regex_match(&self, text: &str, pattern: &str) -> bool {
        // Very basic regex implementation for common phone patterns
        match pattern {
            r"\+.*" => text.starts_with("+"),
            r"\+1[0-9]{10}" => {
                text.starts_with("+1") &&
                text.len() == 12 &&
                text.chars().skip(2).all(|c| c.is_ascii_digit())
            }
            _ => text.contains(pattern),
        }
    }

    /// Update MGCF load information
    pub fn update_mgcf_load(&mut self, mgcf_uri: &str, active_sessions: u32) {
        if let Some(mgcf) = self.mgcf_instances.get_mut(mgcf_uri) {
            mgcf.active_sessions = active_sessions;
            mgcf.load = if mgcf.max_sessions > 0 {
                (active_sessions * 100) / mgcf.max_sessions
            } else {
                0
            };
        }
    }

    /// Add a new routing entry
    pub fn add_routing_entry(&mut self, entry: RoutingEntry) {
        self.routing_table.insert(entry.pattern.clone(), entry);
        info!("Added BGCF routing entry: {} -> {}", entry.pattern, entry.mgcf_uri);
    }

    /// Remove a routing entry
    pub fn remove_routing_entry(&mut self, pattern: &str) {
        if self.routing_table.remove(pattern).is_some() {
            info!("Removed BGCF routing entry: {}", pattern);
        }
    }

    /// Add a new MGCF instance
    pub fn add_mgcf_instance(&mut self, instance: MgcfInstance) {
        self.mgcf_instances.insert(instance.uri.clone(), instance.clone());
        info!("Added BGCF MGCF instance: {} (capabilities: {:?})",
              instance.uri, instance.capabilities);
    }
}

#[async_trait]
impl ImsModule for BgcfModule {
    async fn initialize(&mut self, config: Arc<CynanConfig>) -> Result<()> {
        info!("Initializing BGCF module");

        // Load routing configuration from config if available
        if let Some(bgcf_config) = &config.bgcf {
            // Apply configuration
            for entry in &bgcf_config.routing_entries {
                self.add_routing_entry(entry.clone());
            }

            for mgcf in &bgcf_config.mgcf_instances {
                self.add_mgcf_instance(mgcf.clone());
            }

            if let Some(default) = &bgcf_config.default_mgcf {
                self.default_mgcf = Some(default.clone());
            }
        }

        Ok(())
    }

    async fn process_request(&mut self, req: Request, ctx: RouteContext) -> Result<RouteAction> {
        debug!("BGCF processing request: {} {}", req.method, req.uri);

        // Check if this request needs breakout routing
        if !self.needs_breakout(&req) {
            debug!("Request does not need BGCF breakout routing");
            return Ok(RouteAction::Continue);
        }

        let destination = req.uri.to_string();
        info!("BGCF processing breakout request to: {}", destination);

        // Select appropriate MGCF
        let mgcf_uri = self.select_mgcf(&destination)
            .or_else(|| self.select_least_loaded_mgcf(Some("pstn")))
            .ok_or_else(|| anyhow!("No suitable MGCF found for destination: {}", destination))?;

        info!("BGCF routing to MGCF: {}", mgcf_uri);

        // Create 302 Moved Temporarily response to redirect to MGCF
        let contact_header = format!("<{}>", mgcf_uri);
        let response = create_302_moved_temporarily(&req, &contact_header)?;

        Ok(RouteAction::Respond(response))
    }

    fn name(&self) -> &str {
        "BGCF"
    }

    fn description(&self) -> &str {
        "Breakout Gateway Control Function for PSTN routing"
    }
}

/// BGCF configuration structure
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BgcfConfig {
    /// Default MGCF URI for fallback routing
    pub default_mgcf: Option<String>,
    /// Routing entries for different destination patterns
    pub routing_entries: Vec<RoutingEntry>,
    /// MGCF instances and their configurations
    pub mgcf_instances: Vec<MgcfInstance>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsip::Uri;

    #[test]
    fn test_needs_breakout() {
        let bgcf = BgcfModule::new();

        // Test tel: URI
        let tel_uri = Uri::try_from("tel:+1234567890".to_string()).unwrap();
        let tel_req = Request::builder()
            .method(rsip::Method::Invite)
            .uri(tel_uri)
            .build();

        assert!(bgcf.needs_breakout(&tel_req));
    }

    #[test]
    fn test_select_mgcf() {
        let bgcf = BgcfModule::new();

        // Test emergency number
        assert_eq!(
            bgcf.select_mgcf("tel:911"),
            Some("sip:mgcf-emergency.cynan.ims:5060".to_string())
        );

        // Test international number
        assert_eq!(
            bgcf.select_mgcf("tel:+441234567890"),
            Some("sip:mgcf-international.cynan.ims:5060".to_string())
        );
    }

    #[test]
    fn test_matches_pattern() {
        let bgcf = BgcfModule::new();

        // Test emergency patterns
        assert!(bgcf.matches_pattern("tel:911", "112|911|999"));
        assert!(bgcf.matches_pattern("tel:112", "112|911|999"));

        // Test international pattern
        assert!(bgcf.matches_pattern("tel:+1234567890", r"^\+.*"));
    }
}