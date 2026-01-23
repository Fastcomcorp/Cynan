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

//! IBCF (Interconnection Border Control Function) Implementation
//!
//! The IBCF handles interworking at network boundaries between different
//! operators or administrative domains. It provides topology hiding, security,
//! and protocol normalization for inter-operator IMS communications.

use crate::config::CynanConfig;
use crate::core::{
    routing::{RouteAction, RouteContext},
    sip_utils::create_403_forbidden,
};
use crate::modules::auth::extract_header;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::{debug, info, warn};
use regex;
use rsip::{request::Request, response::Response, Method};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::modules::traits::ImsModule;

/// Trusted peer configuration
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TrustedPeer {
    /// Peer domain name
    pub domain: String,
    /// Peer IP addresses (for topology hiding)
    pub ip_addresses: Vec<IpAddr>,
    /// Trust level (0-100)
    pub trust_level: u32,
    /// Allowed SIP methods
    pub allowed_methods: Vec<String>,
    /// Rate limit (requests per second)
    pub rate_limit: u32,
    /// Current request count
    pub current_count: u32,
    /// Last reset timestamp
    pub last_reset: std::time::SystemTime,
}

/// Security policy for inter-operator traffic
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SecurityPolicy {
    /// Policy name
    pub name: String,
    /// Source domain pattern
    pub source_pattern: String,
    /// Destination domain pattern
    pub dest_pattern: String,
    /// Action to take (allow, deny, modify)
    pub action: SecurityAction,
    /// Headers to modify/remove
    pub header_modifications: HashMap<String, String>,
}

/// Security action for traffic
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub enum SecurityAction {
    Allow,
    Deny,
    Modify,
}

/// Topology hiding rule
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TopologyHidingRule {
    /// Rule name
    pub name: String,
    /// Source pattern to hide
    pub source_pattern: String,
    /// Replacement for topology hiding
    pub replacement: String,
    /// Whether to hide port information
    pub hide_port: bool,
}

/// IBCF (Interconnection Border Control Function) Module
///
/// Provides security, topology hiding, and protocol normalization
/// for inter-operator IMS communications at network boundaries.
pub struct IbcfModule {
    /// Trusted peer configurations
    trusted_peers: HashMap<String, TrustedPeer>,
    /// Security policies
    security_policies: Vec<SecurityPolicy>,
    /// Topology hiding rules
    topology_rules: Vec<TopologyHidingRule>,
    /// Local domain for topology hiding
    local_domain: String,
    /// Request rate tracking
    rate_tracking: HashMap<String, u32>,
    /// Rate limit window (seconds)
    rate_window: u64,
}

impl IbcfModule {
    pub fn new(local_domain: String) -> Self {
        let mut trusted_peers = HashMap::new();
        let mut security_policies = Vec::new();
        let mut topology_rules = Vec::new();

        // Initialize with default configurations
        Self::initialize_default_config(&mut trusted_peers, &mut security_policies, &mut topology_rules);

        Self {
            trusted_peers,
            security_policies,
            topology_rules,
            local_domain,
            rate_tracking: HashMap::new(),
            rate_window: 60, // 1 minute window
        }
    }

    /// Initialize default IBCF configuration
    fn initialize_default_config(
        trusted_peers: &mut HashMap<String, TrustedPeer>,
        security_policies: &mut Vec<SecurityPolicy>,
        topology_rules: &mut Vec<TopologyHidingRule>,
    ) {
        // Default trusted peer (local domain)
        trusted_peers.insert(
            "cynan.ims".to_string(),
            TrustedPeer {
                domain: "cynan.ims".to_string(),
                ip_addresses: vec!["127.0.0.1".parse().unwrap()],
                trust_level: 100,
                allowed_methods: vec!["INVITE".to_string(), "ACK".to_string(), "BYE".to_string(), "CANCEL".to_string()],
                rate_limit: 1000,
                current_count: 0,
                last_reset: std::time::SystemTime::now(),
            },
        );

        // Default security policy - allow local traffic
        security_policies.push(SecurityPolicy {
            name: "local-traffic".to_string(),
            source_pattern: "*.cynan.ims".to_string(),
            dest_pattern: "*.cynan.ims".to_string(),
            action: SecurityAction::Allow,
            header_modifications: HashMap::new(),
        });

        // Default topology hiding rule
        topology_rules.push(TopologyHidingRule {
            name: "hide-internal-topology".to_string(),
            source_pattern: r"internal\.cynan\.ims".to_string(),
            replacement: "border.cynan.ims".to_string(),
            hide_port: true,
        });
    }

    /// Check if request is from a trusted peer
    pub fn is_trusted_peer(&self, domain: &str, ip: &IpAddr) -> bool {
        if let Some(peer) = self.trusted_peers.get(domain) {
            peer.ip_addresses.contains(ip) && peer.trust_level > 0
        } else {
            false
        }
    }

    /// Apply security policies to a request
    pub fn apply_security_policies(&self, req: &Request, source_domain: &str, dest_domain: &str) -> Result<SecurityAction> {
        for policy in &self.security_policies {
            if self.matches_pattern(source_domain, &policy.source_pattern) &&
               self.matches_pattern(dest_domain, &policy.dest_pattern) {
                debug!("IBCF applying security policy: {} -> {}", policy.name, dest_domain);
                return Ok(policy.action.clone());
            }
        }

        // Default deny for unmatched traffic
        warn!("IBCF no matching security policy for: {} -> {}", source_domain, dest_domain);
        Ok(SecurityAction::Deny)
    }

    /// Check and enforce rate limits
    pub fn check_rate_limit(&mut self, peer_domain: &str) -> Result<bool> {
        if let Some(peer) = self.trusted_peers.get_mut(peer_domain) {
            // Reset counter if window expired
            let now = std::time::SystemTime::now();
            if let Ok(duration) = now.duration_since(peer.last_reset) {
                if duration.as_secs() >= self.rate_window {
                    peer.current_count = 0;
                    peer.last_reset = now;
                }
            }

            if peer.current_count >= peer.rate_limit {
                warn!("IBCF rate limit exceeded for peer: {}", peer_domain);
                return Ok(false);
            }

            peer.current_count += 1;
            Ok(true)
        } else {
            // Unknown peer - apply strict rate limit
            let key = format!("unknown-{}", peer_domain);
            let count = self.rate_tracking.entry(key).or_insert(0);
            *count += 1;

            if *count > 10 { // Very strict limit for unknown peers
                warn!("IBCF strict rate limit exceeded for unknown peer: {}", peer_domain);
                Ok(false)
            } else {
                Ok(true)
            }
        }
    }

    /// Apply topology hiding to SIP headers
    pub fn apply_topology_hiding(&self, req: &mut Request) -> Result<()> {
        let headers_to_check = vec!["From", "To", "Contact", "Record-Route", "Route"];

        for header_name in headers_to_check {
            if let Some(header_value) = extract_header(&req.to_string(), header_name) {
                let modified_value = self.apply_topology_rules(&header_value);
                if modified_value != header_value {
                    debug!("IBCF topology hiding applied to {} header", header_name);
                    // Note: In a full implementation, this would modify the actual SIP message
                }
            }
        }

        Ok(())
    }

    /// Apply topology hiding rules to a URI string
    fn apply_topology_rules(&self, uri_str: &str) -> String {
        let mut result = uri_str.to_string();

        for rule in &self.topology_rules {
            if self.matches_pattern(&result, &rule.source_pattern) {
                result = result.replace(&rule.source_pattern, &rule.replacement);
                if rule.hide_port {
                    // Remove port information (simplified)
                    if let Some(at_pos) = result.find('@') {
                        if let Some(colon_pos) = result[at_pos..].find(':') {
                            let port_start = at_pos + colon_pos;
                            if let Some(end_pos) = result[port_start..].find(&['>', ';', ' ', '\t'][..]) {
                                result.replace_range(port_start..port_start + end_pos, "");
                            }
                        }
                    }
                }
                debug!("IBCF applied topology rule: {} -> {}", rule.name, result);
                break; // Apply only first matching rule
            }
        }

        result
    }

    /// Extract domain from SIP URI
    pub fn extract_domain_from_uri(&self, uri_str: &str) -> Option<String> {
        if let Some(at_pos) = uri_str.find('@') {
            let domain_part = &uri_str[at_pos + 1..];
            if let Some(end_pos) = domain_part.find(&[':', '>', ';', ' '][..]) {
                Some(domain_part[..end_pos].to_string())
            } else {
                Some(domain_part.to_string())
            }
        } else {
            None
        }
    }

    /// Simple pattern matching (supports wildcards)
    fn matches_pattern(&self, text: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            // Simple wildcard matching
            let regex_pattern: String = pattern.replace("*", ".*");
            let regex_result: Result<regex::Regex, regex::Error> = regex::Regex::new(&format!("^{}$", regex_pattern));
            match regex_result {
                Ok(regex) => regex.is_match(text),
                Err(_) => false,
            }
        } else {
            text.contains(pattern)
        }
    }

    /// Add a trusted peer
    pub fn add_trusted_peer(&mut self, peer: TrustedPeer) -> Result<()> {
        if self.trusted_peers.contains_key(&peer.domain) {
            return Err(anyhow!("Trusted peer already exists: {}", peer.domain));
        }

        info!("IBCF adding trusted peer: {} (trust level: {})", peer.domain, peer.trust_level);
        self.trusted_peers.insert(peer.domain.clone(), peer);
        Ok(())
    }

    /// Remove a trusted peer
    pub fn remove_trusted_peer(&mut self, domain: &str) -> Result<()> {
        if self.trusted_peers.remove(domain).is_some() {
            info!("IBCF removed trusted peer: {}", domain);
            Ok(())
        } else {
            Err(anyhow!("Trusted peer not found: {}", domain))
        }
    }

    /// Add a security policy
    pub fn add_security_policy(&mut self, policy: SecurityPolicy) -> Result<()> {
        // Check for duplicate names
        if self.security_policies.iter().any(|p| p.name == policy.name) {
            return Err(anyhow!("Security policy already exists: {}", policy.name));
        }

        info!("IBCF adding security policy: {}", policy.name);
        self.security_policies.push(policy);
        Ok(())
    }

    /// Add a topology hiding rule
    pub fn add_topology_rule(&mut self, rule: TopologyHidingRule) -> Result<()> {
        // Check for duplicate names
        if self.topology_rules.iter().any(|r| r.name == rule.name) {
            return Err(anyhow!("Topology rule already exists: {}", rule.name));
        }

        info!("IBCF adding topology rule: {}", rule.name);
        self.topology_rules.push(rule);
        Ok(())
    }

    /// Get IBCF statistics
    pub fn get_statistics(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("trusted_peers".to_string(), self.trusted_peers.len());
        stats.insert("security_policies".to_string(), self.security_policies.len());
        stats.insert("topology_rules".to_string(), self.topology_rules.len());

        let total_requests: u32 = self.trusted_peers.values().map(|p| p.current_count).sum();
        stats.insert("total_requests".to_string(), total_requests as usize);

        stats
    }

    /// Clean up rate limit counters (call periodically)
    pub fn cleanup_rate_limits(&mut self) {
        let now = std::time::SystemTime::now();

        // Clean up trusted peer counters
        for peer in self.trusted_peers.values_mut() {
            match now.duration_since(peer.last_reset) {
                Ok(dur) => {
                    if dur.as_secs() >= self.rate_window {
                        peer.current_count = 0;
                        peer.last_reset = now;
                    }
                }
                Err(_) => {
                    // If time calculation fails, reset anyway for safety
                    peer.current_count = 0;
                    peer.last_reset = now;
                }
            }
        }

        // Clean up unknown peer counters
        self.rate_tracking.retain(|_, count| *count > 0);
    }
}

#[async_trait]
impl ImsModule for IbcfModule {
    async fn initialize(&mut self, config: Arc<CynanConfig>) -> Result<()> {
        info!("Initializing IBCF module for domain: {}", self.local_domain);

        // Load IBCF configuration if available
        if let Some(ibcf_config) = &config.ibcf {
            // Apply configuration
            for peer in &ibcf_config.trusted_peers {
                self.add_trusted_peer(peer.clone())?;
            }

            for policy in &ibcf_config.security_policies {
                self.add_security_policy(policy.clone())?;
            }

            for rule in &ibcf_config.topology_rules {
                self.add_topology_rule(rule.clone())?;
            }
        }

        // TODO: Start cleanup task for rate limits
        // Currently disabled due to borrowing issues - needs Arc<Self> pattern
        // let module_arc = Arc::new(self.clone());
        // tokio::spawn(async move {
        //     let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        //     loop {
        //         interval.tick().await;
        //         // module_arc.cleanup_rate_limits();
        //     }
        // });

        Ok(())
    }

    async fn process_request(&mut self, req: Request, ctx: RouteContext) -> Result<RouteAction> {
        debug!("IBCF processing request: {} {}", req.method, req.uri);

        // Extract source and destination domains
        let source_domain = ctx.peer.ip().to_string();

        let dest_domain = self.extract_domain_from_uri(&req.uri.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Check if source is trusted
        let source_ip = ctx.peer.ip();
        if !self.is_trusted_peer(&source_domain, &source_ip) {
            warn!("IBCF rejecting request from untrusted peer: {} ({})", source_domain, source_ip);
            return Ok(RouteAction::Respond(create_403_forbidden(&req, "Untrusted peer")?));
        }

        // Check rate limits
        if !self.check_rate_limit(&source_domain)? {
            warn!("IBCF rate limit exceeded for peer: {}", source_domain);
            return Ok(RouteAction::Respond(create_403_forbidden(&req, "Rate limit exceeded")?));
        }

        // Apply security policies
        match self.apply_security_policies(&req, &source_domain, &dest_domain)? {
            SecurityAction::Allow => {
                debug!("IBCF allowing request: {} -> {}", source_domain, dest_domain);
            }
            SecurityAction::Deny => {
                warn!("IBCF denying request: {} -> {}", source_domain, dest_domain);
                return Ok(RouteAction::Respond(create_403_forbidden(&req, "Security policy violation")?));
            }
            SecurityAction::Modify => {
                // Apply topology hiding and header modifications
                let mut modified_req = req.clone();
                self.apply_topology_hiding(&mut modified_req)?;
                debug!("IBCF modified request: {} -> {}", source_domain, dest_domain);
                // In a full implementation, would return modified request
            }
        }

        // Request passed all checks - allow to continue
        Ok(RouteAction::Continue)
    }

    fn name(&self) -> &str {
        "IBCF"
    }

    fn description(&self) -> &str {
        "Interconnection Border Control Function for inter-operator boundaries"
    }
}

/// IBCF configuration structure
#[derive(Debug, Clone, serde::Deserialize)]
pub struct IbcfConfig {
    /// Trusted peer configurations
    pub trusted_peers: Vec<TrustedPeer>,
    /// Security policies
    pub security_policies: Vec<SecurityPolicy>,
    /// Topology hiding rules
    pub topology_rules: Vec<TopologyHidingRule>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_trusted_peer_check() {
        let ibcf = IbcfModule::new("cynan.ims".to_string());

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(ibcf.is_trusted_peer("cynan.ims", &ip));

        let unknown_ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!ibcf.is_trusted_peer("unknown.com", &unknown_ip));
    }

    #[test]
    fn test_domain_extraction() {
        let ibcf = IbcfModule::new("cynan.ims".to_string());

        assert_eq!(ibcf.extract_domain_from_uri("sip:user@example.com"), Some("example.com".to_string()));
        assert_eq!(ibcf.extract_domain_from_uri("sip:user@example.com:5060"), Some("example.com".to_string()));
        assert_eq!(ibcf.extract_domain_from_uri("invalid-uri"), None);
    }

    #[test]
    fn test_topology_hiding() {
        let mut ibcf = IbcfModule::new("cynan.ims".to_string());

        // Test topology rule application
        let result = ibcf.apply_topology_rules("sip:internal.cynan.ims");
        assert_eq!(result, "sip:border.cynan.ims");
    }

    #[test]
    fn test_pattern_matching() {
        let ibcf = IbcfModule::new("cynan.ims".to_string());

        assert!(ibcf.matches_pattern("test.cynan.ims", "*.cynan.ims"));
        assert!(ibcf.matches_pattern("example.com", "example.com"));
        assert!(!ibcf.matches_pattern("other.com", "example.com"));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let mut ibcf = IbcfModule::new("cynan.ims".to_string());

        // Should allow requests within limit
        for i in 0..5 {
            assert!(ibcf.check_rate_limit("cynan.ims").unwrap());
        }

        // Should work (rate limit is 1000 for trusted peers)
        assert!(ibcf.check_rate_limit("cynan.ims").unwrap());
    }
}