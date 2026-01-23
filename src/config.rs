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

//! Configuration Management
//!
//! This module handles loading and parsing of YAML configuration files
//! for the Cynan IMS Core application.

use serde::Deserialize;
use std::{fs, path::Path};

/// Main application configuration structure
#[derive(Debug, Deserialize)]
pub struct CynanConfig {
    /// Core SIP engine configuration
    pub core: CoreConfig,
    /// Database connection configuration
    pub database: DatabaseConfig,
    /// Transport layer configuration
    pub transport: TransportConfig,
    /// Armoricore integration configuration
    pub armoricore: ArmoricoreConfig,
    /// BGCF configuration (optional)
    pub bgcf: Option<BgcfConfig>,
    /// MGCF configuration (optional)
    pub mgcf: Option<MgcfConfig>,
    /// SLF configuration (optional)
    pub slf: Option<SlfConfig>,
    /// IBCF configuration (optional)
    pub ibcf: Option<IbcfConfig>,
    /// Application Server integration configuration (optional)
    pub as_integration: Option<AsIntegrationConfig>,
    /// Security policy configuration
    #[serde(default)]
    pub security: SecurityConfig,
}

/// Core SIP engine configuration
#[derive(Debug, Deserialize)]
pub struct CoreConfig {
    /// Default SIP port (typically 5060)
    pub sip_port: u16,
    /// Whether TLS is allowed/enabled
    pub allow_tls: bool,
    /// Optional metrics port for Prometheus exporter
    pub metrics_port: Option<u16>,
}

/// Database connection configuration
#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// Database hostname
    pub host: String,
    /// Database port (typically 5432 for PostgreSQL)
    pub port: u16,
    /// Database username
    pub user: String,
    /// Database password
    pub password: String,
    /// Database name
    pub name: String,
}

/// Transport layer configuration
#[derive(Debug, Deserialize)]
pub struct TransportConfig {
    /// UDP bind address (e.g., "0.0.0.0:5060")
    pub udp_addr: String,
    /// TCP bind address (e.g., "0.0.0.0:5060")
    pub tcp_addr: String,
    /// Optional TLS configuration
    pub tls: Option<TlsConfig>,
}

/// TLS certificate configuration
#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Path to TLS certificate file
    pub cert_path: String,
    /// Path to TLS private key file
    pub key_path: String,
}

/// Armoricore integration configuration
#[derive(Debug, Deserialize)]
pub struct ArmoricoreConfig {
    /// gRPC target URI for Armoricore service
    pub grpc_target: String,
    /// NATS server URL for messaging
    pub nats_url: String,
}

/// BGCF (Breakout Gateway Control Function) configuration
#[derive(Debug, Deserialize)]
pub struct BgcfConfig {
    /// Default MGCF URI for fallback routing
    pub default_mgcf: Option<String>,
    /// Routing entries for different destination patterns
    pub routing_entries: Vec<crate::bgcf::RoutingEntry>,
    /// MGCF instances and their configurations
    pub mgcf_instances: Vec<crate::bgcf::MgcfInstance>,
}

/// MGCF (Media Gateway Control Function) configuration
#[derive(Debug, Deserialize)]
pub struct MgcfConfig {
    /// Local domain for SIP signaling
    pub local_domain: String,
    /// PSTN trunk configurations
    pub pstn_trunks: Vec<crate::mgcf::PstnTrunk>,
    /// MGW endpoint configuration
    pub mgw_endpoint: Option<String>,
}

/// SLF (Subscription Locator Function) configuration
#[derive(Debug, Deserialize)]
pub struct SlfConfig {
    /// Default HSS instance ID
    pub default_hss: Option<String>,
    /// HSS instances configuration
    pub hss_instances: Vec<crate::slf::HssInstance>,
    /// Mapping cache expiry in seconds
    pub cache_expiry: Option<u64>,
}

/// IBCF (Interconnection Border Control Function) configuration
#[derive(Debug, Deserialize)]
pub struct IbcfConfig {
    /// Trusted peer configurations
    pub trusted_peers: Vec<crate::ibcf::TrustedPeer>,
    /// Security policies
    pub security_policies: Vec<crate::ibcf::SecurityPolicy>,
    /// Topology hiding rules
    pub topology_rules: Vec<crate::ibcf::TopologyHidingRule>,
}

/// Application Server integration configuration
#[derive(Debug, Deserialize)]
pub struct AsIntegrationConfig {
    /// Registered Application Servers
    pub application_servers: Vec<crate::as_integration::ApplicationServer>,
    /// Service triggers for automatic AS invocation
    pub service_triggers: Vec<crate::as_integration::ServiceTrigger>,
    /// Default AS for fallback
    pub default_as: Option<String>,
}

/// Security policy configuration
#[derive(Debug, Deserialize)]
pub struct SecurityConfig {
    /// Whether TLS is required for all connections
    pub require_tls: bool,
    /// IPSec policy string (e.g., "strict", "permissive")
    pub ipsec_policy: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            require_tls: true,
            ipsec_policy: Some("strict".into()),
        }
    }
}

impl CynanConfig {
    /// Load configuration from a YAML file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the YAML configuration file
    ///
    /// # Returns
    ///
    /// Returns the parsed configuration, or an error if loading/parsing fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use cynan::config::CynanConfig;
    /// let config = CynanConfig::load("config/cynan.yaml")?;
    /// ```
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(path)?;
        let mut config: CynanConfig = serde_yaml::from_str(&contents)?;
        if config.core.metrics_port.is_none() {
            config.core.metrics_port = Some(9090);
        }
        if config.security.ipsec_policy.is_none() {
            config.security.ipsec_policy = Some("strict".into());
        }
        Ok(config)
    }
}
