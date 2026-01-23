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

//! SLF (Subscription Locator Function) Implementation
//!
//! The SLF is responsible for determining which HSS contains the subscription
//! data for a given subscriber in multi-HSS environments. It provides a
//! centralized lookup service for HSS discovery and load balancing.

use crate::config::CynanConfig;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::Arc;

use crate::modules::traits::ImsModule;

/// HSS instance information
#[derive(Debug, Clone, serde::Deserialize)]
pub struct HssInstance {
    /// HSS identifier
    pub id: String,
    /// HSS Diameter address
    pub address: String,
    /// HSS capabilities
    pub capabilities: Vec<String>,
    /// Current load (0-100)
    pub load: u32,
    /// Maximum subscribers
    pub max_subscribers: u32,
    /// Current subscriber count
    pub current_subscribers: u32,
}

/// Subscriber to HSS mapping
#[derive(Debug, Clone)]
pub struct SubscriberMapping {
    /// Subscriber identifier (IMPU, IMPU, or MSISDN)
    pub subscriber_id: String,
    /// HSS instance ID
    pub hss_id: String,
    /// Mapping creation timestamp
    pub created_at: std::time::SystemTime,
    /// Mapping expiry timestamp
    pub expires_at: Option<std::time::SystemTime>,
}

/// SLF (Subscription Locator Function) Module
///
/// Provides HSS discovery and load balancing for multi-HSS deployments.
/// Routes subscriber queries to the appropriate HSS instance.
pub struct SlfModule {
    /// HSS instances registry
    hss_instances: HashMap<String, HssInstance>,
    /// Subscriber to HSS mappings
    subscriber_mappings: HashMap<String, SubscriberMapping>,
    /// Default HSS for unmapped subscribers
    default_hss: Option<String>,
    /// Mapping cache expiry (seconds)
    cache_expiry: u64,
}

impl SlfModule {
    pub fn new() -> Self {
        let mut hss_instances = HashMap::new();

        // Initialize with default HSS instances
        Self::initialize_default_hss(&mut hss_instances);

        Self {
            hss_instances,
            subscriber_mappings: HashMap::new(),
            default_hss: Some("hss-primary.cynan.ims".to_string()),
            cache_expiry: 3600, // 1 hour
        }
    }

    /// Initialize default HSS instances
    fn initialize_default_hss(hss_instances: &mut HashMap<String, HssInstance>) {
        hss_instances.insert(
            "hss-primary.cynan.ims".to_string(),
            HssInstance {
                id: "hss-primary".to_string(),
                address: "hss-primary.cynan.ims:3868".to_string(),
                capabilities: vec!["cx".to_string(), "sh".to_string(), "zh".to_string()],
                load: 0,
                max_subscribers: 100000,
                current_subscribers: 0,
            },
        );

        hss_instances.insert(
            "hss-secondary.cynan.ims".to_string(),
            HssInstance {
                id: "hss-secondary".to_string(),
                address: "hss-secondary.cynan.ims:3868".to_string(),
                capabilities: vec!["cx".to_string(), "sh".to_string()],
                load: 0,
                max_subscribers: 50000,
                current_subscribers: 0,
            },
        );
    }

    /// Locate HSS for a subscriber
    pub fn locate_hss(&self, subscriber_id: &str) -> Result<HssInstance> {
        debug!("SLF locating HSS for subscriber: {}", subscriber_id);

        // Check cached mapping first
        if let Some(mapping) = self.subscriber_mappings.get(subscriber_id) {
            // Check if mapping is still valid
            if let Some(expires_at) = mapping.expires_at {
                if std::time::SystemTime::now() > expires_at {
                    warn!("Expired SLF mapping for subscriber: {}", subscriber_id);
                    // Remove expired mapping
                    self.subscriber_mappings.remove(subscriber_id);
                } else {
                    // Use cached mapping
                    if let Some(hss) = self.hss_instances.get(&mapping.hss_id) {
                        debug!("SLF cache hit: {} -> {}", subscriber_id, hss.id);
                        return Ok(hss.clone());
                    }
                }
            }
        }

        // Determine HSS based on subscriber ID
        let hss_id = self.determine_hss_for_subscriber(subscriber_id)?;

        if let Some(hss) = self.hss_instances.get(&hss_id) {
            // Cache the mapping
            let mapping = SubscriberMapping {
                subscriber_id: subscriber_id.to_string(),
                hss_id: hss_id.clone(),
                created_at: std::time::SystemTime::now(),
                expires_at: Some(std::time::SystemTime::now() + std::time::Duration::from_secs(self.cache_expiry)),
            };
            self.subscriber_mappings.insert(subscriber_id.to_string(), mapping);

            debug!("SLF resolved: {} -> {}", subscriber_id, hss.id);
            Ok(hss.clone())
        } else {
            Err(anyhow!("HSS instance not found: {}", hss_id))
        }
    }

    /// Determine which HSS should serve a subscriber
    fn determine_hss_for_subscriber(&self, subscriber_id: &str) -> Result<String> {
        // Simple load balancing strategy based on subscriber ID hash
        // In production, this would use more sophisticated routing logic

        let available_hss: Vec<&HssInstance> = self.hss_instances.values()
            .filter(|hss| hss.current_subscribers < hss.max_subscribers)
            .collect();

        if available_hss.is_empty() {
            return Err(anyhow!("No available HSS instances"));
        }

        // Use subscriber ID hash for consistent routing
        let hash = self.simple_hash(subscriber_id);
        let hss_index = hash % available_hss.len();

        Ok(available_hss[hss_index].id.clone())
    }

    /// Simple hash function for load balancing
    fn simple_hash(&self, input: &str) -> usize {
        let mut hash: usize = 0;
        for (i, byte) in input.bytes().enumerate() {
            hash ^= (byte as usize) << ((i % 8) * 8);
        }
        hash
    }

    /// Register a new HSS instance
    pub fn register_hss(&mut self, hss: HssInstance) -> Result<()> {
        if self.hss_instances.contains_key(&hss.id) {
            return Err(anyhow!("HSS instance already registered: {}", hss.id));
        }

        info!("SLF registering HSS instance: {} at {}", hss.id, hss.address);
        self.hss_instances.insert(hss.id.clone(), hss);
        Ok(())
    }

    /// Unregister an HSS instance
    pub fn unregister_hss(&mut self, hss_id: &str) -> Result<()> {
        if self.hss_instances.remove(hss_id).is_some() {
            info!("SLF unregistered HSS instance: {}", hss_id);

            // Remove all mappings for this HSS
            self.subscriber_mappings.retain(|_, mapping| mapping.hss_id != hss_id);

            Ok(())
        } else {
            Err(anyhow!("HSS instance not found: {}", hss_id))
        }
    }

    /// Update HSS load information
    pub fn update_hss_load(&mut self, hss_id: &str, current_subscribers: u32) -> Result<()> {
        if let Some(hss) = self.hss_instances.get_mut(hss_id) {
            hss.current_subscribers = current_subscribers;
            hss.load = if hss.max_subscribers > 0 {
                (current_subscribers * 100) / hss.max_subscribers
            } else {
                0
            };
            debug!("SLF updated HSS load: {} - {}% ({}/{})",
                  hss_id, hss.load, hss.current_subscribers, hss.max_subscribers);
            Ok(())
        } else {
            Err(anyhow!("HSS instance not found: {}", hss_id))
        }
    }

    /// Get all registered HSS instances
    pub fn get_hss_instances(&self) -> Vec<HssInstance> {
        self.hss_instances.values().cloned().collect()
    }

    /// Get subscriber mapping statistics
    pub fn get_mapping_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("total_mappings".to_string(), self.subscriber_mappings.len());

        let mut hss_counts = HashMap::new();
        for mapping in self.subscriber_mappings.values() {
            *hss_counts.entry(mapping.hss_id.clone()).or_insert(0) += 1;
        }

        for (hss_id, count) in hss_counts {
            stats.insert(format!("hss_{}", hss_id), count);
        }

        stats
    }

    /// Clear expired mappings
    pub fn cleanup_expired_mappings(&mut self) {
        let now = std::time::SystemTime::now();
        let mut expired = Vec::new();

        for (subscriber_id, mapping) in &self.subscriber_mappings {
            if let Some(expires_at) = mapping.expires_at {
                if now > expires_at {
                    expired.push(subscriber_id.clone());
                }
            }
        }

        for subscriber_id in expired {
            self.subscriber_mappings.remove(&subscriber_id);
            debug!("SLF cleaned up expired mapping: {}", subscriber_id);
        }
    }
}

#[async_trait]
impl ImsModule for SlfModule {
    async fn initialize(&mut self, config: Arc<CynanConfig>) -> Result<()> {
        info!("Initializing SLF module");

        // Load HSS configuration if available
        if let Some(slf_config) = &config.slf {
            // Override default HSS instances with configured ones
            for hss in &slf_config.hss_instances {
                self.register_hss(hss.clone())?;
            }

            if let Some(default) = &slf_config.default_hss {
                self.default_hss = Some(default.clone());
            }

            if let Some(expiry) = slf_config.cache_expiry {
                self.cache_expiry = expiry;
            }
        }

        // TODO: Start cleanup task for expired mappings
        // Currently disabled due to borrowing issues - needs Arc<Self> pattern
        // let module_arc = Arc::new(self.clone());
        // tokio::spawn(async move {
        //     let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        //     loop {
        //         interval.tick().await;
        //         // module_arc.cleanup_expired_mappings();
        //     }
        // });

        Ok(())
    }

    fn name(&self) -> &str {
        "SLF"
    }

    fn description(&self) -> &str {
        "Subscription Locator Function for multi-HSS environments"
    }
}

/// SLF configuration structure
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SlfConfig {
    /// Default HSS instance ID
    pub default_hss: Option<String>,
    /// HSS instances configuration
    pub hss_instances: Vec<HssInstance>,
    /// Mapping cache expiry in seconds
    pub cache_expiry: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hss_registration() {
        let mut slf = SlfModule::new();

        let hss = HssInstance {
            id: "test-hss".to_string(),
            address: "test-hss.example.com:3868".to_string(),
            capabilities: vec!["cx".to_string()],
            load: 0,
            max_subscribers: 1000,
            current_subscribers: 0,
        };

        assert!(slf.register_hss(hss).is_ok());
        assert!(slf.hss_instances.contains_key("test-hss"));
    }

    #[test]
    fn test_hss_location() {
        let slf = SlfModule::new();

        // Test with default HSS instances
        let result = slf.locate_hss("sip:user@example.com");
        assert!(result.is_ok());

        let hss = result.unwrap();
        assert!(hss.capabilities.contains(&"cx".to_string()));
    }

    #[test]
    fn test_load_update() {
        let mut slf = SlfModule::new();

        let update_result = slf.update_hss_load("hss-primary", 500);
        assert!(update_result.is_ok());

        if let Some(hss) = slf.hss_instances.get("hss-primary") {
            assert_eq!(hss.current_subscribers, 500);
        }
    }

    #[test]
    fn test_simple_hash() {
        let slf = SlfModule::new();
        let hash1 = slf.simple_hash("test1");
        let hash2 = slf.simple_hash("test2");
        let hash1_again = slf.simple_hash("test1");

        // Same input should produce same hash
        assert_eq!(hash1, hash1_again);
        // Different inputs should produce different hashes (not guaranteed but likely)
        assert_ne!(hash1, hash2);
    }
}