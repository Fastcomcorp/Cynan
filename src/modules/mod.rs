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

//! Module Registry
//!
//! Manages registration and initialization of IMS modules.

pub mod auth;
pub mod ims;
pub mod traits;

use std::sync::Arc;

use crate::{
    config::CynanConfig,
    core::routing::RouteHandler,
    state::SharedState,
};

/// Internal entry for registered modules
struct ModuleEntry {
    /// The IMS module instance
    module: Arc<dyn traits::ImsModule>,
    /// Route handler interface (same instance as module)
    handler: Arc<dyn RouteHandler>,
}

/// Registry for IMS modules
///
/// Manages the lifecycle of IMS modules, including registration,
/// initialization, and providing route handlers to the SIP core.
pub struct ModuleRegistry {
    entries: Vec<ModuleEntry>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        ModuleRegistry { entries: Vec::new() }
    }

    pub fn register_module(&mut self, module: Arc<dyn traits::ImsModule>) {
        let handler: Arc<dyn RouteHandler> = module.clone();
        self.entries.push(ModuleEntry { module, handler });
    }

    pub fn route_handlers(&self) -> Vec<Arc<dyn RouteHandler>> {
        self.entries.iter().map(|entry| Arc::clone(&entry.handler)).collect()
    }

    pub async fn initialize_modules(&self, config: Arc<CynanConfig>, state: SharedState) -> anyhow::Result<()> {
        for entry in &self.entries {
            entry.module.init(Arc::clone(&config), state.clone()).await?;
        }
        Ok(())
    }
}
