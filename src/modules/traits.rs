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

//! IMS Module Trait
//!
//! Defines the interface for IMS modules that participate in SIP routing.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{config::CynanConfig, core::routing::RouteHandler, state::SharedState};

/// Trait for IMS modules that participate in routing decisions
///
/// IMS modules implement both `RouteHandler` (for request processing) and
/// `ImsModule` (for initialization and lifecycle management).
#[async_trait]
pub trait ImsModule: RouteHandler {
    /// Returns the module name for logging and identification
    fn name(&self) -> &'static str;
    
    /// Initialize the module with configuration and shared state
    ///
    /// Called once during application startup to allow modules to set up
    /// connections, load configuration, or perform other initialization tasks.
    async fn init(&self, config: Arc<CynanConfig>, state: SharedState) -> anyhow::Result<()>;
}
