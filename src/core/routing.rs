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

//! Routing Framework
//!
//! This module defines the routing trait and context for SIP request handling.
//! Route handlers process SIP requests and return actions (continue, respond, reject).

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use rsip::{Request, Response};

use crate::{
    config::CynanConfig,
    state::SharedState,
};

/// Context passed to route handlers during request processing
///
/// Contains the peer address, application configuration, and shared state
/// that handlers can use to make routing decisions.
#[derive(Clone)]
pub struct RouteContext {
    /// Peer socket address of the request sender
    pub peer: SocketAddr,
    /// Application configuration
    pub config: Arc<CynanConfig>,
    /// Shared application state (locations, database pool)
    pub state: SharedState,
}

/// Action to take after processing a SIP request
#[derive(Debug)]
pub enum RouteAction {
    /// Continue to next handler in the chain
    Continue,
    /// Send a SIP response and stop processing
    Respond(Response),
    /// Reject the request and stop processing
    RejectAny,
}

/// Trait for SIP request route handlers
///
/// Implementations of this trait process SIP requests and return routing actions.
/// Handlers are called in sequence until one returns `Respond` or `RejectAny`.
#[async_trait]
pub trait RouteHandler: Send + Sync {
    /// Process a SIP request
    ///
    /// # Arguments
    ///
    /// * `req` - The SIP request to process
    /// * `ctx` - Routing context with peer info, config, and state
    ///
    /// # Returns
    ///
    /// Returns a `RouteAction` indicating how to proceed:
    /// - `Continue`: Pass to next handler
    /// - `Respond`: Send response and stop
    /// - `RejectAny`: Reject request and stop
    async fn handle_request(
        &self,
        req: Request,
        ctx: RouteContext,
    ) -> anyhow::Result<RouteAction>;
}
