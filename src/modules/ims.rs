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

//! IMS (IP Multimedia Subsystem) Modules
//!
//! This module implements the three core IMS Call Session Control Functions (CSCFs):
//! - **P-CSCF (Proxy-CSCF)**: RegistrarModule - Handles user registration and authentication
//! - **I-CSCF (Interrogating-CSCF)**: IcsCfModule - Queries HSS for user location
//! - **S-CSCF (Serving-CSCF)**: ScsCfModule - Manages session state and service logic

use std::{collections::HashMap, convert::TryFrom, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use log::{debug, info, warn};
use rsip::{headers::Method, request::Request, response::Response};
use uuid::Uuid;

use crate::{
    config::CynanConfig,
    core::{
        routing::{RouteAction, RouteContext},
        sip_utils::{create_200_ok, create_401_unauthorized},
    },
    integration::DiameterInterface,
    modules::{
        auth::{
            extract_header, extract_uri_from_request, extract_user_from_request, generate_nonce,
            parse_authorization, verify_digest,
        },
        traits::ImsModule,
    },
    state::{Location, SharedState},
};

/// Session state information for IMS calls
#[derive(Debug, Clone)]
pub struct SessionState {
    pub call_id: String,
    pub from_uri: String,
    pub to_uri: String,
    pub state: SessionStatus,
    pub created_at: SystemTime,
}

/// Session status enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum SessionStatus {
    Initiated,
    Established,
    Terminated,
}

/// P-CSCF (Proxy-CSCF) Registrar Module
///
/// Responsible for handling SIP REGISTER requests with digest authentication (RFC 3261).
/// Manages user location bindings and contact URI registration.
///
/// # Authentication Flow
///
/// 1. Client sends REGISTER without Authorization header
/// 2. Server responds with 401 Unauthorized + WWW-Authenticate challenge
/// 3. Client retries REGISTER with Authorization header containing digest response
/// 4. Server verifies digest and responds with 200 OK
pub struct RegistrarModule {
    /// Authentication realm for digest challenges
    realm: String,
    /// Map of username -> nonce for pending authentication challenges
    nonces: Arc<dashmap::DashMap<String, String>>,
}

impl RegistrarModule {
    pub fn new(realm: String) -> Self {
        RegistrarModule {
            realm,
            nonces: Arc::new(dashmap::DashMap::new()),
        }
    }
}

impl Default for RegistrarModule {
    fn default() -> Self {
        Self::new("cynan.ims".to_string())
    }
}

/// Handles inbound requests that require Diameter interactions to HSS/HSS+PCRF.
pub struct IcsCfModule {
    diameter: Option<Arc<DiameterInterface>>,
}

/// Controls session handling for authenticated subscribers (service logic).
///
/// Note: Session state is managed through the shared state system rather than
/// per-module state to ensure consistency across all IMS components.
pub struct ScsCfModule;

impl Default for ScsCfModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ImsModule for RegistrarModule {
    fn name(&self) -> &'static str {
        "registrar"
    }

    async fn init(&self, _config: Arc<CynanConfig>, _state: SharedState) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl ImsModule for IcsCfModule {
    fn name(&self) -> &'static str {
        "icscf"
    }

    async fn init(&self, _config: Arc<CynanConfig>, _state: SharedState) -> anyhow::Result<()> {
        Ok(())
    }
}

impl ScsCfModule {
    pub fn new() -> Self {
        ScsCfModule
    }
}

impl Default for ScsCfModule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ImsModule for ScsCfModule {
    fn name(&self) -> &'static str {
        "scscf"
    }

    async fn init(&self, _config: Arc<CynanConfig>, _state: SharedState) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl crate::core::routing::RouteHandler for RegistrarModule {
    async fn handle_request(
        &self,
        req: Request,
        ctx: RouteContext,
    ) -> anyhow::Result<RouteAction> {
        if req.method != Method::REGISTER {
            return Ok(RouteAction::Continue);
        }

        info!("Processing REGISTER request from {}", ctx.peer);

        // Convert request to string for parsing
        let req_str = format!("{}", req);

        // Extract user from request
        let username = match extract_user_from_request(&req_str) {
            Ok(u) => u,
            Err(e) => {
                warn!("Failed to extract user from REGISTER: {}", e);
                return Ok(RouteAction::Respond(Response::try_from(
                    b"SIP/2.0 400 Bad Request\r\n\r\n".as_ref(),
                )?));
            }
        };

        // Check for Authorization header
        let auth_header = extract_header(&req_str, "Authorization")
            .or_else(|| extract_header(&req_str, "Proxy-Authorization"));
        
        if auth_header.is_none() {
            // No authorization - send 401 challenge
            let nonce = generate_nonce();
            self.nonces.insert(username.clone(), nonce.clone());
            
            debug!("Sending 401 challenge to user {}", username);
            let response = create_401_unauthorized(&self.realm, &nonce)?;
            return Ok(RouteAction::Respond(response));
        }

        // Verify authentication
        let auth_value = auth_header.unwrap();
        let auth_params = parse_authorization(&auth_value)?;
        
        // Get stored nonce for this user
        let stored_nonce = self.nonces
            .get(&username)
            .map(|n| n.value().clone())
            .ok_or_else(|| anyhow::anyhow!("No nonce found for user"))?;

        // Extract URI from request
        let uri = extract_uri_from_request(&req_str)
            .unwrap_or_else(|_| format!("sip:{}@{}", username, ctx.peer));
        
        // TODO: Get password from database/HSS
        // For now, use a placeholder - in production this should query HSS
        let password = "default_password".to_string();
        
        // Verify digest
        let is_valid = verify_digest(
            &auth_params,
            "REGISTER",
            &uri,
            &password,
            &stored_nonce,
        )?;

        if !is_valid {
            warn!("Authentication failed for user {}", username);
            // Generate new nonce for retry
            let nonce = generate_nonce();
            self.nonces.insert(username.clone(), nonce.clone());
            let response = create_401_unauthorized(&self.realm, &nonce)?;
            return Ok(RouteAction::Respond(response));
        }

        // Authentication successful - process registration
        info!("User {} authenticated successfully", username);
        
        // Extract Contact header
        let contact_uri = extract_header(&req_str, "Contact")
            .and_then(|c| c.split(',').next().map(|s| s.trim().trim_matches('<').trim_matches('>').to_string()))
            .unwrap_or_else(|| format!("sip:{}@{}", username, ctx.peer));

        // Store location binding
        let user_id = Uuid::new_v4(); // In production, get from HSS
        ctx.state.insert_location(
            user_id,
            Location {
                contact_uri: contact_uri.clone(),
                last_seen: SystemTime::now(),
            },
        );

        // Remove nonce after successful authentication
        self.nonces.remove(&username);

        // Create 200 OK response with Contact header
        let response = Response::try_from(
            format!(
                "SIP/2.0 200 OK\r\nContact: <{}>\r\nExpires: 3600\r\n\r\n",
                contact_uri
            )
            .as_bytes(),
        )?;

        Ok(RouteAction::Respond(response))
    }
}

#[async_trait]
impl crate::core::routing::RouteHandler for IcsCfModule {
    async fn handle_request(
        &self,
        req: Request,
        ctx: RouteContext,
    ) -> anyhow::Result<RouteAction> {
        // I-CSCF handles initial requests (INVITE, REGISTER) by querying HSS
        // For REGISTER, this happens before P-CSCF processing
        // For INVITE, this routes to appropriate S-CSCF
        
        if req.method == Method::INVITE || req.method == Method::REGISTER {
            info!("I-CSCF processing {} request", req.method());
            
            // Extract user identity
            let req_str = format!("{}", req);
            let username = extract_user_from_request(&req_str)
                .unwrap_or_else(|_| "unknown".to_string());
            
            // Query HSS via Diameter Cx interface
            if let Some(diameter) = &self.diameter {
                match diameter.cx_query(&username, &username).await {
                    Ok(profile) => {
                        info!("HSS query successful for user: {}", username);
                        debug!("S-CSCF capabilities: {:?}", profile.scscf_capabilities);
                        
                        // Select appropriate S-CSCF
                        if let Some(scscf_name) = profile.scscf_name {
                            info!("Selected S-CSCF: {}", scscf_name);
                            // In a full implementation, we would route to the S-CSCF here
                            // For now, we continue to let other modules handle it
                        }
                    }
                    Err(e) => {
                        warn!("HSS query failed for user {}: {}", username, e);
                        // Continue processing even if HSS query fails
                    }
                }
            } else {
                debug!("No Diameter interface available, skipping HSS query");
            }
        }
        
        Ok(RouteAction::Continue)
    }
}

#[async_trait]
impl crate::core::routing::RouteHandler for ScsCfModule {
    async fn handle_request(
        &self,
        req: Request,
        ctx: RouteContext,
    ) -> anyhow::Result<RouteAction> {
        let req_str = format!("{}", req);
        
        // Extract Call-ID for session tracking
        let call_id = extract_header(&req_str, "Call-ID")
            .unwrap_or_else(|| format!("call-{}", uuid::Uuid::new_v4()));
        
        match req.method {
            Method::INVITE => {
                info!("S-CSCF handling INVITE, Call-ID: {}", call_id);

                // Extract user information for routing decisions
                let username = extract_user_from_request(&req_str).unwrap_or_default();

                // Check if user is registered (simplified - in production this would query HSS)
                // For now, assume users are registered and continue routing
                info!("Processing INVITE for user: {}, Call-ID: {}", username, call_id);

                // In a full S-CSCF implementation, this would:
                // 1. Query HSS for user profile and service settings
                // 2. Apply service logic and routing policies
                // 3. Route to appropriate destination (PSTN breakout, other IMS domains, etc.)
                // 4. Set up charging and QoS parameters

                // For this MVP, we continue to let other modules handle the routing
            }
            Method::ACK => {
                info!("ACK received for session, Call-ID: {}", call_id);
                // Session state management is handled by higher-level components
                // This module focuses on routing decisions
            }
            Method::BYE => {
                info!("BYE received for session termination, Call-ID: {}", call_id);
                // Return 200 OK for BYE - session cleanup handled elsewhere
                return Ok(RouteAction::Respond(Response::try_from(
                    b"SIP/2.0 200 OK\r\n\r\n".as_ref(),
                )?));
            }
            Method::CANCEL => {
                info!("CANCEL received for session, Call-ID: {}", call_id);
                // Return 200 OK for CANCEL
                return Ok(RouteAction::Respond(Response::try_from(
                    b"SIP/2.0 200 OK\r\n\r\n".as_ref(),
                )?));
            }
            _ => {
                // Other methods pass through
            }
        }
        
        Ok(RouteAction::Continue)
    }
}
