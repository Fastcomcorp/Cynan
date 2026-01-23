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

//! SIP Core Engine
//!
//! This module implements the main SIP processing engine that coordinates
//! transport listeners, routing handlers, and integration components.
//!
//! The `SipCore` is responsible for:
//! - Managing multiple transport listeners (UDP/TCP/TLS)
//! - Parsing incoming SIP messages
//! - Routing messages through registered handlers
//! - Sending responses back to clients
//! - Graceful shutdown handling

use std::{convert::TryFrom, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use futures::future::try_join_all;
use log::{error, info, warn};
use rsip::{request::Request, response::Response, SipMessage};
use tokio::signal;

use crate::{
    bgcf::BgcfModule,
    config::CynanConfig,
    core::{
        routing::{RouteAction, RouteContext, RouteHandler},
        sip_utils::serialize_response,
        transport::{TransportListener, TransportMessage},
    },
    ibcf::IbcfModule,
    mgcf::MgcfModule,
    modules::{
        ims::{IcsCfModule, RegistrarModule, ScsCfModule},
        ModuleRegistry,
    },
    integration::{ArmoricoreBridge, DiameterInterface, SecurityEnforcer},
    rtp_router::{RtpPortManager, RtpRouter},
    slf::SlfModule,
    state::SharedState,
};

/// Main SIP core engine that orchestrates message processing
///
/// The `SipCore` manages the lifecycle of SIP message processing:
/// - Initializes transport listeners for UDP/TCP/TLS
/// - Registers IMS modules (P-CSCF, I-CSCF, S-CSCF)
/// - Processes incoming SIP messages through the routing pipeline
/// - Handles graceful shutdown on SIGINT/SIGTERM
pub struct SipCore {
    /// Application configuration
    config: Arc<CynanConfig>,
    /// Active transport listeners
    listeners: Vec<TransportListener>,
    /// Registered route handlers (IMS modules)
    handlers: Vec<Arc<dyn RouteHandler>>,
    /// Shared application state (user locations, database pool)
    state: SharedState,
    /// Integration components (Armoricore, Diameter, Security)
    integration: IntegrationPlane,
}

/// Integration plane containing external service connections
struct IntegrationPlane {
    /// Armoricore bridge for secure media handling
    armoricore: ArmoricoreBridge,
    /// Diameter interface for HSS queries
    diameter: DiameterInterface,
    /// Security enforcement (TLS/IPSec)
    security: SecurityEnforcer,
    /// RTP packet router for media forwarding
    rtp_router: RtpRouter,
    /// RTP port manager for dynamic port allocation
    rtp_port_manager: RtpPortManager,
    /// Application Server integration manager
    as_integration: crate::as_integration::AsIntegrationManager,
}

impl SipCore {
    pub async fn new(config: CynanConfig) -> Result<Self> {
        let config = Arc::new(config);
        let mut listeners = Vec::new();

        // Bind UDP listener
        let udp_addr: SocketAddr = config.transport.udp_addr.parse()?;
        listeners.push(TransportListener::bind_udp(&udp_addr).await?);

        // Bind TCP listener if configured
        let tcp_addr: SocketAddr = config.transport.tcp_addr.parse()?;
        listeners.push(TransportListener::bind_tcp(&tcp_addr).await?);

        // Bind TLS listener if configured
        if let Some(_tls_config) = &config.transport.tls {
            let security =
                SecurityEnforcer::from_config_async(&config.transport, &config.security).await?;
            if let Some(tls_acceptor) = security.tls_acceptor {
                let tls_addr: SocketAddr = format!("0.0.0.0:{}", config.core.sip_port + 1)
                    .parse()
                    .unwrap_or_else(|_| tcp_addr);
                listeners.push(
                    TransportListener::bind_tls(&tls_addr, Arc::new(tls_acceptor)).await?,
                );
            }
        }

        let state = SharedState::build(&config.database).await?;
        let mut registry = ModuleRegistry::new();
        
        // Create Diameter interface for I-CSCF
        let diameter_interface = Arc::new(DiameterInterface::new(&config.transport).await?);
        
        registry.register_module(Arc::new(RegistrarModule::default()));
        registry.register_module(Arc::new(IcsCfModule::with_diameter(diameter_interface)));
        registry.register_module(Arc::new(ScsCfModule::default()));
        registry.register_module(Arc::new(BgcfModule::new()));
        registry.register_module(Arc::new(MgcfModule::new("cynan.ims".to_string())));
        registry.register_module(Arc::new(SlfModule::new()));
        registry.register_module(Arc::new(IbcfModule::new("cynan.ims".to_string())));
        registry
            .initialize_modules(Arc::clone(&config), state.clone())
            .await?;
        let handlers = registry.route_handlers();

        let security =
            SecurityEnforcer::from_config_async(&config.transport, &config.security).await?;
        let diameter = DiameterInterface::new(&config.transport).await?;
        let armoricore = ArmoricoreBridge::new(&config.armoricore, None).await?;

        // Initialize RTP components
        let armoricore_bridge = Arc::new(armoricore);
        let rtp_router = RtpRouter::new(Arc::clone(&armoricore_bridge));
        let rtp_port_manager = RtpPortManager::new(10000, 20000); // RTP port range

        // Start RTP listeners
        rtp_router.start_rtp_listener(10000, 10100).await?; // Start with 100 ports

        // Initialize AS integration manager
        let mut as_integration = crate::as_integration::AsIntegrationManager::new();

        // Load AS configuration if available
        if let Some(as_config) = &config.as_integration {
            for as_server in &as_config.application_servers {
                as_integration.register_as(as_server.clone())?;
            }
            for trigger in &as_config.service_triggers {
                as_integration.add_service_trigger(trigger.clone())?;
            }
            as_integration.default_as = as_config.default_as.clone();
        }

        let integration = IntegrationPlane {
            armoricore: (*armoricore_bridge).clone(),
            diameter,
            security,
            rtp_router,
            rtp_port_manager,
            as_integration,
        };

        Ok(SipCore {
            config,
            listeners,
            handlers,
            state,
            integration,
        })
    }

    /// Runs the SIP core engine, processing messages until shutdown
    ///
    /// This method spawns a task for each transport listener and processes
    /// incoming SIP messages through the registered route handlers.
    /// The method blocks until a shutdown signal (SIGINT/SIGTERM) is received.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on graceful shutdown, or an error if processing fails
    ///
    /// # Errors
    ///
    /// Returns an error if message processing fails catastrophically
    pub async fn run(self) -> Result<()> {
        let mut tasks = Vec::new();
        let listeners = self.listeners;
        let handlers = self.handlers;

        for listener in listeners {
            let handler_set = handlers.clone();
            let config = Arc::clone(&self.config);
            let state = self.state.clone();
            let listener_clone = listener.clone();

            tasks.push(tokio::spawn(async move {
                info!("Starting listener for {:?}", listener.protocol);

                loop {
                    tokio::select! {
                        msg = listener.recv() => {
                            if let Some(msg) = msg {
                                let TransportMessage { data, peer, response_tx } = msg;
                                
                                match SipMessage::try_from(data.as_slice()) {
                                    Ok(SipMessage::Request(req)) => {
                                        info!("Received {} request from {}", req.method(), peer);
                                        let mut responded = false;
                                        for handler in &handler_set {
                                            let ctx = RouteContext {
                                                peer,
                                                config: Arc::clone(&config),
                                                state: state.clone(),
                                            };
                                            match handler.handle_request(req.clone(), ctx).await {
                                                Ok(RouteAction::Respond(resp)) => {
                                                    match serialize_response(&resp) {
                                                        Ok(bytes) => {
                                                            // Try to send via response channel first (TCP/TLS)
                                                            if let Some(tx) = response_tx {
                                                                if tx.send(bytes.clone()).await.is_ok() {
                                                                    responded = true;
                                                                    info!("Sent response via TCP/TLS to {}", peer);
                                                                    break;
                                                                }
                                                            }
                                                            // Fallback to direct send (UDP)
                                                            if let Err(e) = listener_clone.send(&bytes, peer).await {
                                                                warn!("Failed to send response to {}: {}", peer, e);
                                                            } else {
                                                                responded = true;
                                                                info!("Sent response via UDP to {}", peer);
                                                            }
                                                        }
                                                        Err(e) => {
                                                            error!("Failed to serialize response: {}", e);
                                                        }
                                                    }
                                                    break;
                                                }
                                                Ok(RouteAction::Continue) => continue,
                                                Ok(RouteAction::RejectAny) => {
                                                    responded = true;
                                                    warn!("Request from {} rejected by handler", peer);
                                                    break;
                                                }
                                                Err(err) => {
                                                    error!("Handler error for request from {}: {}", peer, err);
                                                }
                                            }
                                        }
                                        if !responded {
                                            warn!("No handler responded to request from {}", peer);
                                        }
                                    }
                                    Ok(SipMessage::Response(_)) => {
                                        info!("Received SIP response from {}", peer);
                                    }
                                    Err(err) => {
                                        warn!("Failed to parse SIP message from {}: {}", peer, err);
                                    }
                                }
                            } else {
                                warn!("Transport listener closed for {:?}", listener.protocol);
                                break;
                            }
                        }
                        _ = signal::ctrl_c() => {
                            info!("Shutdown signal received for {:?} listener", listener.protocol);
                            break;
                        }
                    }
                }

                Result::<(), anyhow::Error>::Ok(())
            }));
        }

        info!("Cynan IMS Core started with {} listeners", tasks.len());
        
        // Wait for shutdown signal
        signal::ctrl_c().await.context("Failed to listen for shutdown signal")?;
        info!("Shutdown signal received, stopping all listeners...");

        // Wait for all listeners to complete
        try_join_all(tasks).await?;
        info!("All listeners stopped gracefully");
        Ok(())
    }

    /// Register an RTP stream for media forwarding to Armoricore
    ///
    /// This method allocates an RTP port and registers the stream mapping
    /// for forwarding RTP packets to the Armoricore media engine.
    pub fn register_rtp_stream(
        &self,
        sip_session_id: &str,
        armoricore_stream_id: &str,
        remote_addr: SocketAddr,
    ) -> Result<u16> {
        // Allocate RTP port
        let rtp_port = self.integration.rtp_port_manager.allocate_port()
            .ok_or_else(|| anyhow::anyhow!("No available RTP ports"))?;

        // Create stream mapping
        let mapping = crate::rtp_router::RtpStreamMapping::new(
            sip_session_id.to_string(),
            armoricore_stream_id.to_string(),
            rtp_port,
            remote_addr,
        );

        // Register with RTP router
        self.integration.rtp_router.register_stream(mapping)?;

        info!("Registered RTP stream: SIP session {} -> Armoricore stream {} on port {}",
              sip_session_id, armoricore_stream_id, rtp_port);

        Ok(rtp_port)
    }

    /// Unregister an RTP stream
    pub fn unregister_rtp_stream(&self, rtp_port: u16, remote_addr: SocketAddr) -> Result<()> {
        self.integration.rtp_router.unregister_stream(rtp_port, remote_addr)?;
        self.integration.rtp_port_manager.release_port(rtp_port);

        info!("Unregistered RTP stream on port {} for {}", rtp_port, remote_addr);
        Ok(())
    }

    /// Get RTP stream statistics
    pub fn get_rtp_stats(&self, rtp_port: u16, remote_addr: SocketAddr) -> Option<crate::rtp_router::RtpStreamMapping> {
        self.integration.rtp_router.get_stream_stats(rtp_port, remote_addr)
    }

    /// Clean up expired RTP streams
    pub fn cleanup_rtp_streams(&self) {
        self.integration.rtp_router.cleanup_expired();
    }
}

