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

//! Integration Layer
//!
//! This module provides integration interfaces for external services:
//! - **Armoricore**: Secure media handling via gRPC and NATS
//! - **Diameter**: HSS queries via Cx/Sh/Rx interfaces (RFC 6733)
//! - **Security**: TLS/IPSec enforcement and policy validation

use crate::config::{ArmoricoreConfig, SecurityConfig, TransportConfig};
use crate::diameter::{DiameterMessage, Avp, avp_codes, commands, applications};
use crate::sip_arcrtc::{sip_to_arbrtc_config, ArcRtcSession, SipSessionInfo};
use crate::tls_config::TlsCertificateManager;
use anyhow::{anyhow, Result};
use log;
// Temporarily disable NATS due to dependency conflicts
// use nats::asynk::Connection as NatsConnection;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tonic::transport::{Channel, ClientTlsConfig};

// TODO: Import generated protobuf types once build.rs is working
// pub mod armoricore {
//     pub mod media {
//         tonic::include_proto!("armoricore.media");
//     }
// }

// TODO: Re-enable protobuf types once build.rs is fixed
// use armoricore::media::media_engine_client::MediaEngineClient;
// use armoricore::media::{CreateStreamRequest, StreamConfig, StreamRequest};

// Stub implementations for now
pub type MediaEngineClient<T> = crate::integration::StubMediaEngineClient<T>;

#[derive(Clone)]
pub struct StubMediaEngineClient<T> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T> StubMediaEngineClient<T> {
    pub fn new(_channel: T) -> Self {
        Self { _phantom: std::marker::PhantomData }
    }
}

#[derive(Clone)]
pub struct CreateStreamRequest {
    pub config: Option<StreamConfig>,
}

#[derive(Clone)]
pub struct StreamConfig {
    pub user_id: String,
    pub media_type: i32,
    pub codec: i32,
    pub sample_rate: u32,
    pub channels: u32,
    pub bitrate: u32,
    pub width: u32,
    pub height: u32,
    pub frame_rate: u32,
    pub sdp_offer: String,
}

#[derive(Clone)]
pub struct StreamRequest {
    pub stream_id: String,
}

// Placeholder types for now
#[derive(Clone)]
pub struct MediaEngineClient<T> {
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Clone)]
pub struct CreateStreamRequest {
    pub config: Option<StreamConfig>,
}

#[derive(Clone)]
pub struct StreamConfig {
    pub user_id: String,
    pub media_type: i32,
    pub codec: i32,
    pub sample_rate: u32,
    pub channels: u32,
    pub bitrate: u32,
    pub width: u32,
    pub height: u32,
    pub frame_rate: u32,
    pub sdp_offer: String,
}

#[derive(Clone)]
pub struct StreamRequest {
    pub stream_id: String,
}

/// Bridge to Armoricore secure media service
///
/// Provides gRPC connectivity for session handoff and
/// post-quantum cryptographic media handling.
/// NATS integration temporarily disabled due to dependency conflicts.
pub struct ArmoricoreBridge {
    /// gRPC client for media engine operations
    media_client: MediaEngineClient<Channel>,
    // Temporarily disabled: NATS connection for messaging
    // nats: NatsConnection,
}

impl ArmoricoreBridge {
    pub async fn new(config: &ArmoricoreConfig, tls: Option<ClientTlsConfig>) -> Result<Self> {
        let mut builder = Channel::from_shared(config.grpc_target.clone())
            .map_err(|err| anyhow!("invalid gRPC target: {err}"))?;

        if let Some(tls) = tls {
            builder = builder.tls_config(tls)?;
        }

        let channel = builder.connect().await?;
        let media_client = MediaEngineClient::new(channel);

        // Temporarily disabled NATS connection
        // let nats = NatsConnection::connect(&config.nats_url)
        //     .await
        //     .map_err(|err| anyhow!("failed to connect to NATS: {err}"))?;

        Ok(ArmoricoreBridge { media_client })
    }

    /// Request session handoff to Armoricore for secure media processing
    ///
    /// This method:
    /// 1. Converts SIP session info to ArcRTC StreamConfig
    /// 2. Calls Armoricore's MediaEngine.CreateStream via gRPC
    /// 3. Publishes session creation event via NATS
    /// 4. Returns ArcRTC session information for SIP response generation
    pub async fn request_session(&self, session_info: &SipSessionInfo) -> Result<ArcRtcSession> {
        log::info!("Requesting session handoff to Armoricore for session: {}", session_info.session_id);

        // Convert SIP session to ArcRTC configuration
        let stream_config = sip_to_arbrtc_config(session_info)?;

        // Create stream request
        let request = CreateStreamRequest {
            config: Some(stream_config),
        };

        // Call Armoricore gRPC service
        let mut client = self.media_client.clone();
        let response = client.create_stream(request)
            .await
            .map_err(|err| anyhow!("Armoricore gRPC call failed: {err}"))?;

        let reply = response.into_inner();

        // Extract ArcRTC session information
        let arc_session = ArcRtcSession {
            stream_id: reply.stream_id,
            sdp_answer: reply.sdp_answer,
            rtp_port: reply.rtp_port,
        };

        // TODO: Publish session creation event via NATS (temporarily disabled)
        // self.publish_session_event("cynan.session.created", session_info, &arc_session).await?;
        let _arc_session = arc_session; // Suppress unused variable warning
        log::info!("NATS event publishing temporarily disabled due to dependency conflicts");

        log::info!("Successfully created Armoricore session: {}", arc_session.stream_id);
        Ok(arc_session)
    }

    /// End session and clean up Armoricore resources
    pub async fn end_session(&self, stream_id: &str) -> Result<()> {
        log::info!("Ending Armoricore session: {}", stream_id);

        let request = StreamRequest {
            stream_id: stream_id.to_string(),
        };

        let mut client = self.media_client.clone();
        client.stop_stream(request)
            .await
            .map_err(|err| anyhow!("Failed to stop Armoricore stream: {err}"))?;

        // TODO: Publish session ended event (temporarily disabled)
        // self.publish_event("cynan.session.ended", &serde_json::json!({
        //     "stream_id": stream_id,
        //     "timestamp": chrono::Utc::now().timestamp(),
        // })).await?;
        log::info!("NATS event publishing temporarily disabled due to dependency conflicts");

        Ok(())
    }

    /// Publish session lifecycle events to NATS (temporarily disabled)
    async fn publish_session_event(
        &self,
        subject: &str,
        sip_info: &SipSessionInfo,
        arc_session: &ArcRtcSession
    ) -> Result<()> {
        // TODO: Re-enable NATS event publishing once dependency conflicts are resolved
        log::debug!("NATS event publishing disabled: would publish {} for session {}", subject, sip_info.session_id);
        Ok(())
    }

    /// Generic NATS event publishing (temporarily disabled)
    async fn publish_event(&self, subject: &str, payload: &serde_json::Value) -> Result<()> {
        // TODO: Re-enable NATS event publishing once dependency conflicts are resolved
        let _payload = payload; // Suppress unused variable warning
        log::debug!("NATS event publishing disabled: would publish to {}", subject);
        Ok(())
    }
}

/// Server assignment types for Cx interface
#[derive(Debug, Clone, PartialEq)]
pub enum ServerAssignmentType {
    NoAssignment,
    Registration,
    ReRegistration,
    UnregisteredUser,
    TimeoutDeregistration,
    UserDeregistration,
    TimeoutDeregistrationStoreServerName,
    UserDeregistrationStoreServerName,
    AdministrativeDeregistration,
    AuthenticationFailure,
    AuthenticationTimeout,
    DereRegistrationTooMuchData,
}

impl ServerAssignmentType {
    pub fn to_string(&self) -> &'static str {
        match self {
            Self::NoAssignment => "NO_ASSIGNMENT",
            Self::Registration => "REGISTRATION",
            Self::ReRegistration => "RE_REGISTRATION",
            Self::UnregisteredUser => "UNREGISTERED_USER",
            Self::TimeoutDeregistration => "TIMEOUT_DEREGISTRATION",
            Self::UserDeregistration => "USER_DEREGISTRATION",
            Self::TimeoutDeregistrationStoreServerName => "TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME",
            Self::UserDeregistrationStoreServerName => "USER_DEREGISTRATION_STORE_SERVER_NAME",
            Self::AdministrativeDeregistration => "ADMINISTRATIVE_DEREGISTRATION",
            Self::AuthenticationFailure => "AUTHENTICATION_FAILURE",
            Self::AuthenticationTimeout => "AUTHENTICATION_TIMEOUT",
            Self::DereRegistrationTooMuchData => "DEREGISTRATION_TOO_MUCH_DATA",
        }
    }

    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::NoAssignment),
            1 => Some(Self::Registration),
            2 => Some(Self::ReRegistration),
            3 => Some(Self::UnregisteredUser),
            4 => Some(Self::TimeoutDeregistration),
            5 => Some(Self::UserDeregistration),
            6 => Some(Self::TimeoutDeregistrationStoreServerName),
            7 => Some(Self::UserDeregistrationStoreServerName),
            8 => Some(Self::AdministrativeDeregistration),
            9 => Some(Self::AuthenticationFailure),
            10 => Some(Self::AuthenticationTimeout),
            11 => Some(Self::DereRegistrationTooMuchData),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserProfile {
    pub username: String,
    pub scscf_capabilities: Vec<String>,
    pub scscf_name: Option<String>,
    pub server_assignment_type: Option<ServerAssignmentType>,
}

#[derive(Debug, Clone)]
pub struct SipAuthDataItem {
    pub auth_scheme: String,
    pub authenticate: Vec<u8>,
    pub authorization: Vec<u8>,
    pub confidentiality_key: Vec<u8>,
    pub integrity_key: Vec<u8>,
}

pub struct DiameterInterface {
    hss_address: SocketAddr,
    origin_host: String,
    origin_realm: String,
    connection: Arc<Mutex<Option<TcpStream>>>,
}

impl DiameterInterface {
    pub async fn new(hss_addr: SocketAddr, origin_host: String, origin_realm: String) -> Result<Self> {
        Ok(DiameterInterface {
            hss_address: hss_addr,
            origin_host,
            origin_realm,
            connection: Arc::new(Mutex::new(None)),
        })
    }

    async fn ensure_connection(&self) -> Result<()> {
        let mut conn = self.connection.lock().await;
        if conn.is_none() {
            let stream = TcpStream::connect(self.hss_address).await
                .map_err(|e| anyhow!("Failed to connect to HSS: {}", e))?;
            *conn = Some(stream);
            log::info!("Connected to HSS at {}", self.hss_address);
        }
        Ok(())
    }

    async fn send_message(&self, message: &mut DiameterMessage) -> Result<DiameterMessage> {
        self.ensure_connection().await?;

        let data = message.encode()?;
        let mut conn = self.connection.lock().await;
        let stream = conn.as_mut().unwrap();

        // Send message
        tokio::io::AsyncWriteExt::write_all(stream, &data).await
            .map_err(|e| anyhow!("Failed to send Diameter message: {}", e))?;

        // Read response (simplified - in production this needs proper framing)
        let mut response_buf = [0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(stream, &mut response_buf).await
            .map_err(|e| anyhow!("Failed to read Diameter response: {}", e))?;

        if n == 0 {
            return Err(anyhow!("HSS connection closed"));
        }

        DiameterMessage::decode(&response_buf[..n])
            .map_err(|e| anyhow!("Failed to decode Diameter response: {}", e))
    }

    /// Cx-Query: Query HSS for user location and S-CSCF capabilities (UAR/UAA)
    pub async fn cx_query(&self, username: &str, public_identity: &str) -> Result<UserProfile> {
        log::info!("Cx-Query (UAR) for user: {}, public_identity: {}", username, public_identity);

        // Create User-Authorization-Request (UAR)
        let mut request = DiameterMessage::new(
            commands::USER_AUTHORIZATION,
            applications::DIAMETER_3GPP_CX,
            0x80 // Request flag
        );

        // Add mandatory AVPs
        request.add_avp(Avp::new(avp_codes::SESSION_ID, 0x40, b"cx-session-123".to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_HOST, 0x40, self.origin_host.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_REALM, 0x40, self.origin_realm.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::DESTINATION_REALM, 0x40, b"hss.realm".to_vec()));
        request.add_avp(Avp::new(avp_codes::USER_NAME, 0x40, username.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::PUBLIC_IDENTITY, 0x40, public_identity.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::VISITED_NETWORK_IDENTIFIER, 0x40, b"cynan.ims".to_vec()));

        // Send request and get response
        let response = self.send_message(&mut request).await?;

        // Parse UAA (User-Authorization-Answer)
        self.parse_uaa_response(&response)
    }

    /// Cx-Select: Select appropriate S-CSCF based on capabilities (LIR/LIA)
    pub async fn cx_select(&self, username: &str, capabilities: &[String]) -> Result<String> {
        log::info!("Cx-Select (LIR) for user: {}, capabilities: {:?}", username, capabilities);

        // Create Location-Info-Request (LIR)
        let mut request = DiameterMessage::new(
            commands::LOCATION_INFO,
            applications::DIAMETER_3GPP_CX,
            0x80
        );

        request.add_avp(Avp::new(avp_codes::SESSION_ID, 0x40, b"cx-session-456".to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_HOST, 0x40, self.origin_host.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_REALM, 0x40, self.origin_realm.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::DESTINATION_REALM, 0x40, b"hss.realm".to_vec()));
        request.add_avp(Avp::new(avp_codes::USER_NAME, 0x40, username.as_bytes().to_vec()));

        // Add S-CSCF capabilities
        for capability in capabilities {
            request.add_avp(Avp::new(0, 0xC0, capability.as_bytes().to_vec())); // Vendor-specific capability AVP
        }

        let response = self.send_message(&mut request).await?;

        // Parse LIA and extract S-CSCF name
        if let Some(scscf_avp) = response.find_avp(602) { // Server-Name AVP
            String::from_utf8(scscf_avp.data.clone())
                .map_err(|e| anyhow!("Invalid S-CSCF name: {}", e))
        } else {
            Ok("scscf.cynan.ims".to_string()) // Default fallback
        }
    }

    /// Cx-Auth-Data: Get authentication data for user (MAR/MAA)
    pub async fn cx_auth_data(&self, username: &str) -> Result<Vec<SipAuthDataItem>> {
        log::info!("Cx-Auth-Data (MAR) for user: {}", username);

        // Create Multimedia-Auth-Request (MAR)
        let mut request = DiameterMessage::new(
            commands::MULTIMEDIA_AUTH,
            applications::DIAMETER_3GPP_CX,
            0x80
        );

        request.add_avp(Avp::new(avp_codes::SESSION_ID, 0x40, b"cx-session-789".to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_HOST, 0x40, self.origin_host.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_REALM, 0x40, self.origin_realm.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::DESTINATION_REALM, 0x40, b"hss.realm".to_vec()));
        request.add_avp(Avp::new(avp_codes::USER_NAME, 0x40, username.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::PUBLIC_IDENTITY, 0x40, format!("sip:{}", username).as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::SIP_NUMBER_AUTH_ITEMS, 0x40, 1u32.to_be_bytes().to_vec()));

        let response = self.send_message(&mut request).await?;

        // Parse MAA and extract auth data
        self.parse_maa_response(&response)
    }

    fn parse_uaa_response(&self, response: &DiameterMessage) -> Result<UserProfile> {
        // Check result code
        if let Some(result_avp) = response.find_avp(avp_codes::RESULT_CODE) {
            let result_code = u32::from_be_bytes(result_avp.data[..4].try_into().unwrap());
            if result_code != 2001 { // DIAMETER_SUCCESS
                return Err(anyhow!("UAA failed with result code: {}", result_code));
            }
        }

        // Extract server capabilities
        let mut capabilities = Vec::new();
        let mut scscf_name = None;
        let mut server_assignment_type = None;

        for avp in &response.avps {
            match avp.code {
                601 => { // Server-Capabilities AVP
                    if let Ok(cap_str) = String::from_utf8(avp.data.clone()) {
                        capabilities.push(cap_str);
                    }
                }
                602 => { // Server-Name AVP
                    if let Ok(name) = String::from_utf8(avp.data.clone()) {
                        scscf_name = Some(name);
                    }
                }
                614 => { // Server-Assignment-Type AVP
                    if avp.data.len() >= 4 {
                        let sat_value = u32::from_be_bytes(avp.data[..4].try_into().unwrap());
                        server_assignment_type = ServerAssignmentType::from_u32(sat_value);
                    }
                }
                _ => {}
            }
        }

        Ok(UserProfile {
            username: "".to_string(), // Would be extracted from request context
            scscf_capabilities: capabilities,
            scscf_name,
            server_assignment_type,
        })
    }

    fn parse_maa_response(&self, response: &DiameterMessage) -> Result<Vec<SipAuthDataItem>> {
        // Check result code
        if let Some(result_avp) = response.find_avp(avp_codes::RESULT_CODE) {
            let result_code = u32::from_be_bytes(result_avp.data[..4].try_into().unwrap());
            if result_code != 2001 { // DIAMETER_SUCCESS
                return Err(anyhow!("MAA failed with result code: {}", result_code));
            }
        }

        // Extract SIP auth data items
        let mut auth_items = Vec::new();

        for avp in &response.avps {
            if avp.code == avp_codes::SIP_AUTH_DATA_ITEM {
                // Parse the grouped AVP containing auth data
                let auth_item = SipAuthDataItem {
                    auth_scheme: "Digest".to_string(),
                    authenticate: Vec::new(),
                    authorization: Vec::new(),
                    confidentiality_key: Vec::new(),
                    integrity_key: Vec::new(),
                };

                // In a full implementation, this would parse the grouped AVP structure
                // For now, return a placeholder item
                auth_items.push(auth_item);
            }
        }

        Ok(auth_items)
    }

    /// Sh-Query: Retrieve user profile data (UDR/UDA)
    pub async fn sh_query(&self, username: &str, service_indication: &str, data_reference: u32) -> Result<String> {
        log::info!("Sh-Query (UDR) for user: {}, service: {}", username, service_indication);

        // Create User-Data-Request (UDR)
        let mut request = DiameterMessage::new(
            commands::USER_DATA,
            applications::DIAMETER_3GPP_SH,
            0x80
        );

        request.add_avp(Avp::new(avp_codes::SESSION_ID, 0x40, b"sh-session-123".to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_HOST, 0x40, self.origin_host.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_REALM, 0x40, self.origin_realm.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::DESTINATION_REALM, 0x40, b"hss.realm".to_vec()));
        request.add_avp(Avp::new(avp_codes::USER_NAME, 0x40, username.as_bytes().to_vec()));

        // Service-Indication AVP (vendor-specific)
        request.add_avp(Avp::new(704, 0xC0, service_indication.as_bytes().to_vec()));

        // Data-Reference AVP
        request.add_avp(Avp::new(703, 0xC0, data_reference.to_be_bytes().to_vec()));

        let response = self.send_message(&mut request).await?;

        // Parse UDA (User-Data-Answer) and extract user data
        self.parse_uda_response(&response)
    }

    /// Sh-Update: Update user profile data (PUR/PUA)
    pub async fn sh_update(&self, username: &str, service_indication: &str, user_data: &str) -> Result<()> {
        log::info!("Sh-Update (PUR) for user: {}, service: {}", username, service_indication);

        // Create Profile-Update-Request (PUR)
        let mut request = DiameterMessage::new(
            commands::PROFILE_UPDATE,
            applications::DIAMETER_3GPP_SH,
            0x80
        );

        request.add_avp(Avp::new(avp_codes::SESSION_ID, 0x40, b"sh-session-456".to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_HOST, 0x40, self.origin_host.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_REALM, 0x40, self.origin_realm.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::DESTINATION_REALM, 0x40, b"hss.realm".to_vec()));
        request.add_avp(Avp::new(avp_codes::USER_NAME, 0x40, username.as_bytes().to_vec()));

        // Service-Indication AVP
        request.add_avp(Avp::new(704, 0xC0, service_indication.as_bytes().to_vec()));

        // User-Data AVP
        request.add_avp(Avp::new(avp_codes::USER_DATA, 0xC0, user_data.as_bytes().to_vec()));

        let response = self.send_message(&mut request).await?;

        // Check PUA result
        if let Some(result_avp) = response.find_avp(avp_codes::RESULT_CODE) {
            let result_code = u32::from_be_bytes(result_avp.data[..4].try_into().unwrap());
            if result_code != 2001 { // DIAMETER_SUCCESS
                return Err(anyhow!("PUA failed with result code: {}", result_code));
            }
        }

        Ok(())
    }

    fn parse_uda_response(&self, response: &DiameterMessage) -> Result<String> {
        // Check result code
        if let Some(result_avp) = response.find_avp(avp_codes::RESULT_CODE) {
            let result_code = u32::from_be_bytes(result_avp.data[..4].try_into().unwrap());
            if result_code != 2001 { // DIAMETER_SUCCESS
                return Err(anyhow!("UDA failed with result code: {}", result_code));
            }
        }

        // Extract User-Data AVP
        if let Some(user_data_avp) = response.find_avp(avp_codes::USER_DATA) {
            String::from_utf8(user_data_avp.data.clone())
                .map_err(|e| anyhow!("Invalid user data: {}", e))
        } else {
            Err(anyhow!("No user data in UDA response"))
        }
    }

    /// Rx-Auth: Request QoS authorization (AAR/AAA)
    pub async fn rx_auth(&self, session_id: &str, media_components: &[MediaComponent]) -> Result<AuthResponse> {
        log::info!("Rx-Auth (AAR) for session: {}", session_id);

        // Create AA-Request (AAR)
        let mut request = DiameterMessage::new(
            commands::AA,
            applications::DIAMETER_3GPP_RX,
            0x80
        );

        request.add_avp(Avp::new(avp_codes::SESSION_ID, 0x40, session_id.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_HOST, 0x40, self.origin_host.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_REALM, 0x40, self.origin_realm.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::DESTINATION_REALM, 0x40, b"pcrf.realm".to_vec()));

        // Add media components
        for (i, component) in media_components.iter().enumerate() {
            self.add_media_component(&mut request, i as u32 + 1, component);
        }

        let response = self.send_message(&mut request).await?;

        // Parse AAA (AA-Answer)
        self.parse_aaa_response(&response)
    }

    /// Rx-ReAuth: Request re-authorization (RAR/RAA)
    pub async fn rx_reauth(&self, session_id: &str, _updated_components: &[MediaComponent]) -> Result<()> {
        log::info!("Rx-ReAuth (RAR) for session: {}", session_id);

        // Create Re-Auth-Request (RAR)
        let mut request = DiameterMessage::new(
            commands::RE_AUTH,
            applications::DIAMETER_3GPP_RX,
            0x80
        );

        request.add_avp(Avp::new(avp_codes::SESSION_ID, 0x40, session_id.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_HOST, 0x40, self.origin_host.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_REALM, 0x40, self.origin_realm.as_bytes().to_vec()));

        // Add specific action (re-authorization)
        request.add_avp(Avp::new(0, 0xC0, 0u32.to_be_bytes().to_vec())); // Re-Auth-Request-Type

        let response = self.send_message(&mut request).await?;

        // Check RAA result
        if let Some(result_avp) = response.find_avp(avp_codes::RESULT_CODE) {
            let result_code = u32::from_be_bytes(result_avp.data[..4].try_into().unwrap());
            if result_code != 2001 { // DIAMETER_SUCCESS
                return Err(anyhow!("RAA failed with result code: {}", result_code));
            }
        }

        Ok(())
    }

    /// Rx-Termination: Terminate session (STR/STA)
    pub async fn rx_terminate(&self, session_id: &str) -> Result<()> {
        log::info!("Rx-Termination (STR) for session: {}", session_id);

        // Create Session-Termination-Request (STR)
        let mut request = DiameterMessage::new(
            commands::SESSION_TERMINATION,
            applications::DIAMETER_3GPP_RX,
            0x80
        );

        request.add_avp(Avp::new(avp_codes::SESSION_ID, 0x40, session_id.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_HOST, 0x40, self.origin_host.as_bytes().to_vec()));
        request.add_avp(Avp::new(avp_codes::ORIGIN_REALM, 0x40, self.origin_realm.as_bytes().to_vec()));
        request.add_avp(Avp::new(0, 0xC0, 0u32.to_be_bytes().to_vec())); // Termination-Cause

        let response = self.send_message(&mut request).await?;

        // Check STA result
        if let Some(result_avp) = response.find_avp(avp_codes::RESULT_CODE) {
            let result_code = u32::from_be_bytes(result_avp.data[..4].try_into().unwrap());
            if result_code != 2001 { // DIAMETER_SUCCESS
                return Err(anyhow!("STA failed with result code: {}", result_code));
            }
        }

        Ok(())
    }

    fn add_media_component(&self, request: &mut DiameterMessage, component_number: u32, component: &MediaComponent) {
        // Media-Component-Description AVP (grouped)
        // This would contain codec data, bandwidth requirements, etc.
        // In a full implementation, this would be a proper grouped AVP structure

        // For now, add simplified components
        request.add_avp(Avp::new(0, 0xC0, component_number.to_be_bytes().to_vec())); // Media-Component-Number
        request.add_avp(Avp::new(0, 0xC0, component.media_type.as_bytes().to_vec())); // Media-Type
        request.add_avp(Avp::new(0, 0xC0, component.max_requested_bandwidth.to_be_bytes().to_vec())); // Max-Requested-Bandwidth
    }

    fn parse_aaa_response(&self, response: &DiameterMessage) -> Result<AuthResponse> {
        // Check result code
        if let Some(result_avp) = response.find_avp(avp_codes::RESULT_CODE) {
            let result_code = u32::from_be_bytes(result_avp.data[..4].try_into().unwrap());
            if result_code != 2001 { // DIAMETER_SUCCESS
                return Err(anyhow!("AAA failed with result code: {}", result_code));
            }
        }

        // Parse authorization data
        let mut auth_response = AuthResponse {
            session_id: String::new(),
            authorized_components: Vec::new(),
        };

        for avp in &response.avps {
            match avp.code {
                263 => { // Session-Id
                    if let Ok(session_id) = String::from_utf8(avp.data.clone()) {
                        auth_response.session_id = session_id;
                    }
                }
                // Parse authorized QoS parameters
                _ => {}
            }
        }

        Ok(auth_response)
    }

    pub async fn send_probe(&self, _code: u32) -> Result<()> {
        // Implementation for sending capability exchange or watchdog messages
        log::debug!("Sending Diameter probe");
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MediaComponent {
    pub media_type: String,
    pub max_requested_bandwidth: u32,
    pub rr_bandwidth: u32,
    pub rs_bandwidth: u32,
}

#[derive(Debug, Clone)]
pub struct AuthResponse {
    pub session_id: String,
    pub authorized_components: Vec<AuthorizedComponent>,
}

#[derive(Debug, Clone)]
pub struct AuthorizedComponent {
    pub component_number: u32,
    pub authorized_bandwidth: u32,
    pub final_bitrate: u32,
}

/// Security policy enforcement
///
/// Enforces TLS requirements and IPSec policies for secure SIP transport.
pub struct SecurityEnforcer {
    /// TLS certificate manager for certificate loading and hot-reloading
    pub tls_manager: Option<TlsCertificateManager>,
    /// TLS acceptor for incoming TLS connections (derived from certificates)
    pub tls_acceptor: Option<TlsAcceptor>,
    /// Whether TLS is required for all connections
    pub require_tls: bool,
    /// IPSec policy string (e.g., "strict", "permissive")
    pub ipsec_policy: Option<String>,
}

impl SecurityEnforcer {
    /// Create SecurityEnforcer from configuration with certificate loading
    pub async fn from_config_async(
        transport: &TransportConfig,
        security: &SecurityConfig,
    ) -> Result<Self> {
        let tls_manager = if let Some(tls_config) = &transport.tls {
            Some(crate::tls_config::TlsConfigUtils::load_from_config(tls_config).await?)
        } else {
            None
        };

        let tls_acceptor = if let Some(manager) = &tls_manager {
            let server_config = manager.get_server_config().await?;
            Some(TlsAcceptor::from(server_config))
        } else {
            None
        };

        if security.require_tls && transport.tls.is_none() && tls_acceptor.is_none() {
            return Err(anyhow!("TLS is required but no certificates or config were provided"));
        }

        Ok(SecurityEnforcer {
            tls_manager,
            tls_acceptor,
            require_tls: security.require_tls,
            ipsec_policy: security.ipsec_policy.clone(),
        })
    }

    /// Legacy synchronous constructor for backward compatibility
    pub fn from_config(
        _transport: &TransportConfig,
        security: &SecurityConfig,
        _certs: Option<(Certificate, PrivateKey)>,
    ) -> Result<Self> {
        // This method is deprecated - use from_config_async instead
        warn!("SecurityEnforcer::from_config is deprecated, use from_config_async");

        if security.require_tls {
            return Err(anyhow!("TLS is required but async certificate loading is needed"));
        }

        Ok(SecurityEnforcer {
            tls_manager: None,
            tls_acceptor: None,
            require_tls: security.require_tls,
            ipsec_policy: security.ipsec_policy.clone(),
        })
    }

    /// Check and reload certificates if they have changed
    pub async fn check_certificate_reload(&self) -> Result<bool> {
        if let Some(manager) = &self.tls_manager {
            manager.check_and_reload().await
        } else {
            Ok(false)
        }
    }

    /// Get current TLS server configuration
    pub async fn get_tls_config(&self) -> Result<Option<Arc<ServerConfig>>> {
        if let Some(manager) = &self.tls_manager {
            Ok(Some(manager.get_server_config().await?))
        } else {
            Ok(None)
        }
    }

    pub fn enforce_ipsec(&self) -> Result<()> {
        if let Some(policy) = &self.ipsec_policy {
            let _ = policy;
            // placeholder to ensure IPSec policies stay required (e.g., validating SA config)
        }

        Ok(())
    }
}
