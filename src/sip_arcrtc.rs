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

//! SIP-to-ArcRTC Conversion Utilities
//!
//! This module provides utilities for converting between SIP/SDP and ArcRTC
//! protocol formats for seamless integration between Cynan IMS and Armoricore.

use anyhow::{anyhow, Result};
use rsip::common::Method;
use rsip::{Request, Response};
use serde::{Deserialize, Serialize};

/// Extract header value from SIP message string
fn extract_header(message: &str, header_name: &str) -> Option<String> {
    for line in message.lines() {
        if line.to_lowercase().starts_with(&header_name.to_lowercase()) {
            if let Some(colon_pos) = line.find(':') {
                return Some(line[colon_pos + 1..].trim().to_string());
            }
        }
    }
    None
}

/// SIP session information extracted from SIP messages
#[derive(Debug, Clone)]
pub struct SipSessionInfo {
    pub session_id: String,
    pub user_id: String,
    pub from_uri: String,
    pub to_uri: String,
    pub call_id: String,
    pub media_streams: Vec<MediaStream>,
}

/// Media stream information from SIP SDP
#[derive(Debug, Clone)]
pub struct MediaStream {
    pub media_type: MediaType,
    pub port: u32,
    pub codec: CodecType,
    pub fmtp_params: Option<String>,
    pub rtpmap: Option<String>,
}

/// ArcRTC session response from Armoricore
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcRtcSession {
    pub stream_id: String,
    pub sdp_answer: String,
    pub rtp_port: u32,
}

/// Media types for conversion
#[derive(Debug, Clone, PartialEq)]
pub enum MediaType {
    Audio,
    Video,
    Screen,
}

/// Codec types supported in both SIP and ArcRTC
#[derive(Debug, Clone, PartialEq)]
pub enum CodecType {
    Opus,
    Aac,
    Pcm,
    H264,
    Vp9,
    Av1,
    Unknown(String),
}

impl SipSessionInfo {
    /// Extract session info from SIP INVITE request
    pub fn from_invite(invite: &Request) -> Result<Self> {
        // rsip 0.4 has limited structured access - use string parsing
        let request_str = format!("{}", invite);

        if !request_str.contains("INVITE") {
            return Err(anyhow!("Not an INVITE request"));
        }

        let call_id = extract_header(&request_str, "Call-ID")
            .unwrap_or_else(|| format!("call-{}", uuid::Uuid::new_v4()));

        let from_uri = extract_header(&request_str, "From")
            .unwrap_or("unknown".to_string());

        let to_uri = extract_header(&request_str, "To")
            .unwrap_or("unknown".to_string());

        // Extract user ID from From URI (simplified)
        let user_id = extract_user_from_uri(&from_uri)?;

        // Generate session ID
        let session_id = format!("sip-{}", call_id);

        // Simplified media streams parsing for rsip 0.4
        let media_streams = vec![]; // TODO: Implement proper SDP parsing

        Ok(SipSessionInfo {
            session_id,
            user_id,
            from_uri,
            to_uri,
            call_id,
            media_streams,
        })
    }
}

impl ArcRtcSession {
    /// Convert ArcRTC session to SIP 200 OK response
    pub fn to_sip_response(&self, _invite: &Request) -> Result<Response> {
        // rsip 0.4 has very limited response creation capabilities
        // This is a stub implementation - in production we'd need a different SIP library
        // or implement our own response creation

        // For now, return an error indicating this needs to be implemented
        Err(anyhow!("SIP response creation not implemented for rsip 0.4. Use string-based response generation instead."))
    }
}

/// Convert SIP SDP offer to ArcRTC StreamConfig
pub fn sip_to_arbrtc_config(session_info: &SipSessionInfo) -> Result<armoricore::media::StreamConfig> {
    // Use the first media stream (prioritize video, then audio)
    let primary_stream = session_info.media_streams
        .iter()
        .find(|s| s.media_type == MediaType::Video)
        .or_else(|| session_info.media_streams.first())
        .ok_or_else(|| anyhow!("No media streams found"))?;

    let media_type = match primary_stream.media_type {
        MediaType::Audio => armoricore::media::MediaType::Audio,
        MediaType::Video => armoricore::media::MediaType::Video,
        MediaType::Screen => armoricore::media::MediaType::Screen,
    };

    let codec = match primary_stream.codec {
        CodecType::Opus => armoricore::media::CodecType::Opus,
        CodecType::Aac => armoricore::media::CodecType::Aac,
        CodecType::Pcm => armoricore::media::CodecType::Pcm,
        CodecType::H264 => armoricore::media::CodecType::H264,
        CodecType::Vp9 => armoricore::media::CodecType::Vp9,
        CodecType::Av1 => armoricore::media::CodecType::Av1,
        CodecType::Unknown(ref s) => return Err(anyhow!("Unsupported codec: {}", s)),
    };

    // Create basic config - in production this should be more sophisticated
    Ok(armoricore::media::StreamConfig {
        user_id: session_info.user_id.clone(),
        media_type: media_type as i32,
        codec: codec as i32,
        sample_rate: if media_type == armoricore::media::MediaType::Audio { 48000 } else { 0 },
        channels: if media_type == armoricore::media::MediaType::Audio { 2 } else { 0 },
        bitrate: 128, // Default bitrate
        width: if media_type == armoricore::media::MediaType::Video { 1280 } else { 0 },
        height: if media_type == armoricore::media::MediaType::Video { 720 } else { 0 },
        frame_rate: if media_type == armoricore::media::MediaType::Video { 30 } else { 0 },
        sdp_offer: create_basic_sdp_offer(session_info),
    })
}

/// Convert ArcRTC SDP answer to SIP-compatible format
pub fn arbrtc_to_sip_sdp(sdp_answer: &str, session_info: &SipSessionInfo) -> String {
    // In a full implementation, this would properly convert ArcRTC SDP to SIP SDP
    // For now, return the answer as-is with some basic SIP SDP structure
    format!("v=0\r\no=- {} 0 IN IP4 127.0.0.1\r\ns=Cynan IMS Session\r\nt=0 0\r\n{}", session_info.session_id, sdp_answer)
}

/// Extract user ID from SIP URI
fn extract_user_from_uri(uri: &str) -> Result<String> {
    // Simple extraction - in production this should parse SIP URIs properly
    if let Some(at_pos) = uri.find('@') {
        Ok(uri[..at_pos].trim_start_matches("sip:").to_string())
    } else {
        Err(anyhow!("Invalid SIP URI format: {}", uri))
    }
}

/// Parse SDP media streams from SIP message body
fn parse_sdp_media_streams(body: &[u8]) -> Result<Vec<MediaStream>> {
    let sdp = String::from_utf8_lossy(body);
    let mut streams = Vec::new();

    for line in sdp.lines() {
        if line.starts_with("m=") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let media_type = match parts[0].strip_prefix("m=") {
                    Some("audio") => MediaType::Audio,
                    Some("video") => MediaType::Video,
                    _ => continue,
                };

                let port: u32 = parts[1].parse().unwrap_or(0);
                let codec_str = parts[3];

                // Determine codec type
                let codec = match codec_str {
                    "opus" | "111" => CodecType::Opus,
                    "H264" | "96" => CodecType::H264,
                    "VP9" | "98" => CodecType::Vp9,
                    "AV1" | "97" => CodecType::Av1,
                    _ => CodecType::Unknown(codec_str.to_string()),
                };

                streams.push(MediaStream {
                    media_type,
                    port,
                    codec,
                    fmtp_params: None, // Would parse fmtp lines
                    rtpmap: None,     // Would parse rtpmap lines
                });
            }
        }
    }

    Ok(streams)
}

/// Create basic SDP offer for ArcRTC (placeholder)
fn create_basic_sdp_offer(session_info: &SipSessionInfo) -> String {
    format!(
        "v=0\r\no=- {} 0 IN IP4 127.0.0.1\r\ns=Cynan SIP Session\r\nt=0 0\r\n",
        session_info.session_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_user_from_uri() {
        assert_eq!(extract_user_from_uri("sip:alice@example.com").unwrap(), "alice");
        assert_eq!(extract_user_from_uri("sip:bob@domain.org").unwrap(), "bob");
        assert!(extract_user_from_uri("invalid-uri").is_err());
    }

    #[test]
    fn test_media_type_conversion() {
        let audio_stream = MediaStream {
            media_type: MediaType::Audio,
            port: 5004,
            codec: CodecType::Opus,
            fmtp_params: None,
            rtpmap: None,
        };

        assert_eq!(audio_stream.media_type, MediaType::Audio);
        assert_eq!(audio_stream.codec, CodecType::Opus);
    }
}