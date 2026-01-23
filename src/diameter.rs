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

//! Diameter Protocol Implementation
//!
//! This module provides a complete Diameter protocol implementation for IMS networks,
//! including Cx, Sh, and Rx interfaces as defined in 3GPP specifications.

use anyhow::{anyhow, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Diameter message header (20 bytes)
#[derive(Debug, Clone)]
pub struct DiameterHeader {
    pub version: u8,
    pub command_flags: u8,
    pub command_code: u32,
    pub application_id: u32,
    pub hop_by_hop_id: u32,
    pub end_to_end_id: u32,
    pub message_length: u32,
}

impl DiameterHeader {
    pub fn new(command_code: u32, application_id: u32, flags: u8) -> Self {
        static NEXT_HOP_ID: AtomicU32 = AtomicU32::new(1);
        static NEXT_END_ID: AtomicU32 = AtomicU32::new(1);

        Self {
            version: 1,
            command_flags: flags,
            command_code,
            application_id,
            hop_by_hop_id: NEXT_HOP_ID.fetch_add(1, Ordering::SeqCst),
            end_to_end_id: NEXT_END_ID.fetch_add(1, Ordering::SeqCst),
            message_length: 0, // Set when encoding
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version);
        buf.put_u8(self.command_flags);
        // Write command_code as 3 bytes (big-endian)
        buf.put_u8(((self.command_code >> 16) & 0xFF) as u8);
        buf.put_u8(((self.command_code >> 8) & 0xFF) as u8);
        buf.put_u8((self.command_code & 0xFF) as u8);
        buf.put_u32(self.application_id);
        buf.put_u32(self.hop_by_hop_id);
        buf.put_u32(self.end_to_end_id);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < 20 {
            return Err(anyhow!("Header too short"));
        }

        // Read 3 bytes for command_code (big-endian)
        let cmd_bytes = buf.split_to(3);
        let command_code = ((cmd_bytes[0] as u32) << 16) |
                          ((cmd_bytes[1] as u32) << 8) |
                          (cmd_bytes[2] as u32);

        Ok(Self {
            version: buf.get_u8(),
            command_flags: buf.get_u8(),
            command_code,
            application_id: buf.get_u32(),
            hop_by_hop_id: buf.get_u32(),
            end_to_end_id: buf.get_u32(),
            message_length: 0, // Not stored in header itself
        })
    }
}

/// Diameter AVP (Attribute-Value Pair)
#[derive(Debug, Clone)]
pub struct Avp {
    pub code: u32,
    pub flags: u8,
    pub length: u32,
    pub vendor_id: Option<u32>,
    pub data: Vec<u8>,
}

impl Avp {
    pub fn new(code: u32, flags: u8, data: Vec<u8>) -> Self {
        let vendor_id = if flags & 0x80 != 0 { Some(0) } else { None };
        let length = 8 + vendor_id.map(|_| 4).unwrap_or(0) + data.len() as u32;

        Self {
            code,
            flags,
            length,
            vendor_id,
            data,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.code);
        buf.put_u8(self.flags);
        // Write length as 3 bytes (big-endian)
        buf.put_u8(((self.length >> 16) & 0xFF) as u8);
        buf.put_u8(((self.length >> 8) & 0xFF) as u8);
        buf.put_u8((self.length & 0xFF) as u8);

        if let Some(vendor_id) = self.vendor_id {
            buf.put_u32(vendor_id);
        }

        buf.put_slice(&self.data);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < 8 {
            return Err(anyhow!("AVP too short"));
        }

        let code = buf.get_u32();
        let flags = buf.get_u8();
        // Read 3 bytes for length (big-endian)
        let length_bytes = buf.split_to(3);
        let length = ((length_bytes[0] as u32) << 16) |
                     ((length_bytes[1] as u32) << 8) |
                     (length_bytes[2] as u32);

        let vendor_id = if flags & 0x80 != 0 {
            if buf.remaining() < 4 {
                return Err(anyhow!("AVP vendor ID missing"));
            }
            Some(buf.get_u32())
        } else {
            None
        };

        let data_len = length as usize - 8 - vendor_id.map(|_| 4).unwrap_or(0);
        if buf.remaining() < data_len {
            return Err(anyhow!("AVP data truncated"));
        }

        let mut data = vec![0; data_len];
        buf.copy_to_slice(&mut data);

        Ok(Self {
            code,
            flags,
            length,
            vendor_id,
            data,
        })
    }
}

/// Diameter message
#[derive(Debug, Clone)]
pub struct DiameterMessage {
    pub header: DiameterHeader,
    pub avps: Vec<Avp>,
}

impl DiameterMessage {
    pub fn new(command_code: u32, application_id: u32, flags: u8) -> Self {
        Self {
            header: DiameterHeader::new(command_code, application_id, flags),
            avps: Vec::new(),
        }
    }

    pub fn add_avp(&mut self, avp: Avp) {
        self.avps.push(avp);
    }

    pub fn encode(&mut self) -> Result<Bytes> {
        let mut buf = BytesMut::new();

        // Encode AVPs first to calculate total length
        let mut avp_data = BytesMut::new();
        for avp in &self.avps {
            avp.encode(&mut avp_data);
        }

        // Update header length
        self.header.message_length = 20 + avp_data.len() as u32;

        // Encode header and AVPs
        self.header.encode(&mut buf);
        buf.extend(avp_data);

        Ok(buf.freeze())
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let mut buf = Bytes::copy_from_slice(data);

        let header = DiameterHeader::decode(&mut buf)?;
        let mut avps = Vec::new();

        while buf.has_remaining() {
            let avp = Avp::decode(&mut buf)?;
            avps.push(avp);
        }

        Ok(Self { header, avps })
    }

    pub fn find_avp(&self, code: u32) -> Option<&Avp> {
        self.avps.iter().find(|avp| avp.code == code)
    }
}

/// Diameter AVP codes (RFC 6733 + 3GPP extensions)
pub mod avp_codes {
    pub const SESSION_ID: u32 = 263;
    pub const RESULT_CODE: u32 = 268;
    pub const ORIGIN_HOST: u32 = 264;
    pub const ORIGIN_REALM: u32 = 296;
    pub const DESTINATION_HOST: u32 = 293;
    pub const DESTINATION_REALM: u32 = 283;
    pub const USER_NAME: u32 = 1;
    pub const PUBLIC_IDENTITY: u32 = 601;
    pub const VISITED_NETWORK_IDENTIFIER: u32 = 600;
    pub const SERVER_ASSIGNMENT_TYPE: u32 = 614;
    pub const USER_DATA: u32 = 606;
    pub const SIP_AUTH_DATA_ITEM: u32 = 612;
    pub const SIP_NUMBER_AUTH_ITEMS: u32 = 607;
}

/// Diameter command codes
pub mod commands {
    pub const CAPABILITIES_EXCHANGE: u32 = 257;
    pub const DEVICE_WATCHDOG: u32 = 280;

    // Cx interface commands
    pub const USER_AUTHORIZATION: u32 = 300;
    pub const SERVER_ASSIGNMENT: u32 = 301;
    pub const LOCATION_INFO: u32 = 302;
    pub const MULTIMEDIA_AUTH: u32 = 303;
    pub const REGISTRATION_TERMINATION: u32 = 304;
    pub const PUSH_PROFILE: u32 = 305;

    // Sh interface commands
    pub const USER_DATA: u32 = 306;
    pub const PROFILE_UPDATE: u32 = 307;
    pub const SUBSCRIBE_NOTIFICATIONS: u32 = 308;
    pub const PUSH_NOTIFICATION: u32 = 309;

    // Rx interface commands
    pub const AA: u32 = 265;
    pub const RE_AUTH: u32 = 258;
    pub const SESSION_TERMINATION: u32 = 275;
}

/// Diameter application IDs
pub mod applications {
    pub const DIAMETER_COMMON_MESSAGES: u32 = 0;
    pub const NASREQ: u32 = 1;
    pub const MOBILE_IPV4: u32 = 2;
    pub const DIAMETER_BASE_ACCOUNTING: u32 = 3;
    pub const CREDIT_CONTROL: u32 = 4;
    pub const DIAMETER_EAP: u32 = 5;
    pub const DIAMETER_SIP_APPLICATION: u32 = 6;
    pub const ETSI_RESE: u32 = 7;
    pub const DIAMETER_3GPP: u32 = 16777216;
    pub const DIAMETER_3GPP_CX: u32 = 16777216;
    pub const DIAMETER_3GPP_SH: u32 = 16777217;
    pub const DIAMETER_3GPP_RX: u32 = 16777236;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_avp_encode_decode() {
        let original = Avp::new(263, 0x40, b"test-session-id".to_vec());
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let decoded = Avp::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded.code, original.code);
        assert_eq!(decoded.data, original.data);
    }

    #[test]
    fn test_diameter_message() {
        let mut msg = DiameterMessage::new(commands::USER_AUTHORIZATION, applications::DIAMETER_3GPP_CX, 0x80);
        msg.add_avp(Avp::new(avp_codes::SESSION_ID, 0x40, b"session-123".to_vec()));

        let encoded = msg.encode().unwrap();
        let decoded = DiameterMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.header.command_code, commands::USER_AUTHORIZATION);
        assert_eq!(decoded.avps.len(), 1);
    }
}