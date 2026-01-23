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

//! SIP Message Utilities
//!
//! This module provides utility functions for SIP message serialization
//! and common response creation.

use anyhow::Result;
use rsip::{response::Response, SipMessage};
use std::fmt::Write;

/// Serialize a SIP Response to bytes for transmission over the network
///
/// # Arguments
///
/// * `response` - The SIP response to serialize
///
/// # Returns
///
/// Returns the serialized response as a byte vector, or an error if serialization fails
pub fn serialize_response(response: &Response) -> Result<Vec<u8>> {
    // Convert Response to SipMessage and serialize it
    let sip_msg = SipMessage::Response(response.clone());
    
    // Use Display trait to serialize
    let mut buf = String::new();
    write!(buf, "{}", sip_msg)?;
    
    Ok(buf.into_bytes())
}

/// Create a basic 200 OK response (RFC 3261)
///
/// # Returns
///
/// A SIP 200 OK response
pub fn create_200_ok() -> Response {
    Response::try_from(b"SIP/2.0 200 OK\r\n\r\n".as_ref()).unwrap()
}

/// Create a 401 Unauthorized response with WWW-Authenticate header (RFC 3261)
///
/// Used for digest authentication challenges.
///
/// # Arguments
///
/// * `realm` - Authentication realm
/// * `nonce` - Authentication nonce
///
/// # Returns
///
/// A SIP 401 Unauthorized response with Digest challenge, or an error if creation fails
pub fn create_401_unauthorized(realm: &str, nonce: &str) -> Result<Response> {
    let auth_header = format!(
        "Digest realm=\"{}\", nonce=\"{}\", algorithm=MD5",
        realm, nonce
    );
    let response_bytes = format!(
        "SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: {}\r\n\r\n",
        auth_header
    );
    Response::try_from(response_bytes.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to create 401 response: {}", e))
}

/// Create a 400 Bad Request response (RFC 3261)
///
/// Used when the request is malformed or invalid.
///
/// # Returns
///
/// A SIP 400 Bad Request response
pub fn create_400_bad_request() -> Response {
    Response::try_from(b"SIP/2.0 400 Bad Request\r\n\r\n".as_ref()).unwrap()
}

/// Create a 500 Server Error response (RFC 3261)
///
/// Used when an internal server error occurs.
///
/// # Returns
///
/// A SIP 500 Server Error response
pub fn create_500_server_error() -> Response {
    Response::try_from(b"SIP/2.0 500 Server Error\r\n\r\n".as_ref()).unwrap()
}
