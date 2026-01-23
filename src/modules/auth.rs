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

//! SIP Digest Authentication (RFC 3261)
//!
//! This module implements SIP digest authentication as specified in RFC 3261.
//! It provides functions for parsing Authorization headers, generating nonces,
//! computing digest responses, and verifying authentication credentials.

use anyhow::{anyhow, Result};
use hex;
use ring::digest;
use std::collections::HashMap;

/// Parse Authorization header from SIP request
///
/// Extracts digest authentication parameters from a SIP Authorization header.
///
/// # Arguments
///
/// * `header_value` - The value of the Authorization header (with or without "Digest " prefix)
///
/// # Returns
///
/// Returns a HashMap of parameter names to values, or an error if parsing fails
///
/// # Example
///
/// ```
/// use cynan::modules::auth::parse_authorization;
/// let params = parse_authorization(r#"Digest username="user", realm="cynan.ims", nonce="abc123""#)?;
/// assert_eq!(params.get("username"), Some(&"user".to_string()));
/// ```
pub fn parse_authorization(header_value: &str) -> Result<HashMap<String, String>> {
    let mut params = HashMap::new();
    
    // Remove "Digest " prefix if present
    let value = header_value.strip_prefix("Digest ").unwrap_or(header_value);
    
    // Parse key=value pairs
    for part in value.split(',') {
        let part = part.trim();
        if let Some((key, val)) = part.split_once('=') {
            let key = key.trim();
            let val = val.trim().trim_matches('"');
            params.insert(key.to_string(), val.to_string());
        }
    }
    
    Ok(params)
}

/// Generate a cryptographically secure nonce for digest authentication
///
/// Uses random bytes to create a unique nonce for each authentication challenge.
///
/// # Returns
///
/// Returns a hex-encoded 16-byte random nonce
pub fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    hex::encode(bytes)
}

/// Compute digest authentication response (RFC 3261)
///
/// Computes the MD5 digest response value for SIP digest authentication.
/// Supports both simple digest (without qop) and qop-based digest.
///
/// # Arguments
///
/// * `username` - Username from Authorization header
/// * `realm` - Authentication realm
/// * `password` - User's password (or HA1 pre-computed hash)
/// * `method` - SIP method (e.g., "REGISTER", "INVITE")
/// * `uri` - Request-URI from SIP request
/// * `nonce` - Nonce from WWW-Authenticate challenge
/// * `nc` - Nonce count (optional, for qop)
/// * `cnonce` - Client nonce (optional, for qop)
/// * `qop` - Quality of protection (optional, e.g., "auth")
///
/// # Returns
///
/// Returns the computed digest response as a hex string
pub fn compute_digest_response(
    username: &str,
    realm: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    nc: Option<&str>,
    cnonce: Option<&str>,
    qop: Option<&str>,
) -> String {
    // HA1 = MD5(username:realm:password)
    let ha1_input = format!("{}:{}:{}", username, realm, password);
    let ha1 = hex::encode(digest::digest(&digest::MD5, ha1_input.as_bytes()));
    
    // HA2 = MD5(method:uri)
    let ha2_input = format!("{}:{}", method, uri);
    let ha2 = hex::encode(digest::digest(&digest::MD5, ha2_input.as_bytes()));
    
    // Response = MD5(HA1:nonce:HA2) or MD5(HA1:nonce:nc:cnonce:qop:HA2)
    let response_input = if let (Some(nc), Some(cnonce), Some(qop)) = (nc, cnonce, qop) {
        format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, qop, ha2)
    } else {
        format!("{}:{}:{}", ha1, nonce, ha2)
    };
    
    hex::encode(digest::digest(&digest::MD5, response_input.as_bytes()))
}

/// Verify digest authentication response
///
/// Verifies that the provided Authorization header matches the expected digest response.
///
/// # Arguments
///
/// * `auth_params` - Parsed Authorization header parameters
/// * `method` - SIP method from the request
/// * `uri` - Request-URI from the request
/// * `password` - User's password for verification
/// * `stored_nonce` - Nonce that was sent in the challenge
///
/// # Returns
///
/// Returns `Ok(true)` if authentication is valid, `Ok(false)` if invalid, or an error
pub fn verify_digest(
    auth_params: &HashMap<String, String>,
    method: &str,
    uri: &str,
    password: &str,
    stored_nonce: &str,
) -> Result<bool> {
    let username = auth_params
        .get("username")
        .ok_or_else(|| anyhow!("Missing username in Authorization header"))?;
    let realm = auth_params
        .get("realm")
        .ok_or_else(|| anyhow!("Missing realm in Authorization header"))?;
    let nonce = auth_params
        .get("nonce")
        .ok_or_else(|| anyhow!("Missing nonce in Authorization header"))?;
    let response = auth_params
        .get("response")
        .ok_or_else(|| anyhow!("Missing response in Authorization header"))?;
    
    // Verify nonce matches
    if nonce != stored_nonce {
        return Ok(false);
    }
    
    let nc = auth_params.get("nc");
    let cnonce = auth_params.get("cnonce");
    let qop = auth_params.get("qop");
    
    let computed_response = compute_digest_response(
        username, realm, password, method, uri, nonce, 
        nc.map(|s| s.as_str()), 
        cnonce.map(|s| s.as_str()), 
        qop.map(|s| s.as_str())
    );
    
    Ok(computed_response == *response)
}

/// Extract user from SIP request (From header or Authorization)
/// This parses the raw SIP message string since rsip Request API may vary
pub fn extract_user_from_request(request_str: &str) -> Result<String> {
    // Try to get from Authorization header first
    for line in request_str.lines() {
        if line.starts_with("Authorization:") || line.starts_with("Proxy-Authorization:") {
            let header_value = line.split(':').nth(1).unwrap_or("").trim();
            if let Ok(params) = parse_authorization(header_value) {
                if let Some(username) = params.get("username") {
                    return Ok(username.clone());
                }
            }
        }
    }
    
    // Fallback to From header
    for line in request_str.lines() {
        if line.starts_with("From:") {
            let from_value = line.split(':').nth(1).unwrap_or("").trim();
            // Parse SIP URI: <sip:user@domain> or sip:user@domain
            let uri = from_value.trim_matches('<').trim_matches('>');
            if let Some(colon_pos) = uri.find(':') {
                let after_colon = &uri[colon_pos + 1..];
                if let Some(at_pos) = after_colon.find('@') {
                    return Ok(after_colon[..at_pos].to_string());
                }
            }
        }
    }
    
    Err(anyhow!("Could not extract user from request"))
}

/// Extract URI from SIP request
pub fn extract_uri_from_request(request_str: &str) -> Result<String> {
    // Get Request-URI from first line: METHOD sip:uri SIP/2.0
    if let Some(first_line) = request_str.lines().next() {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 {
            return Ok(parts[1].to_string());
        }
    }
    Err(anyhow!("Could not extract URI from request"))
}

/// Extract header value from SIP request
pub fn extract_header(request_str: &str, header_name: &str) -> Option<String> {
    for line in request_str.lines() {
        if line.starts_with(&format!("{}:", header_name)) {
            return line.split(':').nth(1).map(|s| s.trim().to_string());
        }
    }
    None
}
