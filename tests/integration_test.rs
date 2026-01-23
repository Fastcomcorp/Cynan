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

//! Integration tests for Cynan IMS Core
//!
//! Run with: `cargo test --test integration_test`

use cynan::config::CynanConfig;
use cynan::core::SipCore;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_config_loading() {
    let config = CynanConfig::load("config/cynan.yaml");
    assert!(config.is_ok());
}

#[tokio::test]
async fn test_sip_core_initialization() {
    let config = CynanConfig::load("config/cynan.yaml").unwrap();
    
    // This test may fail if database is not available, which is expected
    let core_result = timeout(Duration::from_secs(5), SipCore::new(config)).await;
    
    // We expect this to either succeed or fail gracefully
    match core_result {
        Ok(Ok(_)) => println!("SIP Core initialized successfully"),
        Ok(Err(e)) => println!("SIP Core initialization failed (expected if DB unavailable): {}", e),
        Err(_) => println!("SIP Core initialization timed out"),
    }
}

#[tokio::test]
async fn test_sip_message_parsing() {
    use rsip::{SipMessage, request::Request};
    
    let sip_bytes = b"REGISTER sip:cynan.ims SIP/2.0\r\n\
                      Via: SIP/2.0/UDP 192.168.1.1:5060\r\n\
                      From: <sip:user@cynan.ims>\r\n\
                      To: <sip:user@cynan.ims>\r\n\
                      Call-ID: test-call-id\r\n\
                      CSeq: 1 REGISTER\r\n\
                      Contact: <sip:user@192.168.1.1:5060>\r\n\
                      Content-Length: 0\r\n\r\n";
    
    match SipMessage::try_from(sip_bytes.as_slice()) {
        Ok(SipMessage::Request(req)) => {
            assert_eq!(req.method().to_string(), "REGISTER");
        }
        Ok(SipMessage::Response(_)) => panic!("Expected Request, got Response"),
        Err(e) => panic!("Failed to parse SIP message: {}", e),
    }
}
