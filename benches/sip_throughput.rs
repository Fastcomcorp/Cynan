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

//! Performance benchmarks for SIP message processing
//!
//! Run with: `cargo bench`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rsip::{SipMessage, request::Request};

fn parse_sip_message(c: &mut Criterion) {
    let sip_bytes = b"REGISTER sip:cynan.ims SIP/2.0\r\n\
                      Via: SIP/2.0/UDP 192.168.1.1:5060\r\n\
                      From: <sip:user@cynan.ims>\r\n\
                      To: <sip:user@cynan.ims>\r\n\
                      Call-ID: test-call-id\r\n\
                      CSeq: 1 REGISTER\r\n\
                      Contact: <sip:user@192.168.1.1:5060>\r\n\
                      Content-Length: 0\r\n\r\n";
    
    c.bench_function("parse_sip_request", |b| {
        b.iter(|| {
            let _ = SipMessage::try_from(black_box(sip_bytes.as_slice()));
        })
    });
}

fn serialize_sip_response(c: &mut Criterion) {
    use cynan::core::sip_utils::serialize_response;
    
    let response = rsip::Response::try_from(
        b"SIP/2.0 200 OK\r\n\
          Via: SIP/2.0/UDP 192.168.1.1:5060\r\n\
          From: <sip:user@cynan.ims>\r\n\
          To: <sip:user@cynan.ims>\r\n\
          Call-ID: test-call-id\r\n\
          CSeq: 1 REGISTER\r\n\
          Contact: <sip:user@192.168.1.1:5060>\r\n\
          Content-Length: 0\r\n\r\n".as_ref()
    ).unwrap();
    
    c.bench_function("serialize_sip_response", |b| {
        b.iter(|| {
            let _ = serialize_response(black_box(&response));
        })
    });
}

criterion_group!(benches, parse_sip_message, serialize_sip_response);
criterion_main!(benches);
