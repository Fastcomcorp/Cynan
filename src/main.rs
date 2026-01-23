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

//! Cynan IMS Core - Main Entry Point
//!
//! This module provides the main entry point for the Cynan IMS Core application.
//! It initializes the SIP core engine and starts processing SIP messages.

mod as_integration;
mod bgcf;
mod config;
mod core;
mod diameter;
mod ibcf;
mod integration;
mod mgcf;
mod metrics;
mod modules;
mod rtp_router;
mod sip_arcrtc;
mod slf;
mod state;
mod tls_config;

use anyhow::Context;
use clap::Parser;
use config::CynanConfig;
use core::SipCore;

/// Command-line arguments for Cynan IMS Core
#[derive(Parser)]
#[command(name = "Cynan IMS Core", about = "Memory-safe SIP/IMS core in Rust")]
struct Args {
    /// Path to the configuration file (YAML)
    #[arg(short, long, default_value = "config/cynan.yaml")]
    config: String,
}

/// Main entry point for Cynan IMS Core
///
/// Initializes logging, loads configuration, and starts the SIP core engine.
/// The application runs until interrupted by a shutdown signal (SIGINT/SIGTERM).
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    let config =
        CynanConfig::load(&args.config).context("failed to load Cynan configuration")?;

    let core = SipCore::new(config).await?;
    core.run().await?;
    Ok(())
}
