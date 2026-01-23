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

//! Shared State Management
//!
//! This module provides thread-safe shared state for the IMS core, including
//! in-memory location storage and database connection pooling.

pub mod db;

use crate::config::DatabaseConfig;
use anyhow::Result;
use dashmap::DashMap;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{sync::Arc, time::SystemTime};
use uuid::Uuid;

/// Shared state container accessible across all IMS modules
///
/// Provides thread-safe access to:
/// - User location bindings (in-memory cache)
/// - Database connection pool for HSS queries
#[derive(Clone)]
pub struct SharedState {
    inner: Arc<State>,
}

impl SharedState {
    pub async fn build(db_config: &DatabaseConfig) -> Result<Self> {
        let database = DatabaseLayer::connect(db_config).await?;

        Ok(SharedState {
            inner: Arc::new(State {
                user_locations: DashMap::new(),
                database,
            }),
        })
    }

    pub fn insert_location(&self, user: Uuid, contact: Location) {
        self.inner.user_locations.insert(user, contact);
    }

    pub fn get_location(&self, user: &Uuid) -> Option<Location> {
        self.inner
            .user_locations
            .get(user)
            .map(|entry| entry.value().clone())
    }

    pub fn pool(&self) -> &PgPool {
        &self.inner.database.pool
    }
}

pub struct State {
    user_locations: DashMap<Uuid, Location>,
    database: DatabaseLayer,
}

/// Encapsulates the async SQLx connection pool for HSS/PCRF interactions.
pub struct DatabaseLayer {
    pub pool: PgPool,
}

impl DatabaseLayer {
    pub async fn connect(config: &DatabaseConfig) -> Result<Self> {
        let conn_str = format!(
            "postgres://{}:{}@{}:{}/{}",
            config.user, config.password, config.host, config.port, config.name
        );
        let pool = PgPoolOptions::new().max_connections(5).connect(&conn_str).await?;
        Ok(DatabaseLayer { pool })
    }
}

/// User location binding information
///
/// Represents a SIP contact binding for a user, storing the contact URI
/// and timestamp of last registration.
#[derive(Debug, Clone)]
pub struct Location {
    /// SIP contact URI (e.g., "sip:user@192.168.1.1:5060")
    pub contact_uri: String,
    /// Timestamp when this binding was last seen/updated
    pub last_seen: SystemTime,
}
