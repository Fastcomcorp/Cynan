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

//! Database Query Layer
//!
//! Provides type-safe database queries for HSS (Home Subscriber Server) operations.

use anyhow::Result;
use sqlx::{postgres::PgRow, FromRow, PgPool};
use uuid::Uuid;

use crate::state::Location;

/// User record from the database
#[derive(Debug, Clone, FromRow)]
pub struct User {
    /// User UUID
    pub id: Uuid,
    /// Username/IMPI
    pub username: String,
    /// Domain name
    pub domain: String,
    /// Password hash (for digest authentication)
    pub password_hash: String,
    /// International Mobile Subscriber Identity (optional)
    pub imsi: Option<String>,
    /// Mobile Station International Subscriber Directory Number (optional)
    pub msisdn: Option<String>,
}

/// User location binding record from the database
#[derive(Debug, Clone, FromRow)]
pub struct UserLocation {
    /// Location record UUID
    pub id: Uuid,
    /// User UUID (foreign key)
    pub user_id: Uuid,
    /// Contact URI (e.g., "sip:user@192.168.1.1:5060")
    pub contact_uri: String,
    /// Call-ID from REGISTER request (optional)
    pub call_id: Option<String>,
    /// CSeq value from REGISTER request
    pub cseq: i32,
    /// Expiration timestamp
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Last seen timestamp
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

impl UserLocation {
    pub fn to_location(&self) -> Location {
        Location {
            contact_uri: self.contact_uri.clone(),
            last_seen: self.last_seen.into(),
        }
    }
}

/// Database query helper functions
pub struct DatabaseQueries;

impl DatabaseQueries {
    /// Get user by username from the database
    ///
    /// # Arguments
    ///
    /// * `pool` - PostgreSQL connection pool
    /// * `username` - Username to lookup
    ///
    /// # Returns
    ///
    /// Returns `Some(User)` if found, `None` if not found, or an error
    pub async fn get_user(pool: &PgPool, username: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>(
            "SELECT id, username, domain, password_hash, imsi, msisdn FROM users WHERE username = $1"
        )
        .bind(username)
        .fetch_optional(pool)
        .await?;
        Ok(user)
    }

    /// Get user location bindings
    pub async fn get_user_locations(
        pool: &PgPool,
        user_id: &Uuid,
    ) -> Result<Vec<UserLocation>> {
        let locations = sqlx::query_as::<_, UserLocation>(
            "SELECT id, user_id, contact_uri, call_id, cseq, expires_at, last_seen 
             FROM user_locations 
             WHERE user_id = $1 AND expires_at > CURRENT_TIMESTAMP
             ORDER BY q_value DESC, expires_at DESC"
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        Ok(locations)
    }

    /// Insert or update user location
    pub async fn upsert_location(
        pool: &PgPool,
        user_id: &Uuid,
        contact_uri: &str,
        expires: i32,
    ) -> Result<()> {
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires as i64);
        
        sqlx::query(
            "INSERT INTO user_locations (user_id, contact_uri, expires_at, last_seen)
             VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
             ON CONFLICT (user_id, contact_uri) 
             DO UPDATE SET expires_at = $3, last_seen = CURRENT_TIMESTAMP"
        )
        .bind(user_id)
        .bind(contact_uri)
        .bind(expires_at)
        .execute(pool)
        .await?;
        
        Ok(())
    }

    /// Clean up expired locations
    pub async fn cleanup_expired_locations(pool: &PgPool) -> Result<u64> {
        let result = sqlx::query("DELETE FROM user_locations WHERE expires_at < CURRENT_TIMESTAMP")
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }
}
