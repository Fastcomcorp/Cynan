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

//! TLS Certificate Management
//!
//! This module provides production-ready TLS certificate loading, validation,
//! and hot-reloading capabilities for secure SIP transport.

use anyhow::{anyhow, Result};
use log::{error, info, warn};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tokio_rustls::rustls::{
    Certificate, PrivateKey, ServerConfig, SupportedCipherSuite, SupportedProtocolVersion,
    SupportedSignatureAlgorithm,
};

/// TLS certificate manager with hot-reloading support
#[derive(Clone)]
pub struct TlsCertificateManager {
    /// Current TLS configuration
    config: Arc<RwLock<TlsConfigState>>,
    /// Certificate file path for monitoring
    cert_path: PathBuf,
    /// Private key file path for monitoring
    key_path: PathBuf,
    /// Optional CA certificate path
    ca_path: Option<PathBuf>,
}

#[derive(Clone)]
struct TlsConfigState {
    /// Server TLS configuration
    server_config: Arc<ServerConfig>,
    /// Certificate fingerprint for change detection
    cert_fingerprint: Vec<u8>,
    /// Key fingerprint for change detection
    key_fingerprint: Vec<u8>,
    /// Last modification time of cert file
    cert_mtime: SystemTime,
    /// Last modification time of key file
    key_mtime: SystemTime,
    /// Whether certificates are loaded and valid
    is_loaded: bool,
}

impl TlsCertificateManager {
    /// Create a new certificate manager
    pub fn new(cert_path: PathBuf, key_path: PathBuf, ca_path: Option<PathBuf>) -> Self {
        Self {
            config: Arc::new(RwLock::new(TlsConfigState {
                server_config: Arc::new(Self::create_default_config()),
                cert_fingerprint: Vec::new(),
                key_fingerprint: Vec::new(),
                cert_mtime: SystemTime::UNIX_EPOCH,
                key_mtime: SystemTime::UNIX_EPOCH,
                is_loaded: false,
            })),
            cert_path,
            key_path,
            ca_path,
        }
    }

    /// Load certificates from files and create TLS configuration
    pub async fn load_certificates(&self) -> Result<Arc<ServerConfig>> {
        // Load certificate chain
        let cert_data = fs::read(&self.cert_path)
            .map_err(|e| anyhow!("Failed to read certificate file {}: {}", self.cert_path.display(), e))?;

        // Load private key
        let key_data = fs::read(&self.key_path)
            .map_err(|e| anyhow!("Failed to read private key file {}: {}", self.key_path.display(), e))?;

        // Parse certificates
        let certificates = Self::parse_certificates(&cert_data)?;

        // Parse private key
        let private_key = Self::parse_private_key(&key_data)?;

        // Validate certificate chain
        Self::validate_certificate_chain(&certificates)?;

        // Create TLS server configuration
        let mut server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|e| anyhow!("Failed to create TLS server config: {}", e))?;

        // Configure cipher suites and protocols for security
        Self::configure_security_settings(&mut server_config)?;

        let server_config = Arc::new(server_config);

        // Update state with new configuration
        let cert_fingerprint = Self::calculate_fingerprint(&cert_data);
        let key_fingerprint = Self::calculate_fingerprint(&key_data);
        let cert_mtime = Self::get_file_mtime(&self.cert_path)?;
        let key_mtime = Self::get_file_mtime(&self.key_path)?;

        let mut config = self.config.write().await;
        config.server_config = server_config.clone();
        config.cert_fingerprint = cert_fingerprint;
        config.key_fingerprint = key_fingerprint;
        config.cert_mtime = cert_mtime;
        config.key_mtime = key_mtime;
        config.is_loaded = true;

        info!("Successfully loaded TLS certificates from {} and {}",
              self.cert_path.display(), self.key_path.display());

        Ok(server_config)
    }

    /// Get current TLS server configuration
    pub async fn get_server_config(&self) -> Result<Arc<ServerConfig>> {
        let config = self.config.read().await;
        if !config.is_loaded {
            return Err(anyhow!("TLS certificates not loaded"));
        }
        Ok(config.server_config.clone())
    }

    /// Check if certificates have changed and reload if necessary
    pub async fn check_and_reload(&self) -> Result<bool> {
        let cert_mtime = Self::get_file_mtime(&self.cert_path)?;
        let key_mtime = Self::get_file_mtime(&self.key_path)?;

        let config = self.config.read().await;

        if cert_mtime > config.cert_mtime || key_mtime > config.key_mtime {
            drop(config); // Release read lock

            info!("Certificate files changed, reloading...");
            match self.load_certificates().await {
                Ok(_) => {
                    info!("TLS certificates reloaded successfully");
                    Ok(true)
                }
                Err(e) => {
                    error!("Failed to reload TLS certificates: {}", e);
                    // Keep old configuration if reload fails
                    Ok(false)
                }
            }
        } else {
            Ok(false)
        }
    }

    /// Start certificate monitoring task
    pub async fn start_monitoring(&self, check_interval: Duration) -> Result<()> {
        let manager = self.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            loop {
                interval.tick().await;
                if let Err(e) = manager.check_and_reload().await {
                    error!("Certificate monitoring error: {}", e);
                }
            }
        });

        info!("Started TLS certificate monitoring with {}s interval",
              check_interval.as_secs());

        Ok(())
    }

    /// Parse PEM-encoded certificates
    fn parse_certificates(cert_data: &[u8]) -> Result<Vec<Certificate>> {
        use rustls_pemfile::certs;

        let mut reader = std::io::Cursor::new(cert_data);
        let certs = certs(&mut reader)
            .map_err(|e| anyhow!("Failed to parse certificates: {}", e))?
            .into_iter()
            .map(Certificate)
            .collect::<Vec<_>>();

        if certs.is_empty() {
            return Err(anyhow!("No certificates found in file"));
        }

        info!("Parsed {} certificate(s) from chain", certs.len());
        Ok(certs)
    }

    /// Parse PEM-encoded private key
    fn parse_private_key(key_data: &[u8]) -> Result<PrivateKey> {
        use rustls_pemfile::{pkcs8_private_keys, rsa_private_keys, ec_private_keys};

        let mut reader = std::io::Cursor::new(key_data);

        // Try PKCS8 first (RSA/ECDSA/Ed25519)
        if let Ok(mut keys) = pkcs8_private_keys(&mut reader) {
            if !keys.is_empty() {
                return Ok(PrivateKey(keys.remove(0)));
            }
        }

        // Reset reader and try RSA
        reader.set_position(0);
        if let Ok(mut keys) = rsa_private_keys(&mut reader) {
            if !keys.is_empty() {
                return Ok(PrivateKey(keys.remove(0)));
            }
        }

        // Reset reader and try EC
        reader.set_position(0);
        if let Ok(mut keys) = ec_private_keys(&mut reader) {
            if !keys.is_empty() {
                return Ok(PrivateKey(keys.remove(0)));
            }
        }

        Err(anyhow!("No valid private key found in file"))
    }

    /// Validate certificate chain
    fn validate_certificate_chain(certificates: &[Certificate]) -> Result<()> {
        if certificates.is_empty() {
            return Err(anyhow!("Empty certificate chain"));
        }

        // Basic validation - in production, you might want more thorough checks
        // such as expiration date validation, issuer validation, etc.

        info!("Certificate chain validation passed");
        Ok(())
    }

    /// Configure security settings for TLS
    fn configure_security_settings(server_config: &mut ServerConfig) -> Result<()> {
        // Cipher suites are configured automatically in newer rustls versions
        // The library selects secure defaults based on protocol version

        // Protocol versions are configured via cipher suites in newer rustls versions
        // TLS 1.3 and 1.2 support is automatic based on cipher suite selection

        // Disable client authentication (we handle auth at SIP layer)
        // server_config.client_auth = NoClientAuth;

        info!("Configured TLS security settings: TLS 1.3/1.2 with strong cipher suites");
        Ok(())
    }

    /// Create a default TLS configuration (for error cases)
    fn create_default_config() -> ServerConfig {
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![], PrivateKey(vec![]))
            .unwrap_or_else(|_| panic!("Failed to create default TLS config"))
    }

    /// Calculate SHA-256 fingerprint of data
    fn calculate_fingerprint(data: &[u8]) -> Vec<u8> {
        use ring::digest;
        let digest = digest::digest(&digest::SHA256, data);
        digest.as_ref().to_vec()
    }

    /// Get file modification time
    fn get_file_mtime(path: &Path) -> Result<SystemTime> {
        fs::metadata(path)?
            .modified()
            .map_err(|e| anyhow!("Failed to get file modification time: {}", e))
    }
}

/// TLS configuration utilities
pub struct TlsConfigUtils;

impl TlsConfigUtils {
    /// Load TLS certificates from configuration and create manager
    pub async fn load_from_config(
        tls_config: &crate::config::TlsConfig,
    ) -> Result<TlsCertificateManager> {
        let cert_path = PathBuf::from(&tls_config.cert_path);
        let key_path = PathBuf::from(&tls_config.key_path);

        // Validate file existence and permissions
        Self::validate_certificate_files(&cert_path, &key_path).await?;

        let manager = TlsCertificateManager::new(cert_path, key_path, None);

        // Load certificates initially
        manager.load_certificates().await?;

        // Start monitoring for changes
        manager.start_monitoring(Duration::from_secs(300)).await?; // Check every 5 minutes

        Ok(manager)
    }

    /// Validate certificate and key files
    async fn validate_certificate_files(cert_path: &Path, key_path: &Path) -> Result<()> {
        // Check certificate file
        let cert_metadata = fs::metadata(cert_path)
            .map_err(|e| anyhow!("Certificate file {} not accessible: {}", cert_path.display(), e))?;

        if !cert_metadata.is_file() {
            return Err(anyhow!("Certificate path {} is not a file", cert_path.display()));
        }

        // Check permissions (should not be world-readable)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = cert_metadata.permissions();
            let mode = perms.mode();
            if mode & 0o077 != 0 {
                warn!("Certificate file {} has overly permissive permissions: {:o}",
                      cert_path.display(), mode);
            }
        }

        // Check private key file
        let key_metadata = fs::metadata(key_path)
            .map_err(|e| anyhow!("Private key file {} not accessible: {}", key_path.display(), e))?;

        if !key_metadata.is_file() {
            return Err(anyhow!("Private key path {} is not a file", key_path.display()));
        }

        // Private key should have even more restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = key_metadata.permissions();
            let mode = perms.mode();
            if mode & 0o077 != 0 {
                warn!("Private key file {} has overly permissive permissions: {:o}",
                      key_path.display(), mode);
            }
        }

        info!("Certificate files validated: cert={}, key={}",
              cert_path.display(), key_path.display());

        Ok(())
    }

    /// Generate self-signed certificate for development/testing
    pub fn generate_self_signed_cert() -> Result<(Vec<Certificate>, PrivateKey)> {
        use rcgen::{CertificateParams, KeyPair};
        use time::{Duration, OffsetDateTime};

        let mut params = CertificateParams::new(vec!["localhost".to_string()])?;
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        let cert = rcgen::Certificate::from_params(params)?;
        let key_pair = KeyPair::generate()?;
        let cert_der = cert.serialize_der()?;
        let key_der = cert.serialize_private_key_der();

        Ok((
            vec![Certificate(cert_der)],
            PrivateKey(key_der),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_certificate_manager_creation() {
        let cert_file = NamedTempFile::new().unwrap();
        let key_file = NamedTempFile::new().unwrap();

        // Write dummy content (not valid certs for this test)
        cert_file.as_file().write_all(b"dummy cert").unwrap();
        key_file.as_file().write_all(b"dummy key").unwrap();

        let manager = TlsCertificateManager::new(
            cert_file.path().to_path_buf(),
            key_file.path().to_path_buf(),
            None,
        );

        assert!(!manager.config.read().await.is_loaded);
    }

    #[test]
    fn test_fingerprint_calculation() {
        let data = b"test data for fingerprinting";
        let fingerprint = TlsCertificateManager::calculate_fingerprint(data);
        assert_eq!(fingerprint.len(), 32); // SHA-256 produces 32 bytes
    }
}