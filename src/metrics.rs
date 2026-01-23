//! Metrics and monitoring for Cynan IMS Core
//! Provides Prometheus-compatible metrics

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct Metrics {
    pub sip_requests_total: Arc<AtomicU64>,
    pub sip_responses_total: Arc<AtomicU64>,
    pub sip_errors_total: Arc<AtomicU64>,
    pub register_requests: Arc<AtomicU64>,
    pub invite_requests: Arc<AtomicU64>,
    pub active_sessions: Arc<AtomicU64>,
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            sip_requests_total: Arc::new(AtomicU64::new(0)),
            sip_responses_total: Arc::new(AtomicU64::new(0)),
            sip_errors_total: Arc::new(AtomicU64::new(0)),
            register_requests: Arc::new(AtomicU64::new(0)),
            invite_requests: Arc::new(AtomicU64::new(0)),
            active_sessions: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn increment_requests(&self) {
        self.sip_requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_responses(&self) {
        self.sip_responses_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_errors(&self) {
        self.sip_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_register(&self) {
        self.register_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_invite(&self) {
        self.invite_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Export metrics in Prometheus text format
    ///
    /// Returns a string containing all metrics in Prometheus exposition format,
    /// suitable for serving via HTTP endpoint.
    ///
    /// # Returns
    ///
    /// Returns a formatted string with Prometheus metrics
    pub fn export_prometheus(&self) -> String {
        format!(
            "# HELP cynan_sip_requests_total Total number of SIP requests\n\
             # TYPE cynan_sip_requests_total counter\n\
             cynan_sip_requests_total {}\n\
             # HELP cynan_sip_responses_total Total number of SIP responses\n\
             # TYPE cynan_sip_responses_total counter\n\
             cynan_sip_responses_total {}\n\
             # HELP cynan_sip_errors_total Total number of SIP errors\n\
             # TYPE cynan_sip_errors_total counter\n\
             cynan_sip_errors_total {}\n\
             # HELP cynan_register_requests Total number of REGISTER requests\n\
             # TYPE cynan_register_requests counter\n\
             cynan_register_requests {}\n\
             # HELP cynan_invite_requests Total number of INVITE requests\n\
             # TYPE cynan_invite_requests counter\n\
             cynan_invite_requests {}\n\
             # HELP cynan_active_sessions Current number of active sessions\n\
             # TYPE cynan_active_sessions gauge\n\
             cynan_active_sessions {}\n",
            self.sip_requests_total.load(Ordering::Relaxed),
            self.sip_responses_total.load(Ordering::Relaxed),
            self.sip_errors_total.load(Ordering::Relaxed),
            self.register_requests.load(Ordering::Relaxed),
            self.invite_requests.load(Ordering::Relaxed),
            self.active_sessions.load(Ordering::Relaxed),
        )
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
