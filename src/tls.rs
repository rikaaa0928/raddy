//! Dynamic TLS Certificate Module
//!
//! This module provides dynamic TLS certificate loading for hot-reload support.
//! When certificates are renewed via ACME, new connections automatically use the
//! updated certificates without requiring a server restart.

use async_trait::async_trait;
use log::{debug, error, warn};
use pingora::tls::ext;
use pingora::tls::ssl::SslRef;
use std::sync::Arc;

use crate::acme::CertStore;

/// Dynamic certificate provider that implements TlsAccept
///
/// This struct reads certificates from a shared CertStore on each TLS handshake,
/// enabling hot-reload of certificates when they are renewed.
pub struct DynamicCert {
    cert_store: Arc<CertStore>,
}

impl DynamicCert {
    /// Create a new DynamicCert with a reference to the shared CertStore
    pub fn new(cert_store: Arc<CertStore>) -> Box<Self> {
        Box::new(Self { cert_store })
    }
}

#[async_trait]
impl pingora::listeners::TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        // Extract SNI (Server Name Indication) from the SSL context
        let sni = ssl
            .servername(pingora::tls::ssl::NameType::HOST_NAME)
            .map(|s| s.to_string());

        debug!("TLS handshake with SNI: {:?}", sni);

        let Some(domain) = sni.as_deref() else {
            warn!("TLS handshake rejected: missing SNI");
            return;
        };

        match self.cert_store.get_parsed_for_domain(domain) {
            Some(cert) => {
                if let Err(e) = ext::ssl_use_certificate(ssl, &cert.leaf_cert) {
                    error!("Failed to set certificate: {}", e);
                    return;
                }
                for chain_cert in &cert.chain_certs {
                    if let Err(e) = ext::ssl_add_chain_cert(ssl, chain_cert) {
                        error!("Failed to add chain certificate: {}", e);
                        return;
                    }
                }
                if let Err(e) = ext::ssl_use_private_key(ssl, &cert.private_key) {
                    error!("Failed to set private key: {}", e);
                    return;
                }
                debug!(
                    "Certificate callback completed successfully for SNI {:?} (chain certs: {})",
                    sni,
                    cert.chain_certs.len()
                );
            }
            None => {
                warn!("TLS handshake rejected: no certificate configured for SNI {domain}");
            }
        }
    }
}
