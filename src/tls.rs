//! Dynamic TLS Certificate Module
//!
//! This module provides dynamic TLS certificate loading for hot-reload support.
//! When certificates are renewed via ACME, new connections automatically use the
//! updated certificates without requiring a server restart.

use async_trait::async_trait;
use log::{debug, error, warn};
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::SslRef;
use pingora::tls::x509::X509;
use std::sync::Arc;

use crate::acme::CertStore;

/// Dynamic certificate provider that implements TlsAccept
/// 
/// This struct reads certificates from a shared CertStore on each TLS handshake,
/// enabling hot-reload of certificates when they are renewed.
pub struct DynamicCert {
    cert_store: Arc<CertStore>,
    /// Fallback certificate for when CertStore is empty
    fallback_cert: Option<X509>,
    fallback_key: Option<PKey<Private>>,
}

impl DynamicCert {
    /// Create a new DynamicCert with a reference to the shared CertStore
    pub fn new(cert_store: Arc<CertStore>) -> Box<Self> {
        Box::new(Self {
            cert_store,
            fallback_cert: None,
            fallback_key: None,
        })
    }

    /// Create a new DynamicCert with fallback certificate files
    /// 
    /// The fallback certificates are used if the CertStore is empty.
    pub fn with_fallback(
        cert_store: Arc<CertStore>,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Box<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let cert_bytes = std::fs::read(cert_path)?;
        let cert = X509::from_pem(&cert_bytes)?;

        let key_bytes = std::fs::read(key_path)?;
        let key = PKey::private_key_from_pem(&key_bytes)?;

        Ok(Box::new(Self {
            cert_store,
            fallback_cert: Some(cert),
            fallback_key: Some(key),
        }))
    }

    /// Load certificate and key from PEM strings
    fn load_from_pem(
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(X509, PKey<Private>), Box<dyn std::error::Error + Send + Sync>> {
        let cert = X509::from_pem(cert_pem.as_bytes())?;
        let key = PKey::private_key_from_pem(key_pem.as_bytes())?;
        Ok((cert, key))
    }
}

#[async_trait]
impl pingora::listeners::TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        // Try to load certificate from CertStore first
        let cert_guard = self.cert_store.load();
        
        let result = if let Some(cert_pair) = &**cert_guard {
            // Use certificate from CertStore (hot-reloadable)
            debug!("Using certificate from CertStore (expires: {})", cert_pair.expires_at);
            Self::load_from_pem(&cert_pair.cert_pem, &cert_pair.key_pem)
        } else {
            // Fall back to static certificate if available
            if let (Some(cert), Some(key)) = (&self.fallback_cert, &self.fallback_key) {
                debug!("Using fallback certificate");
                if let Err(e) = ext::ssl_use_certificate(ssl, cert) {
                    error!("Failed to set fallback certificate: {}", e);
                    return;
                }
                if let Err(e) = ext::ssl_use_private_key(ssl, key) {
                    error!("Failed to set fallback private key: {}", e);
                    return;
                }
                return;
            } else {
                warn!("No certificate available in CertStore and no fallback configured");
                return;
            }
        };

        // Apply the loaded certificate and key
        match result {
            Ok((cert, key)) => {
                if let Err(e) = ext::ssl_use_certificate(ssl, &cert) {
                    error!("Failed to set certificate: {}", e);
                    return;
                }
                if let Err(e) = ext::ssl_use_private_key(ssl, &key) {
                    error!("Failed to set private key: {}", e);
                    return;
                }
                debug!("Certificate callback completed successfully");
            }
            Err(e) => {
                error!("Failed to load certificate from PEM: {}", e);
                // Try fallback if available
                if let (Some(cert), Some(key)) = (&self.fallback_cert, &self.fallback_key) {
                    warn!("Falling back to static certificate");
                    if let Err(e) = ext::ssl_use_certificate(ssl, cert) {
                        error!("Failed to set fallback certificate: {}", e);
                        return;
                    }
                    if let Err(e) = ext::ssl_use_private_key(ssl, key) {
                        error!("Failed to set fallback private key: {}", e);
                    }
                }
            }
        }
    }
}
