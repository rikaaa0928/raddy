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

}

#[async_trait]
impl pingora::listeners::TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        // Extract SNI (Server Name Indication) from the SSL context
        let sni = ssl.servername(pingora::tls::ssl::NameType::HOST_NAME)
            .map(|s| s.to_string());
        
        debug!("TLS handshake with SNI: {:?}", sni);

        // Use pre-parsed certificate objects (parsed once at store time)
        let parsed = if let Some(ref domain) = sni {
            self.cert_store.get_parsed_for_domain_or_default(domain)
        } else {
            self.cert_store.get_default_parsed()
        };

        match parsed {
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
                debug!("Certificate callback completed successfully for SNI {:?} (chain certs: {})", sni, cert.chain_certs.len());
            }
            None => {
                warn!("No certificate found for SNI {:?}, trying fallback", sni);
                self.apply_fallback(ssl);
            }
        }
    }
}

impl DynamicCert {
    /// Apply fallback certificate if available
    fn apply_fallback(&self, ssl: &mut SslRef) {
        if let (Some(cert), Some(key)) = (&self.fallback_cert, &self.fallback_key) {
            debug!("Using fallback certificate");
            if let Err(e) = ext::ssl_use_certificate(ssl, cert) {
                error!("Failed to set fallback certificate: {}", e);
                return;
            }
            if let Err(e) = ext::ssl_use_private_key(ssl, key) {
                error!("Failed to set fallback private key: {}", e);
            }
        } else {
            warn!("No certificate available and no fallback configured");
        }
    }
}
