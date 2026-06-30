//! ACME Certificate Manager
//!
//! This module provides automatic SSL certificate acquisition and renewal
//! using the ACME protocol (Let's Encrypt compatible).

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use log::{debug, error, info, warn};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::sleep;

use crate::config::AcmeCertSource;

/// Certificate and key pair with expiration info
#[derive(Clone)]
pub struct CertKeyPair {
    pub cert_pem: String,
    pub key_pem: String,
    pub expires_at: DateTime<Utc>,
}

impl CertKeyPair {
    /// Check if certificate needs renewal
    pub fn needs_renewal(&self, renew_before_days: u32) -> bool {
        let renew_threshold = Utc::now() + Duration::days(renew_before_days as i64);
        self.expires_at <= renew_threshold
    }

    /// Load certificate from PEM files
    pub fn load_from_files(
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;

        // Parse certificate to get expiration
        let expires_at = Self::parse_cert_expiry(&cert_pem)?;

        Ok(Self {
            cert_pem,
            key_pem,
            expires_at,
        })
    }

    /// Parse certificate expiration from PEM
    fn parse_cert_expiry(
        cert_pem: &str,
    ) -> Result<DateTime<Utc>, Box<dyn std::error::Error + Send + Sync>> {
        let pem_data = pem::parse(cert_pem)?;
        let (_, cert) = x509_parser::parse_x509_certificate(pem_data.contents())?;
        let not_after = cert.validity().not_after.to_datetime();
        // Use DateTime::from_timestamp instead of deprecated from_timestamp_opt
        Ok(DateTime::from_timestamp(not_after.unix_timestamp(), 0).unwrap_or_else(|| Utc::now()))
    }

    /// Save certificate and key to files
    pub fn save_to_files(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        std::fs::write(cert_path, &self.cert_pem)?;
        std::fs::write(key_path, &self.key_pem)?;
        Ok(())
    }

    /// Extract domains (SANs) from certificate
    pub fn get_domains(&self) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let pem_data = pem::parse(&self.cert_pem)?;
        let (_, cert) = x509_parser::parse_x509_certificate(pem_data.contents())?;

        let mut domains = Vec::new();

        // Get Subject Alternative Names
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                if let x509_parser::prelude::GeneralName::DNSName(dns) = name {
                    domains.push(dns.to_string());
                }
            }
        }

        // If no SANs, try to get CN from subject
        if domains.is_empty() {
            for rdn in cert.subject().iter_rdn() {
                for attr in rdn.iter() {
                    if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
                        if let Ok(cn) = attr.as_str() {
                            domains.push(cn.to_string());
                        }
                    }
                }
            }
        }

        Ok(domains)
    }

    /// Check if certificate covers all required domains
    pub fn covers_domains(&self, required_domains: &[String]) -> bool {
        match self.get_domains() {
            Ok(cert_domains) => {
                let cert_set: std::collections::HashSet<_> = cert_domains.iter().collect();
                required_domains.iter().all(|d| cert_set.contains(d))
            }
            Err(_) => false,
        }
    }
}

/// Pre-parsed OpenSSL certificate objects for efficient TLS handshakes.
/// Avoids re-parsing PEM text on every TLS connection.
pub struct ParsedCert {
    pub leaf_cert: X509,
    pub chain_certs: Vec<X509>,
    pub private_key: PKey<Private>,
}

impl ParsedCert {
    /// Parse certificate chain and private key from PEM strings
    pub fn from_pem(
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let certs = X509::stack_from_pem(cert_pem.as_bytes())?;
        if certs.is_empty() {
            return Err("No certificates found in PEM".into());
        }
        let leaf_cert = certs[0].clone();
        let chain_certs: Vec<X509> = certs.into_iter().skip(1).collect();
        let private_key = PKey::private_key_from_pem(key_pem.as_bytes())?;
        Ok(Self {
            leaf_cert,
            chain_certs,
            private_key,
        })
    }
}

/// Thread-safe certificate store with atomic updates
///
/// Supports domain-indexed certificate storage for SNI-based certificate selection.
/// Certificates are parsed into OpenSSL objects once at store time and cached
/// to avoid expensive PEM re-parsing on every TLS handshake.
pub struct CertStore {
    /// Domain-indexed certificate storage (PEM data for persistence)
    certs: ArcSwap<HashMap<String, Arc<CertKeyPair>>>,
    /// Default certificate for when no domain-specific cert is found
    default_cert: ArcSwap<Option<Arc<CertKeyPair>>>,
    /// Cached pre-parsed certificates per domain
    parsed_certs: ArcSwap<HashMap<String, Arc<ParsedCert>>>,
    /// Cached pre-parsed default certificate
    default_parsed: ArcSwap<Option<Arc<ParsedCert>>>,
}

impl CertStore {
    pub fn new() -> Self {
        Self {
            certs: ArcSwap::from_pointee(HashMap::new()),
            default_cert: ArcSwap::from_pointee(None),
            parsed_certs: ArcSwap::from_pointee(HashMap::new()),
            default_parsed: ArcSwap::from_pointee(None),
        }
    }

    /// Load the default certificate (legacy API)
    pub fn load(&self) -> arc_swap::Guard<Arc<Option<Arc<CertKeyPair>>>> {
        self.default_cert.load()
    }

    /// Store a certificate for specific domains
    pub fn store_for_domains(&self, domains: &[String], cert: CertKeyPair) {
        self.store_shared_for_domains(domains, Arc::new(cert));
    }

    /// Store a shared certificate for specific domains without duplicating PEM data.
    pub fn store_shared_for_domains(&self, domains: &[String], cert: Arc<CertKeyPair>) {
        // Pre-parse once, share across all domains via Arc
        let parsed = match ParsedCert::from_pem(&cert.cert_pem, &cert.key_pem) {
            Ok(p) => Some(Arc::new(p)),
            Err(e) => {
                warn!("Failed to pre-parse certificate for {:?}: {}", domains, e);
                None
            }
        };

        // Store PEM data
        let mut certs = (**self.certs.load()).clone();
        for domain in domains {
            certs.insert(domain.clone(), cert.clone());
        }
        self.certs.store(Arc::new(certs));

        // Store parsed data (shared via Arc, no duplication)
        if let Some(ref parsed) = parsed {
            let mut parsed_map = (**self.parsed_certs.load()).clone();
            for domain in domains {
                parsed_map.insert(domain.clone(), parsed.clone());
            }
            self.parsed_certs.store(Arc::new(parsed_map));
        }

        // Also set as default if no default exists
        if self.default_cert.load().is_none() {
            self.default_cert.store(Arc::new(Some(cert)));
            if let Some(parsed) = parsed {
                self.default_parsed.store(Arc::new(Some(parsed)));
            }
        }
    }

    /// Get certificate for a specific domain
    pub fn get_for_domain(&self, domain: &str) -> Option<Arc<CertKeyPair>> {
        let certs = self.certs.load();
        certs.get(domain).cloned()
    }

    /// Get pre-parsed certificate for a domain, falling back to default.
    /// This avoids PEM re-parsing on every TLS handshake.
    pub fn get_parsed_for_domain_or_default(&self, domain: &str) -> Option<Arc<ParsedCert>> {
        let parsed = self.parsed_certs.load();
        if let Some(cert) = parsed.get(domain) {
            return Some(cert.clone());
        }
        (**self.default_parsed.load()).clone()
    }

    /// Get pre-parsed default certificate
    pub fn get_default_parsed(&self) -> Option<Arc<ParsedCert>> {
        (**self.default_parsed.load()).clone()
    }
}

/// HTTP-01 challenge token store for ACME validation
pub struct ChallengeStore {
    tokens: RwLock<HashMap<String, String>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
        }
    }

    pub async fn set(&self, token: String, key_auth: String) {
        let mut tokens = self.tokens.write().await;
        tokens.insert(token, key_auth);
    }

    pub async fn get(&self, token: &str) -> Option<String> {
        let tokens = self.tokens.read().await;
        tokens.get(token).cloned()
    }

    pub async fn remove(&self, token: &str) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(token);
    }
}

/// Internal configuration for ACME Certificate Manager
/// Combines AcmeCertSource with the domains to manage
#[derive(Clone)]
pub struct AcmeManagerConfig {
    /// Contact email for ACME account
    pub email: String,
    /// Domain names to request certificates for
    pub domains: Vec<String>,
    /// ACME directory URL
    pub directory_url: String,
    /// Directory to store certificates
    pub cert_dir: String,
    /// Days before expiration to renew certificate
    pub renew_before_days: u32,
    /// Use staging environment
    pub staging: bool,
}

impl AcmeManagerConfig {
    /// Create from AcmeCertSource and domains
    pub fn from_source(source: &AcmeCertSource, domains: Vec<String>) -> Self {
        Self {
            email: source.email.clone(),
            domains,
            directory_url: source.directory_url.clone(),
            cert_dir: source.cert_dir.clone(),
            renew_before_days: source.renew_before_days,
            staging: source.staging,
        }
    }
}

/// ACME Certificate Manager
///
/// Handles certificate acquisition, renewal, and hot-reload coordination.
pub struct CertificateManager {
    pub config: AcmeManagerConfig,
    cert_store: Arc<CertStore>,
    challenge_store: Arc<ChallengeStore>,
    account: Option<Account>,
}

impl CertificateManager {
    /// Create a new certificate manager
    pub fn new(
        config: AcmeManagerConfig,
        cert_store: Arc<CertStore>,
        challenge_store: Arc<ChallengeStore>,
    ) -> Self {
        Self {
            config,
            cert_store,
            challenge_store,
            account: None,
        }
    }

    /// Get the certificate store for use with GlobalCertificate
    pub fn renew_before_days(&self) -> u32 {
        self.config.renew_before_days
    }

    pub fn domains(&self) -> &[String] {
        &self.config.domains
    }

    pub fn current_cert(&self) -> Option<Arc<CertKeyPair>> {
        self.config
            .domains
            .iter()
            .find_map(|domain| self.cert_store.get_for_domain(domain))
            .or_else(|| (**self.cert_store.load()).clone())
    }

    pub fn needs_certificate(&self) -> bool {
        match self.current_cert() {
            Some(cert) => cert.needs_renewal(self.renew_before_days()),
            None => true,
        }
    }

    /// Try to load existing certificate from disk
    pub fn load_existing_cert(
        &self,
    ) -> Result<Option<CertKeyPair>, Box<dyn std::error::Error + Send + Sync>> {
        let cert_path = format!("{}/cert.pem", self.config.cert_dir);
        let key_path = format!("{}/key.pem", self.config.cert_dir);

        if Path::new(&cert_path).exists() && Path::new(&key_path).exists() {
            match CertKeyPair::load_from_files(&cert_path, &key_path) {
                Ok(cert_pair) => {
                    // Check if certificate covers all configured domains
                    if !cert_pair.covers_domains(&self.config.domains) {
                        info!(
                            "Existing certificate does not cover all configured domains, renewal needed"
                        );
                        return Ok(None);
                    }

                    if !cert_pair.needs_renewal(self.config.renew_before_days) {
                        info!(
                            "Loaded existing certificate, expires at: {}",
                            cert_pair.expires_at
                        );
                        return Ok(Some(cert_pair));
                    } else {
                        info!("Existing certificate needs renewal");
                        // If certificate is still valid (not expired), load it anyway
                        // The background task will handle the renewal
                        if cert_pair.expires_at > Utc::now() {
                            info!(
                                "Loaded existing certificate (needing renewal), expires at: {}",
                                cert_pair.expires_at
                            );
                            return Ok(Some(cert_pair));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to load existing certificate: {}", e);
                }
            }
        }
        Ok(None)
    }

    /// Initialize or load ACME account
    async fn get_or_create_account(
        &mut self,
    ) -> Result<&Account, Box<dyn std::error::Error + Send + Sync>> {
        if self.account.is_some() {
            return Ok(self.account.as_ref().unwrap());
        }

        let account_path = format!("{}/account.json", self.config.cert_dir);

        // Ensure cert directory exists
        std::fs::create_dir_all(&self.config.cert_dir)?;

        // Try to load existing account
        if Path::new(&account_path).exists() {
            let account_json = std::fs::read_to_string(&account_path)?;
            let credentials: AccountCredentials = serde_json::from_str(&account_json)?;
            let account = Account::builder()?.from_credentials(credentials).await?;
            self.account = Some(account);
            info!("Loaded existing ACME account");
        } else {
            // Create new account
            let directory_url = if self.config.staging {
                LetsEncrypt::Staging.url()
            } else {
                &self.config.directory_url
            };

            let (account, credentials) = Account::builder()?
                .create(
                    &NewAccount {
                        contact: &[&format!("mailto:{}", self.config.email)],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    directory_url.to_owned(),
                    None,
                )
                .await?;

            // Save account credentials
            let credentials_json = serde_json::to_string_pretty(&credentials)?;
            std::fs::write(&account_path, credentials_json)?;

            self.account = Some(account);
            info!("Created new ACME account");
        }

        Ok(self.account.as_ref().unwrap())
    }

    /// Request a new certificate from ACME
    pub async fn request_certificate(
        &mut self,
    ) -> Result<CertKeyPair, Box<dyn std::error::Error + Send + Sync>> {
        // Clone domains early to avoid borrow conflicts
        let domains = self.config.domains.clone();

        info!("Requesting certificate for domains: {:?}", domains);

        let account = self.get_or_create_account().await?;

        // Create identifiers for all domains
        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

        // Create new order
        let mut order = account
            .new_order(&NewOrder::new(identifiers.as_slice()))
            .await?;

        // Get authorizations and complete challenges
        let mut authorizations = order.authorizations();

        // Collect all challenges to set up
        let mut challenge_tokens: Vec<String> = Vec::new();

        // First pass: set up all challenges
        while let Some(result) = authorizations.next().await {
            let mut auth = result?;
            match auth.status {
                AuthorizationStatus::Pending => {
                    // Find HTTP-01 challenge
                    let mut challenge = auth
                        .challenge(ChallengeType::Http01)
                        .ok_or("No HTTP-01 challenge found")?;

                    let token = challenge.token.clone();
                    let key_auth = challenge.key_authorization().as_str().to_string();

                    info!(
                        "Setting up HTTP-01 challenge for token: {} (domain: {:?})",
                        token,
                        challenge.identifier()
                    );

                    // Store challenge response
                    self.challenge_store.set(token.clone(), key_auth).await;
                    challenge_tokens.push(token);

                    // Notify ACME server that challenge is ready
                    challenge.set_ready().await?;
                }
                AuthorizationStatus::Valid => {
                    info!(
                        "Authorization already valid for {:?} (skipping challenge)",
                        auth.identifier()
                    );
                }
                _ => {
                    return Err(
                        format!("Unexpected authorization status: {:?}", auth.status).into(),
                    );
                }
            }
        }

        // Wait for order to be ready (all authorizations validated)
        let mut attempts = 0;
        loop {
            sleep(std::time::Duration::from_secs(2)).await;
            let status = order.refresh().await?.status;

            match status {
                OrderStatus::Ready | OrderStatus::Valid => {
                    info!("All authorizations validated, order is ready");
                    break;
                }
                OrderStatus::Invalid => {
                    // Log detailed error information
                    let mut authorizations = order.authorizations();
                    while let Some(result) = authorizations.next().await {
                        let auth = result?;
                        if auth.status == AuthorizationStatus::Invalid {
                            for challenge in &auth.challenges {
                                if let Some(error) = &challenge.error {
                                    error!(
                                        "Authorization failed for domain {:?}: {:?} - {:?}",
                                        auth.identifier(),
                                        error.r#type,
                                        error.detail
                                    );
                                }
                            }
                        }
                    }

                    // Clean up all challenge tokens
                    for token in &challenge_tokens {
                        self.challenge_store.remove(token).await;
                    }
                    return Err("Authorization failed".into());
                }
                OrderStatus::Pending | OrderStatus::Processing => {
                    attempts += 1;
                    if attempts > 60 {
                        // Increased timeout for multiple domains
                        // Clean up all challenge tokens
                        for token in &challenge_tokens {
                            self.challenge_store.remove(token).await;
                        }
                        return Err("Authorization timeout".into());
                    }
                }
            }
        }

        // Clean up all challenge tokens
        for token in &challenge_tokens {
            self.challenge_store.remove(token).await;
        }

        // Generate CSR and finalize order.
        let key_pem = order.finalize().await?;

        // Wait for certificate
        let mut attempts = 0;
        let cert_chain = loop {
            match order.certificate().await? {
                Some(cert) => break cert,
                None => {
                    attempts += 1;
                    if attempts > 30 {
                        return Err("Certificate issuance timeout".into());
                    }
                    sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        };

        let cert_pair = CertKeyPair {
            cert_pem: cert_chain,
            key_pem,
            expires_at: Utc::now() + Duration::days(90), // Let's Encrypt certs are valid for 90 days
        };

        // Save to disk
        let cert_path = format!("{}/cert.pem", self.config.cert_dir);
        let key_path = format!("{}/key.pem", self.config.cert_dir);
        cert_pair.save_to_files(&cert_path, &key_path)?;

        info!(
            "Certificate obtained successfully, expires at: {}",
            cert_pair.expires_at
        );

        // Update cert store (hot-reload)
        self.cert_store
            .store_for_domains(&self.config.domains, cert_pair.clone());

        Ok(cert_pair)
    }
}

pub struct AcmeBackgroundService {
    managers: Vec<Arc<tokio::sync::Mutex<CertificateManager>>>,
}

impl AcmeBackgroundService {
    pub fn new(managers: Vec<Arc<tokio::sync::Mutex<CertificateManager>>>) -> Self {
        Self { managers }
    }

    async fn process_due_certificates(&self) {
        for manager in &self.managers {
            let mut mgr = manager.lock().await;
            let domains = mgr.domains().to_vec();

            if mgr.needs_certificate() {
                info!("ACME renewal check: certificate needed for {:?}", domains);
                match mgr.request_certificate().await {
                    Ok(_) => info!("ACME certificate updated for {:?}", domains),
                    Err(e) => error!("ACME certificate update failed for {:?}: {}", domains, e),
                }
            } else {
                debug!(
                    "ACME renewal check: certificate still valid for {:?}",
                    domains
                );
            }
        }
    }
}

#[async_trait]
impl BackgroundService for AcmeBackgroundService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        tokio::select! {
            _ = sleep(std::time::Duration::from_secs(5)) => {}
            _ = shutdown.changed() => {
                info!("ACME background service shutting down before initial certificate check");
                return;
            }
        }

        self.process_due_certificates().await;

        loop {
            tokio::select! {
                _ = sleep(std::time::Duration::from_secs(3600)) => {
                    self.process_due_certificates().await;
                }
                _ = shutdown.changed() => {
                    info!("ACME background service shutting down");
                    return;
                }
            }
        }
    }
}
