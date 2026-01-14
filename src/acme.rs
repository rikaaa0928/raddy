//! ACME Certificate Manager
//!
//! This module provides automatic SSL certificate acquisition and renewal
//! using the ACME protocol (Let's Encrypt compatible).

use arc_swap::ArcSwap;
use chrono::{DateTime, Duration, Utc};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use log::{debug, error, info, warn};
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
        Ok(
            DateTime::from_timestamp(not_after.unix_timestamp(), 0)
                .unwrap_or_else(|| Utc::now()),
        )
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

/// Thread-safe certificate store with atomic updates
/// 
/// Supports domain-indexed certificate storage for SNI-based certificate selection.
pub struct CertStore {
    /// Domain-indexed certificate storage
    /// Key is the domain name, value is the certificate pair
    certs: ArcSwap<HashMap<String, CertKeyPair>>,
    /// Default certificate for when no domain-specific cert is found
    default_cert: ArcSwap<Option<CertKeyPair>>,
}

impl CertStore {
    pub fn new() -> Self {
        Self {
            certs: ArcSwap::from_pointee(HashMap::new()),
            default_cert: ArcSwap::from_pointee(None),
        }
    }

    /// Load the default certificate (legacy API)
    pub fn load(&self) -> arc_swap::Guard<Arc<Option<CertKeyPair>>> {
        self.default_cert.load()
    }

    /// Store a certificate as the default (legacy API, also stores for given domains if any)
    pub fn store(&self, cert: CertKeyPair) {
        self.default_cert.store(Arc::new(Some(cert)));
    }

    /// Store a certificate for specific domains
    pub fn store_for_domains(&self, domains: &[String], cert: CertKeyPair) {
        let mut certs = (**self.certs.load()).clone();
        for domain in domains {
            certs.insert(domain.clone(), cert.clone());
        }
        self.certs.store(Arc::new(certs));
        
        // Also set as default if no default exists
        if self.default_cert.load().is_none() {
            self.default_cert.store(Arc::new(Some(cert)));
        }
    }

    /// Get certificate for a specific domain
    pub fn get_for_domain(&self, domain: &str) -> Option<CertKeyPair> {
        let certs = self.certs.load();
        certs.get(domain).cloned()
    }

    /// Get certificate for a domain, falling back to default
    pub fn get_for_domain_or_default(&self, domain: &str) -> Option<CertKeyPair> {
        self.get_for_domain(domain)
            .or_else(|| (**self.default_cert.load()).clone())
    }

    /// Get all stored domains
    pub fn domains(&self) -> Vec<String> {
        self.certs.load().keys().cloned().collect()
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
    pub async fn new(
        config: AcmeManagerConfig,
        cert_store: Arc<CertStore>,
        challenge_store: Arc<ChallengeStore>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            config,
            cert_store,
            challenge_store,
            account: None,
        })
    }

    /// Get the certificate store for use with GlobalCertificate
    pub fn cert_store(&self) -> Arc<CertStore> {
        self.cert_store.clone()
    }

    /// Get the challenge store for HTTP-01 validation
    pub fn challenge_store(&self) -> Arc<ChallengeStore> {
        self.challenge_store.clone()
    }

    /// Get renewal before days config
    pub fn renew_before_days(&self) -> u32 {
        self.config.renew_before_days
    }

    /// Try to load existing certificate from disk
    pub async fn load_existing_cert(
        &self,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
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
                        return Ok(false);
                    }
                    
                    if !cert_pair.needs_renewal(self.config.renew_before_days) {
                        info!(
                            "Loaded existing certificate, expires at: {}",
                            cert_pair.expires_at
                        );
                        self.cert_store.store(cert_pair);
                        return Ok(true);
                    } else {
                        info!("Existing certificate needs renewal");
                        // If certificate is still valid (not expired), load it anyway
                        // The background task will handle the renewal
                        if cert_pair.expires_at > Utc::now() {
                            info!(
                                "Loaded existing certificate (needing renewal), expires at: {}",
                                cert_pair.expires_at
                            );
                            self.cert_store.store(cert_pair);
                            return Ok(true);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to load existing certificate: {}", e);
                }
            }
        }
        Ok(false)
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
            let account = Account::from_credentials(credentials).await?;
            self.account = Some(account);
            info!("Loaded existing ACME account");
        } else {
            // Create new account
            let directory_url = if self.config.staging {
                LetsEncrypt::Staging.url()
            } else {
                &self.config.directory_url
            };

            let (account, credentials) = Account::create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", self.config.email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url,
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
        
        info!(
            "Requesting certificate for domains: {:?}",
            domains
        );

        let account = self.get_or_create_account().await?;

        // Create identifiers for all domains
        let identifiers: Vec<Identifier> = domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        // Create new order
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await?;

        // Get authorizations and complete challenges
        let authorizations = order.authorizations().await?;

        // Collect all challenges to set up
        let mut challenge_tokens: Vec<String> = Vec::new();

        // First pass: set up all challenges
        for auth in &authorizations {
            match auth.status {
                AuthorizationStatus::Pending => {
                    // Find HTTP-01 challenge
                    let challenge = auth
                        .challenges
                        .iter()
                        .find(|c| c.r#type == ChallengeType::Http01)
                        .ok_or("No HTTP-01 challenge found")?;

                    let token = challenge.token.clone();
                    let key_auth = order.key_authorization(challenge).as_str().to_string();

                    info!("Setting up HTTP-01 challenge for token: {} (domain: {:?})", token, auth.identifier);

                    // Store challenge response
                    self.challenge_store.set(token.clone(), key_auth).await;
                    challenge_tokens.push(token);

                    // Notify ACME server that challenge is ready
                    order.set_challenge_ready(&challenge.url).await?;
                }
                AuthorizationStatus::Valid => {
                    info!("Authorization already valid for {:?} (skipping challenge)", auth.identifier);
                }
                _ => {
                    return Err(format!(
                        "Unexpected authorization status: {:?}",
                        auth.status
                    )
                    .into());
                }
            }
        }

        // Wait for order to be ready (all authorizations validated)
        let mut attempts = 0;
        loop {
            sleep(std::time::Duration::from_secs(2)).await;
            order.refresh().await?;
            
            let state = order.state();
            match state.status {
                OrderStatus::Ready | OrderStatus::Valid => {
                    info!("All authorizations validated, order is ready");
                    break;
                }
                OrderStatus::Invalid => {
                    // Log detailed error information
                    for auth in order.authorizations().await? {
                         if auth.status == AuthorizationStatus::Invalid {
                             for challenge in auth.challenges {
                                 if let Some(error) = challenge.error {
                                     error!("Authorization failed for domain {:?}: {:?} - {:?}", 
                                         auth.identifier, error.r#type, error.detail);
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
                    if attempts > 60 {  // Increased timeout for multiple domains
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

        // Generate CSR and finalize order
        let mut params = rcgen::CertificateParams::new(self.config.domains.clone())?;
        params.distinguished_name = rcgen::DistinguishedName::new();

        let private_key = rcgen::KeyPair::generate()?;
        let csr = params.serialize_request(&private_key)?;

        order.finalize(csr.der()).await?;

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

        let key_pem = private_key.serialize_pem();
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
        self.cert_store.store(cert_pair.clone());

        Ok(cert_pair)
    }

    /// Start background renewal task
    pub fn start_renewal_task(manager: Arc<tokio::sync::Mutex<Self>>) {
        tokio::spawn(async move {
            loop {
                // Check every hour
                sleep(std::time::Duration::from_secs(3600)).await;

                let mut mgr = manager.lock().await;
                let renew_before_days = mgr.renew_before_days();
                let needs_renewal = {
                    let cert_guard = mgr.cert_store.load();
                    match &**cert_guard {
                        Some(cert) => cert.needs_renewal(renew_before_days),
                        None => true,
                    }
                };

                if needs_renewal {
                    info!("Certificate renewal check: renewal needed");
                    match mgr.request_certificate().await {
                        Ok(_) => info!("Certificate renewed successfully"),
                        Err(e) => error!("Certificate renewal failed: {}", e),
                    }
                } else {
                    debug!("Certificate renewal check: no renewal needed");
                }
            }
        });
    }
}
