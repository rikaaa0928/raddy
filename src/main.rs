mod acme;
mod config;
mod proxy;
mod tls;

use log::{error, info, warn};
use mimalloc::MiMalloc;
use pingora::prelude::*;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
use std::sync::Arc;

use acme::{CertKeyPair, CertStore, CertificateManager, ChallengeStore};
use config::Config;
use proxy::ProxyService;
use tls::DynamicCert;

fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Load configuration from environment variable
    let config_path =
        std::env::var("RADDY_CONFIG").unwrap_or_else(|_| "config.yaml".to_string());

    info!("Loading configuration from: {}", config_path);

    let config = match Config::load(&config_path) {
        Ok(cfg) => Arc::new(cfg),
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    info!("Configuration loaded successfully");
    if let Some(addr) = config.http_addr() {
        info!("HTTP Listen address: {}", addr);
    }
    if let Some(addr) = config.https_addr() {
        info!("HTTPS Listen address: {}", addr);
    }
    info!("Routes configured: {}", config.routes.len());

    for (i, route) in config.routes.iter().enumerate() {
        info!(
            "  Route {}: hosts={:?}, path_prefix={:?} -> {} ({:?})",
            i,
            route.hosts,
            route.path_prefix,
            route.upstream.url,
            route.upstream.protocol
        );
    }

    // Create tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    // Initialize certificate store and challenge store for ACME
    let cert_store = Arc::new(CertStore::new());
    let challenge_store = Arc::new(ChallengeStore::new());

    // Handle TLS configuration
    if let Some(tls_certs) = &config.listen.tls {
        if tls_certs.is_empty() {
            error!("TLS config must have at least one certificate configuration");
            std::process::exit(1);
        }
        
        info!("Processing {} TLS certificate configuration(s)", tls_certs.len());
        
        // Process each certificate configuration
        for cert_config in tls_certs {
            let domains = cert_config.domains.clone();
            info!("Processing certificate for domains: {:?}", domains);
            
            match &cert_config.source {
                config::CertSource::Acme(acme_source) => {
                    info!("  Source: ACME (email: {})", acme_source.email);
                    
                    // Create AcmeManagerConfig from source
                    let acme_config = acme::AcmeManagerConfig::from_source(acme_source, domains.clone());
                    
                    let cert_store_clone = cert_store.clone();
                    let challenge_store_clone = challenge_store.clone();
                    let domains_for_store = domains.clone();
                    
                    rt.block_on(async {
                        let manager = CertificateManager::new(
                            acme_config.clone(),
                            cert_store_clone.clone(),
                            challenge_store_clone,
                        )
                        .await
                        .expect("Failed to create certificate manager");

                        // Try to load existing certificate
                        let has_cert = manager
                            .load_existing_cert()
                            .await
                            .unwrap_or_else(|e| {
                                warn!("Failed to load existing certificate for {:?}: {}", domains_for_store, e);
                                false
                            });

                        if has_cert {
                            // Store certificate for these domains
                            if let Some(cert) = (**manager.cert_store().load()).clone() {
                                cert_store_clone.store_for_domains(&domains_for_store, cert);
                            }
                        } else {
                            // Generate temporary self-signed cert
                            info!("No valid certificate found for {:?}, will request after server starts", domains_for_store);
                            
                            let temp_cert = generate_temp_cert(&domains_for_store)
                                .expect("Failed to generate temporary certificate");
                            
                            std::fs::create_dir_all(&acme_config.cert_dir)
                                .expect("Failed to create cert directory");
                            
                            let cert_path = format!("{}/cert.pem", acme_config.cert_dir);
                            let key_path = format!("{}/key.pem", acme_config.cert_dir);
                            
                            temp_cert.save_to_files(&cert_path, &key_path)
                                .expect("Failed to save temporary certificate");
                            
                            cert_store_clone.store_for_domains(&domains_for_store, temp_cert.clone());
                            manager.cert_store().store(temp_cert);
                        }
                    });
                    
                    // Start background ACME renewal task for this configuration
                    let acme_config_for_task = acme::AcmeManagerConfig::from_source(acme_source, domains.clone());
                    let cert_store_for_task = cert_store.clone();
                    let challenge_store_for_task = challenge_store.clone();
                    let domains_for_task = domains.clone();
                    
                    rt.spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        
                        let manager = Arc::new(tokio::sync::Mutex::new(
                            CertificateManager::new(
                                acme_config_for_task,
                                cert_store_for_task.clone(),
                                challenge_store_for_task,
                            )
                            .await
                            .expect("Failed to create certificate manager for renewal"),
                        ));

                        // Check if we need to request initial certificate
                        {
                            let mut mgr = manager.lock().await;
                            let renew_days = mgr.renew_before_days();
                            let cert_guard = mgr.cert_store().load();
                            let needs_real_cert = match &**cert_guard {
                                Some(cert) => cert.needs_renewal(renew_days),
                                None => true,
                            };
                            drop(cert_guard);

                            if needs_real_cert {
                                info!("Requesting initial ACME certificate for {:?}...", domains_for_task);
                                match mgr.request_certificate().await {
                                    Ok(cert) => {
                                        info!("Initial ACME certificate obtained successfully for {:?}", domains_for_task);
                                        cert_store_for_task.store_for_domains(&domains_for_task, cert);
                                    }
                                    Err(e) => error!("Failed to obtain initial ACME certificate for {:?}: {}", domains_for_task, e),
                                }
                            }
                        }

                        // Start renewal task
                        CertificateManager::start_renewal_task(manager);
                    });
                }
                config::CertSource::File(file_source) => {
                    info!("  Source: Static file (cert: {}, key: {})", file_source.cert_path, file_source.key_path);
                    
                    // Load static certificate and store for these domains
                    match CertKeyPair::load_from_files(&file_source.cert_path, &file_source.key_path) {
                        Ok(cert_pair) => {
                            cert_store.store_for_domains(&domains, cert_pair);
                            info!("Loaded static certificate for domains: {:?}", domains);
                        }
                        Err(e) => {
                            error!("Failed to load static certificate for {:?}: {}", domains, e);
                        }
                    }
                }
            }
        }
    };

    // Create pingora server
    let mut server = Server::new(Some(Opt::parse_args())).expect("Failed to create server");
    server.bootstrap();

    // Setup HTTP listener
    if let Some(addr) = config.http_addr() {
        info!("Initializing HTTP listener on {}", addr);
        let proxy_service = ProxyService::new(config.clone(), false, challenge_store.clone());
        let mut http_proxy = http_proxy_service(&server.configuration, proxy_service);

        let mut options = pingora::apps::HttpServerOptions::default();
        options.h2c = true;
        http_proxy.app_logic_mut().map(|logic| {
            logic.server_options = Some(options);
        });

        http_proxy.add_tcp(&addr);
        server.add_service(http_proxy);
    }

    // Setup HTTPS listener
    if let Some(addr) = config.https_addr() {
        if config.listen.tls.is_some() {
            info!("Initializing HTTPS listener on {}", addr);
            let proxy_service = ProxyService::new(config.clone(), true, challenge_store.clone());
            let mut https_proxy = http_proxy_service(&server.configuration, proxy_service);

            // Use dynamic certificate callback for TLS with SNI-based selection
            let dynamic_cert = DynamicCert::new(cert_store.clone());
            
            let mut tls_settings = pingora::listeners::tls::TlsSettings::with_callbacks(dynamic_cert)
                .expect("Failed to create TLS settings with callbacks");
            tls_settings.enable_h2();
            https_proxy.add_tls_with_settings(&addr, None, tls_settings);
            server.add_service(https_proxy);
        } else {
            error!("HTTPS port configured but TLS config is missing");
            std::process::exit(1);
        }
    }

    // Run the server
    server.run_forever();
}

/// Generate a temporary self-signed certificate for initial server startup
fn generate_temp_cert(domains: &[String]) -> Result<CertKeyPair, Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, KeyPair};
    
    let mut params = CertificateParams::new(domains.to_vec())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    
    // Set short expiration for temporary cert (1 day) so it triggers ACME renewal immediately
    // We need to set this in the certificate parameters so the generated PEM has short validity
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(1);
    
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    
    // Temporary cert, set expiry to 1 day from now
    // This matches what we put in the certificate parameters
    let expires_at = chrono::Utc::now() + chrono::Duration::days(1);
    
    Ok(CertKeyPair {
        cert_pem,
        key_pem,
        expires_at,
    })
}
