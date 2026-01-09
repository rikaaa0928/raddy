mod acme;
mod config;
mod proxy;

use log::{error, info, warn};
use pingora::prelude::*;
use std::sync::Arc;

use acme::{CertKeyPair, CertStore, CertificateManager, ChallengeStore};
use config::Config;
use proxy::ProxyService;

fn main() {
    // Install rustls crypto provider (ring) before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

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
            "  Route {}: host={:?}, path_prefix={:?} -> {} ({:?})",
            i,
            route.host,
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
    let (cert_path, key_path) = if let Some(tls_config) = &config.listen.tls {
        if let Some(acme_config) = &tls_config.acme {
            // ACME mode: try to load existing cert or request new one
            info!("ACME mode enabled for domains: {:?}", acme_config.domains);

            let acme_config_clone = acme_config.clone();
            let cert_store_clone = cert_store.clone();
            let challenge_store_clone = challenge_store.clone();

            let (cert_p, key_p) = rt.block_on(async {
                let manager = CertificateManager::new(
                    acme_config_clone.clone(),
                    cert_store_clone,
                    challenge_store_clone,
                )
                .await
                .expect("Failed to create certificate manager");

                // Try to load existing certificate
                let has_cert = manager
                    .load_existing_cert()
                    .await
                    .unwrap_or_else(|e| {
                        warn!("Failed to load existing certificate: {}", e);
                        false
                    });

                if !has_cert {
                    // Need to request new certificate
                    // For initial setup, we need HTTP server running first for HTTP-01 challenge
                    // So we'll use a temporary self-signed cert and request ACME cert after server starts
                    info!("No valid certificate found, will request after server starts");
                    
                    // Generate temporary self-signed cert for initial startup
                    let temp_cert = generate_temp_cert(&acme_config_clone.domains)
                        .expect("Failed to generate temporary certificate");
                    
                    // Ensure cert directory exists
                    std::fs::create_dir_all(&acme_config_clone.cert_dir)
                        .expect("Failed to create cert directory");
                    
                    let cert_path = format!("{}/cert.pem", acme_config_clone.cert_dir);
                    let key_path = format!("{}/key.pem", acme_config_clone.cert_dir);
                    
                    temp_cert.save_to_files(&cert_path, &key_path)
                        .expect("Failed to save temporary certificate");
                    
                    manager.cert_store().store(temp_cert);
                }

                let cert_path = format!("{}/cert.pem", acme_config_clone.cert_dir);
                let key_path = format!("{}/key.pem", acme_config_clone.cert_dir);
                (cert_path, key_path)
            });

            // Start ACME certificate manager for background renewal
            let acme_config_for_task = acme_config.clone();
            let cert_store_for_task = cert_store.clone();
            let challenge_store_for_task = challenge_store.clone();
            
            rt.spawn(async move {
                // Wait a bit for server to start
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                
                let manager = Arc::new(tokio::sync::Mutex::new(
                    CertificateManager::new(
                        acme_config_for_task,
                        cert_store_for_task,
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
                        info!("Requesting initial ACME certificate...");
                        match mgr.request_certificate().await {
                            Ok(_) => info!("Initial ACME certificate obtained successfully"),
                            Err(e) => error!("Failed to obtain initial ACME certificate: {}", e),
                        }
                    }
                }

                // Start renewal task
                CertificateManager::start_renewal_task(manager);
            });

            (cert_p, key_p)
        } else if let (Some(cert_p), Some(key_p)) = (&tls_config.cert_path, &tls_config.key_path) {
            // Static certificate mode
            info!("Static TLS certificate mode");
            
            // Load static cert into cert store for potential future hot-reload
            match CertKeyPair::load_from_files(cert_p, key_p) {
                Ok(cert_pair) => {
                    cert_store.store(cert_pair);
                }
                Err(e) => {
                    warn!("Failed to load static certificate into store: {}", e);
                }
            }
            
            (cert_p.clone(), key_p.clone())
        } else {
            error!("TLS config must have either static cert paths or ACME config");
            std::process::exit(1);
        }
    } else {
        // No TLS config, empty paths
        (String::new(), String::new())
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
        if config.listen.tls.is_some() && !cert_path.is_empty() && !key_path.is_empty() {
            info!("Initializing HTTPS listener on {}", addr);
            let proxy_service = ProxyService::new(config.clone(), true, challenge_store.clone());
            let mut https_proxy = http_proxy_service(&server.configuration, proxy_service);

            // Check if cert files exist
            if !std::path::Path::new(&cert_path).exists()
                || !std::path::Path::new(&key_path).exists()
            {
                error!(
                    "TLS certificate or key file not found: {} / {}",
                    cert_path, key_path
                );
                std::process::exit(1);
            }

            https_proxy
                .add_tls(&addr, &cert_path, &key_path)
                .expect("Failed to add TLS listener");
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
    
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    
    // Temporary cert, set expiry to 1 day from now
    let expires_at = chrono::Utc::now() + chrono::Duration::days(1);
    
    Ok(CertKeyPair {
        cert_pem,
        key_pem,
        expires_at,
    })
}
