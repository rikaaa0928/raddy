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

use acme::{AcmeBackgroundService, CertKeyPair, CertStore, CertificateManager, ChallengeStore};
use config::Config;
use proxy::ProxyService;
use tls::DynamicCert;

fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Determine configuration path
    let config_path_raw = std::env::var("RADDY_CONFIG").unwrap_or_else(|_| {
        let etc_path = "/etc/raddy/config.yaml";
        if std::path::Path::new(etc_path).exists() {
            etc_path.to_string()
        } else {
            "config.yaml".to_string()
        }
    });

    // Get absolute path before potentially changing working directory
    let startup_cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let config_path = if std::path::Path::new(&config_path_raw).is_absolute() {
        std::path::PathBuf::from(&config_path_raw)
    } else {
        startup_cwd.join(&config_path_raw)
    };

    // Check if configuration is in the starting working directory
    let is_in_startup_cwd = match (config_path.canonicalize(), startup_cwd.canonicalize()) {
        (Ok(abs_config), Ok(abs_cwd)) => abs_config.parent() == Some(&abs_cwd),
        _ => !config_path_raw.contains('/') && !config_path_raw.contains('\\'),
    };

    if !is_in_startup_cwd {
        if let Ok(home) = std::env::var("HOME") {
            let target_dir = std::path::Path::new(&home).join(".raddy");
            if !target_dir.exists() {
                if let Err(e) = std::fs::create_dir_all(&target_dir) {
                    warn!("Failed to create working directory {:?}: {}", target_dir, e);
                }
            }
            if target_dir.exists() {
                if let Err(e) = std::env::set_current_dir(&target_dir) {
                    warn!(
                        "Failed to change working directory to {:?}: {}",
                        target_dir, e
                    );
                } else {
                    info!("Changed working directory to {:?}", target_dir);
                }
            }
        }
    }

    info!("Loading configuration from: {:?}", config_path);

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
            i, route.hosts, route.path_prefix, route.upstream.url, route.upstream.protocol
        );
    }

    // Initialize certificate store and challenge store for ACME
    let cert_store = Arc::new(CertStore::new());
    let challenge_store = Arc::new(ChallengeStore::new());
    let mut acme_managers = Vec::new();

    // Handle TLS configuration
    if let Some(tls_certs) = &config.listen.tls {
        if tls_certs.is_empty() {
            error!("TLS config must have at least one certificate configuration");
            std::process::exit(1);
        }

        info!(
            "Processing {} TLS certificate configuration(s)",
            tls_certs.len()
        );

        // Process each certificate configuration
        for cert_config in tls_certs {
            let domains = cert_config.domains.clone();
            info!("Processing certificate for domains: {:?}", domains);

            match &cert_config.source {
                config::CertSource::Acme(acme_source) => {
                    info!("  Source: ACME (email: {})", acme_source.email);

                    // Create AcmeManagerConfig from source
                    let acme_config =
                        acme::AcmeManagerConfig::from_source(acme_source, domains.clone());
                    let manager = CertificateManager::new(
                        acme_config.clone(),
                        cert_store.clone(),
                        challenge_store.clone(),
                    );

                    match manager.load_existing_cert() {
                        Ok(Some(cert)) => {
                            cert_store.store_for_domains(&domains, cert);
                        }
                        Ok(None) => {
                            provision_temp_cert(&acme_config.cert_dir, &domains, &cert_store);
                        }
                        Err(e) => {
                            warn!(
                                "Failed to load existing certificate for {:?}: {}",
                                domains, e
                            );
                            provision_temp_cert(&acme_config.cert_dir, &domains, &cert_store);
                        }
                    }

                    acme_managers.push(Arc::new(tokio::sync::Mutex::new(manager)));
                }
                config::CertSource::File(file_source) => {
                    info!(
                        "  Source: Static file (cert: {}, key: {})",
                        file_source.cert_path, file_source.key_path
                    );

                    // Load static certificate and store for these domains
                    match CertKeyPair::load_from_files(
                        &file_source.cert_path,
                        &file_source.key_path,
                    ) {
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

            let mut tls_settings =
                pingora::listeners::tls::TlsSettings::with_callbacks(dynamic_cert)
                    .expect("Failed to create TLS settings with callbacks");
            tls_settings.enable_h2();
            https_proxy.add_tls_with_settings(&addr, None, tls_settings);
            server.add_service(https_proxy);
        } else {
            error!("HTTPS port configured but TLS config is missing");
            std::process::exit(1);
        }
    }

    if !acme_managers.is_empty() {
        server.add_service(background_service(
            "acme renewal",
            AcmeBackgroundService::new(acme_managers),
        ));
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

fn provision_temp_cert(cert_dir: &str, domains: &[String], cert_store: &Arc<CertStore>) {
    info!(
        "No valid certificate found for {:?}, will request after server starts",
        domains
    );

    let temp_cert = generate_temp_cert(domains).expect("Failed to generate temporary certificate");

    std::fs::create_dir_all(cert_dir).expect("Failed to create cert directory");

    let cert_path = format!("{}/cert.pem", cert_dir);
    let key_path = format!("{}/key.pem", cert_dir);

    temp_cert
        .save_to_files(&cert_path, &key_path)
        .expect("Failed to save temporary certificate");

    cert_store.store_for_domains(domains, temp_cert);
}
