mod config;
mod proxy;

use log::{error, info};
use pingora::prelude::*;
use std::sync::Arc;

use config::Config;
use proxy::ProxyService;

fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Load configuration from environment variable
    let config_path = std::env::var("RADDY_CONFIG")
        .unwrap_or_else(|_| "config.yaml".to_string());

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

    // Create pingora server
    let mut server = Server::new(Some(Opt::parse_args())).expect("Failed to create server");
    server.bootstrap();

    // Setup HTTP listener
    if let Some(addr) = config.http_addr() {
        info!("Initializing HTTP listener on {}", addr);
        let proxy_service = ProxyService::new(config.clone(), false);
        let mut http_proxy = http_proxy_service(&server.configuration, proxy_service);
        http_proxy.add_tcp(&addr);
        server.add_service(http_proxy);
    }

    // Setup HTTPS listener
    if let Some(addr) = config.https_addr() {
        if let Some(tls_config) = &config.listen.tls {
            info!("Initializing HTTPS listener on {}", addr);
            let proxy_service = ProxyService::new(config.clone(), true);
            let mut https_proxy = http_proxy_service(&server.configuration, proxy_service);
            
            let cert_path = &tls_config.cert_path;
            let key_path = &tls_config.key_path;
            
            // Check if cert files exist
            if !std::path::Path::new(cert_path).exists() || !std::path::Path::new(key_path).exists() {
                 error!("TLS certificate or key file not found: {} / {}", cert_path, key_path);
                 std::process::exit(1);
            }

            https_proxy.add_tls(&addr, cert_path, key_path).expect("Failed to add TLS listener");
            server.add_service(https_proxy);
        } else {
             error!("HTTPS port configured but TLS config is missing");
             std::process::exit(1);
        }
    }

    // Run the server
    server.run_forever();
}
