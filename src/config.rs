use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Listen configuration
    pub listen: ListenConfig,
    /// Route configurations
    pub routes: Vec<RouteConfig>,
}

/// Listen address configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenConfig {
    /// Bind address, e.g., "0.0.0.0"
    pub address: String,
    /// Legacy port number, treated as HTTP port if http_port is not specified
    pub port: Option<u16>,
    /// HTTP port number, e.g., 80 or 8080
    pub http_port: Option<u16>,
    /// HTTPS port number, e.g., 443 or 8443
    pub https_port: Option<u16>,
    /// TLS configuration (required if https_port is specified)
    pub tls: Option<TlsConfig>,
    /// Global force HTTPS redirect
    #[serde(default)]
    pub force_https_redirect: bool,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: String,
    /// Path to key file
    pub key_path: String,
}

/// Route configuration for matching requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Host to match (optional, matches all if not specified)
    pub host: Option<String>,
    /// Path prefix to match (optional, matches all if not specified)
    pub path_prefix: Option<String>,
    /// Upstream configuration
    pub upstream: UpstreamConfig,
    /// Custom headers to add/override on the request
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// Force HTTPS redirect for this route (overrides global setting)
    pub force_https_redirect: Option<bool>,
}

/// Upstream server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Upstream URL, e.g., "https://backend.example.com:443"
    pub url: String,
    /// Protocol type
    pub protocol: Protocol,
}

/// Supported upstream protocols
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// Plain HTTP
    Http,
    /// HTTPS with TLS
    Https,
    /// gRPC over HTTP/2
    Grpc,
    /// gRPC over HTTP/2 with TLS
    GrpcTls,
    /// WebSocket
    Ws,
    /// WebSocket Secure (WSS)
    Wss,
}

impl Protocol {
    /// Returns true if this protocol uses TLS
    pub fn is_tls(&self) -> bool {
        matches!(self, Protocol::Https | Protocol::GrpcTls | Protocol::Wss)
    }

    /// Returns true if this protocol is WebSocket based
    pub fn is_websocket(&self) -> bool {
        matches!(self, Protocol::Ws | Protocol::Wss)
    }

    /// Returns true if this protocol is gRPC based
    pub fn is_grpc(&self) -> bool {
        matches!(self, Protocol::Grpc | Protocol::GrpcTls)
    }
}

impl Config {
    /// Load configuration from a YAML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path.as_ref()).map_err(|e| ConfigError::IoError {
            path: path.as_ref().display().to_string(),
            source: e,
        })?;

        let config: Config =
            serde_yaml::from_str(&content).map_err(|e| ConfigError::ParseError {
                path: path.as_ref().display().to_string(),
                source: e,
            })?;

        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> Result<(), ConfigError> {
        if self.routes.is_empty() {
            return Err(ConfigError::ValidationError(
                "At least one route must be configured".to_string(),
            ));
        }

        for (i, route) in self.routes.iter().enumerate() {
            if route.upstream.url.is_empty() {
                return Err(ConfigError::ValidationError(format!(
                    "Route {} has empty upstream URL",
                    i
                )));
            }
        }

        Ok(())
    }

    /// Get the HTTP listen address as a string in "address:port" format
    pub fn http_addr(&self) -> Option<String> {
        self.listen
            .http_port
            .or(self.listen.port)
            .map(|port| format!("{}:{}", self.listen.address, port))
    }

    /// Get the HTTPS listen address as a string in "address:port" format
    pub fn https_addr(&self) -> Option<String> {
        self.listen
            .https_port
            .map(|port| format!("{}:{}", self.listen.address, port))
    }

    /// Find a matching route for the given host(s) and path
    pub fn find_route(&self, hosts: &[&str], path: &str) -> Option<&RouteConfig> {
        // First, try to find an exact match with both host and path_prefix
        for route in &self.routes {
            let host_matches = match &route.host {
                Some(route_host) => {
                    hosts.iter().any(|req_host| {
                         req_host == &route_host || req_host.starts_with(&format!("{}:", route_host))
                    })
                }
                None => true,
            };

            let path_matches = match &route.path_prefix {
                Some(prefix) => path.starts_with(prefix),
                None => true,
            };

            if host_matches && path_matches {
                return Some(route);
            }
        }

        None
    }
}

/// Configuration errors
#[derive(Debug)]
pub enum ConfigError {
    IoError {
        path: String,
        source: std::io::Error,
    },
    ParseError {
        path: String,
        source: serde_yaml::Error,
    },
    ValidationError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::IoError { path, source } => {
                write!(f, "Failed to read config file '{}': {}", path, source)
            }
            ConfigError::ParseError { path, source } => {
                write!(f, "Failed to parse config file '{}': {}", path, source)
            }
            ConfigError::ValidationError(msg) => {
                write!(f, "Configuration validation error: {}", msg)
            }
        }
    }
}

impl std::error::Error for ConfigError {}
