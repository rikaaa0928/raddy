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
    /// Path to certificate file (optional if using ACME)
    pub cert_path: Option<String>,
    /// Path to key file (optional if using ACME)
    pub key_path: Option<String>,
    /// ACME automatic certificate configuration
    pub acme: Option<AcmeConfig>,
}

/// ACME automatic certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Contact email for ACME account (required)
    pub email: String,
    /// Domain names to request certificates for
    pub domains: Vec<String>,
    /// ACME directory URL (defaults to Let's Encrypt production)
    #[serde(default = "default_acme_directory")]
    pub directory_url: String,
    /// Directory to store certificates
    #[serde(default = "default_cert_dir")]
    pub cert_dir: String,
    /// Days before expiration to renew certificate
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
    /// Use Let's Encrypt staging environment (for testing)
    #[serde(default)]
    pub staging: bool,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_cert_dir() -> String {
    "./certs".to_string()
}

fn default_renew_before_days() -> u32 {
    7
}

/// Route configuration for matching requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Host(s) to match (optional, matches all if not specified)
    /// Supports single string "example.com" or list ["a.com", "b.com"]
    #[serde(
        default,
        alias = "host",
        deserialize_with = "deserialize_string_or_vec"
    )]
    pub hosts: Option<Vec<String>>,
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

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        String(String),
        Vec(Vec<String>),
    }

    let opt = Option::<StringOrVec>::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(StringOrVec::String(s)) => Ok(Some(vec![s])),
        Some(StringOrVec::Vec(v)) => Ok(Some(v)),
    }
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
            let host_matches = match &route.hosts {
                Some(route_hosts) => {
                    route_hosts.iter().any(|route_host| {
                        hosts.iter().any(|req_host| {
                             req_host == &route_host || req_host.starts_with(&format!("{}:", route_host))
                        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_single_host() {
        let yaml = r#"
upstream:
  url: "http://localhost:8080"
  protocol: http
host: example.com
"#;
        let config: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.hosts, Some(vec!["example.com".to_string()]));
    }

    #[test]
    fn test_deserialize_multiple_hosts() {
        let yaml = r#"
upstream:
  url: "http://localhost:8080"
  protocol: http
hosts:
  - example.com
  - api.example.com
"#;
        let config: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        let hosts = config.hosts.unwrap();
        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains(&"example.com".to_string()));
        assert!(hosts.contains(&"api.example.com".to_string()));
    }

    #[test]
    fn test_deserialize_no_host() {
        let yaml = r#"
upstream:
  url: "http://localhost:8080"
  protocol: http
"#;
        let config: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.hosts, None);
    }

    #[test]
    fn test_find_route() {
        let route1 = RouteConfig {
            hosts: Some(vec!["example.com".to_string(), "alias.com".to_string()]),
            path_prefix: None,
            upstream: UpstreamConfig { url: "u1".to_string(), protocol: Protocol::Http },
            headers: Default::default(),
            force_https_redirect: None,
        };
        
        let mut routes = Vec::new();
        routes.push(route1);

        let config = Config {
            listen: ListenConfig {
                address: "0.0.0.0".to_string(),
                port: Some(80),
                http_port: None,
                https_port: None,
                tls: None,
                force_https_redirect: false,
            },
            routes,
        };

        // Match first host
        assert!(config.find_route(&["example.com"], "/").is_some());
        // Match second host
        assert!(config.find_route(&["alias.com"], "/").is_some());
        // No match
        assert!(config.find_route(&["other.com"], "/").is_none());
    }
}
