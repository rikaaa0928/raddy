use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Listen configuration
    pub listen: ListenConfig,
    /// Route configurations
    #[serde(deserialize_with = "deserialize_routes")]
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
    /// TLS certificate configurations (required if https_port is specified)
    /// Each entry defines domains and their certificate source (ACME or file)
    pub tls: Option<Vec<TlsCertConfig>>,
    /// Global HTTP/3 listener switch. When disabled, no UDP listener is started.
    #[serde(default = "default_true", alias = "h3")]
    pub http3: bool,
    /// Global force HTTPS redirect
    #[serde(default)]
    pub force_https_redirect: bool,
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

fn default_true() -> bool {
    true
}

/// Per-domain TLS certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertConfig {
    /// Domains this certificate covers
    pub domains: Vec<String>,
    /// Certificate source (ACME or static file)
    pub source: CertSource,
}

/// Certificate source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CertSource {
    /// ACME automatic certificate
    Acme(AcmeCertSource),
    /// Static certificate from files
    File(FileCertSource),
}

/// ACME certificate source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeCertSource {
    /// Contact email for ACME account (required)
    pub email: String,
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

/// Static file certificate source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCertSource {
    /// Path to certificate file
    pub cert_path: String,
    /// Path to private key file
    pub key_path: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawRouteConfig {
    WithPaths {
        #[serde(
            default,
            alias = "host",
            deserialize_with = "deserialize_string_or_vec"
        )]
        hosts: Option<Vec<String>>,
        #[serde(default, alias = "h3")]
        http3: Option<bool>,
        paths: Vec<RouteConfig>,
    },
    Single(Box<RouteConfig>),
}

fn deserialize_routes<'de, D>(deserializer: D) -> Result<Vec<RouteConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw_routes: Vec<RawRouteConfig> = Vec::deserialize(deserializer)?;
    let mut routes = Vec::new();

    for raw in raw_routes {
        match raw {
            RawRouteConfig::WithPaths {
                hosts,
                http3,
                paths,
            } => {
                for mut path in paths {
                    if path.hosts.is_none() {
                        path.hosts = hosts.clone();
                    }
                    if path.http3.is_none() {
                        path.http3 = http3;
                    }
                    routes.push(path);
                }
            }
            RawRouteConfig::Single(route) => {
                routes.push(*route);
            }
        }
    }

    Ok(routes)
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
    /// Headers to remove from the upstream response
    #[serde(default)]
    pub hide_headers: Vec<String>,
    /// Force HTTPS redirect for this route (overrides global setting)
    pub force_https_redirect: Option<bool>,
    /// HTTP/3 switch for this route (defaults to enabled)
    #[serde(default, alias = "h3")]
    pub http3: Option<bool>,
    /// Path rewriting configuration
    pub rewrite: Option<RewriteConfig>,
    /// Compiled regex for path rewriting (internal use)
    #[serde(skip)]
    pub rewrite_regex: Option<regex::Regex>,
    /// Query rewriting configuration
    pub rewrite_query: Option<RewriteConfig>,
    /// Compiled regex for query rewriting (internal use)
    #[serde(skip)]
    pub rewrite_query_regex: Option<regex::Regex>,
}

impl RouteConfig {
    /// Whether this route accepts HTTP/3 requests.
    pub fn http3_enabled(&self) -> bool {
        self.http3.unwrap_or(true)
    }
}

/// Path rewriting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteConfig {
    /// Regex pattern to match against the path
    pub pattern: String,
    /// Replacement string (can contain capture groups like $1, $2)
    pub to: String,
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

        let mut config: Config =
            serde_yaml::from_str(&content).map_err(|e| ConfigError::ParseError {
                path: path.as_ref().display().to_string(),
                source: e,
            })?;

        // Compile regexes for rewrite rules
        for (i, route) in config.routes.iter_mut().enumerate() {
            if let Some(rewrite) = &route.rewrite {
                let regex = regex::Regex::new(&rewrite.pattern).map_err(|e| {
                    ConfigError::ValidationError(format!(
                        "Invalid rewrite regex in route {}: {}",
                        i, e
                    ))
                })?;
                route.rewrite_regex = Some(regex);
            }
            if let Some(rewrite) = &route.rewrite_query {
                let regex = regex::Regex::new(&rewrite.pattern).map_err(|e| {
                    ConfigError::ValidationError(format!(
                        "Invalid rewrite_query regex in route {}: {}",
                        i, e
                    ))
                })?;
                route.rewrite_query_regex = Some(regex);
            }
        }

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
                Some(route_hosts) => route_hosts.iter().any(|route_host| {
                    hosts.iter().any(|req_host| {
                        req_host == route_host || req_host.starts_with(&format!("{}:", route_host))
                    })
                }),
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
#[allow(clippy::enum_variant_names)]
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
            upstream: UpstreamConfig {
                url: "u1".to_string(),
                protocol: Protocol::Http,
            },
            headers: Default::default(),
            hide_headers: Default::default(),
            force_https_redirect: None,
            http3: None,
            rewrite: None,
            rewrite_regex: None,
            rewrite_query: None,
            rewrite_query_regex: None,
        };

        let routes = vec![route1];

        let config = Config {
            listen: ListenConfig {
                address: "0.0.0.0".to_string(),
                port: Some(80),
                http_port: None,
                https_port: None,
                tls: None,
                http3: true,
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

    #[test]
    fn test_deserialize_tls_certs_acme() {
        let yaml = r#"
domains:
  - "test.example.com"
  - "test2.example.com"
source:
  type: acme
  email: "admin@example.com"
  staging: true
"#;
        let cert_config: TlsCertConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cert_config.domains.len(), 2);
        assert!(cert_config
            .domains
            .contains(&"test.example.com".to_string()));

        match &cert_config.source {
            CertSource::Acme(acme) => {
                assert_eq!(acme.email, "admin@example.com");
                assert!(acme.staging);
            }
            _ => panic!("Expected ACME source"),
        }
    }

    #[test]
    fn test_deserialize_tls_certs_file() {
        let yaml = r#"
domains:
  - "static.example.com"
source:
  type: file
  cert_path: "/path/to/cert.pem"
  key_path: "/path/to/key.pem"
"#;
        let cert_config: TlsCertConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cert_config.domains.len(), 1);
        assert_eq!(cert_config.domains[0], "static.example.com");

        match &cert_config.source {
            CertSource::File(file) => {
                assert_eq!(file.cert_path, "/path/to/cert.pem");
                assert_eq!(file.key_path, "/path/to/key.pem");
            }
            _ => panic!("Expected File source"),
        }
    }

    #[test]
    fn test_deserialize_tls_certs_list() {
        let yaml = r#"
- domains:
    - "acme.example.com"
  source:
    type: acme
    email: "admin@example.com"
- domains:
    - "static.example.com"
  source:
    type: file
    cert_path: "/path/to/cert.pem"
    key_path: "/path/to/key.pem"
"#;
        let tls_certs: Vec<TlsCertConfig> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(tls_certs.len(), 2);

        // First cert should be ACME
        assert!(matches!(&tls_certs[0].source, CertSource::Acme(_)));
        // Second cert should be File
        assert!(matches!(&tls_certs[1].source, CertSource::File(_)));
    }

    #[test]
    fn test_deserialize_routes_with_paths() {
        let yaml = r#"
listen:
  address: "0.0.0.0"
  port: 80
routes:
  - hosts: ["example.com"]
    paths:
      - path_prefix: "/api"
        upstream:
          url: "127.0.0.1:8080"
          protocol: http
      - path_prefix: "/static"
        upstream:
          url: "127.0.0.1:8081"
          protocol: http
  - host: "test.com"
    path_prefix: "/v1"
    upstream:
      url: "127.0.0.1:8082"
      protocol: http
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.routes.len(), 3);

        let r1 = &config.routes[0];
        assert_eq!(r1.hosts, Some(vec!["example.com".to_string()]));
        assert_eq!(r1.path_prefix, Some("/api".to_string()));
        assert_eq!(r1.upstream.url, "127.0.0.1:8080");

        let r2 = &config.routes[1];
        assert_eq!(r2.hosts, Some(vec!["example.com".to_string()]));
        assert_eq!(r2.path_prefix, Some("/static".to_string()));
        assert_eq!(r2.upstream.url, "127.0.0.1:8081");

        let r3 = &config.routes[2];
        assert_eq!(r3.hosts, Some(vec!["test.com".to_string()]));
        assert_eq!(r3.path_prefix, Some("/v1".to_string()));
        assert_eq!(r3.upstream.url, "127.0.0.1:8082");
    }

    #[test]
    fn test_http3_defaults_to_enabled() {
        let yaml = r#"
listen:
  address: "0.0.0.0"
  https_port: 443
routes:
  - host: "example.com"
    upstream:
      url: "http://127.0.0.1:8080"
      protocol: http
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.listen.http3);
        assert!(config.routes[0].http3_enabled());
    }

    #[test]
    fn test_http3_can_be_disabled_globally_and_per_route() {
        let yaml = r#"
listen:
  address: "0.0.0.0"
  https_port: 443
  http3: false
routes:
  - host: "example.com"
    http3: false
    upstream:
      url: "http://127.0.0.1:8080"
      protocol: http
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.listen.http3);
        assert_eq!(config.routes[0].http3, Some(false));
        assert!(!config.routes[0].http3_enabled());
    }

    #[test]
    fn test_http3_inherits_from_route_group() {
        let yaml = r#"
listen:
  address: "0.0.0.0"
  https_port: 443
routes:
  - hosts: ["example.com"]
    http3: false
    paths:
      - path_prefix: "/api"
        upstream:
          url: "http://127.0.0.1:8080"
          protocol: http
      - path_prefix: "/public"
        http3: true
        upstream:
          url: "http://127.0.0.1:8081"
          protocol: http
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.routes[0].http3, Some(false));
        assert!(!config.routes[0].http3_enabled());
        assert_eq!(config.routes[1].http3, Some(true));
        assert!(config.routes[1].http3_enabled());
    }
}
