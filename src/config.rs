
use serde::Deserialize;
use std::collections::HashMap;
use url::Url;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UpstreamParseError {
    #[error("Invalid URL format: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("Missing host in upstream: {0}")]
    MissingHost(String),
}

#[derive(Deserialize, Debug)]
pub struct Config {
    pub servers: HashMap<String, Server>,
}

#[derive(Deserialize, Debug)]
pub struct Server {
    pub listen: String,
    pub routes: HashMap<String, Route>,
}

#[derive(Deserialize, Debug, Clone)]
pub enum Route {
    Echo(String),
    Proxy(Proxy),
}

#[derive(Deserialize, Debug, Clone)]
pub struct Proxy {
    pub upstream: String,
    #[serde(default)]
    pub tls: Option<bool>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct ParsedUpstream {
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub use_tls: bool,
}

impl Proxy {
    pub fn parse_upstream(&self) -> Result<ParsedUpstream, UpstreamParseError> {
        let upstream = &self.upstream;
        
        let parsed = if upstream.contains("://") {
            Url::parse(upstream)?
        } else {
            let scheme = if self.tls.unwrap_or(false) { "https" } else { "http" };
            Url::parse(&format!("{}://{}", scheme, upstream))?
        };

        let host = parsed.host_str()
            .ok_or_else(|| UpstreamParseError::MissingHost(upstream.clone()))?
            .to_string();

        let port = parsed.port().unwrap_or_else(|| {
            match parsed.scheme() {
                "https" => 443,
                "http" => 80,
                _ => 80,
            }
        });

        let use_tls = self.tls.unwrap_or_else(|| {
            parsed.scheme() == "https"
        });

        Ok(ParsedUpstream {
            host,
            port,
            scheme: parsed.scheme().to_string(),
            use_tls,
        })
    }
}
