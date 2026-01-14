use async_trait::async_trait;
use log::{debug, error, info, warn};
use pingora::http::RequestHeader;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use std::sync::Arc;
use url::Url;

use crate::acme::ChallengeStore;
use crate::config::{Config, Protocol, RouteConfig};

/// Proxy service that handles HTTP requests and routes them to upstream servers
#[derive(Clone)]
pub struct ProxyService {
    config: Arc<Config>,
    is_tls: bool,
    challenge_store: Arc<ChallengeStore>,
}

impl ProxyService {
    /// Create a new proxy service with the given configuration
    pub fn new(config: Arc<Config>, is_tls: bool, challenge_store: Arc<ChallengeStore>) -> Self {
        Self { config, is_tls, challenge_store }
    }

    /// Parse upstream URL and return host, port, and whether to use TLS
    fn parse_upstream(route: &RouteConfig) -> Result<(String, u16, bool), Box<pingora::Error>> {
        let url = &route.upstream.url;
        let use_tls = route.upstream.protocol.is_tls();

        // Parse the URL to extract host and port
        let parsed = Url::parse(url).map_err(|e| {
            error!("Failed to parse upstream URL '{}': {}", url, e);
            pingora::Error::new(pingora::ErrorType::InvalidHTTPHeader)
        })?;

        let host = parsed.host_str().ok_or_else(|| {
            error!("No host in upstream URL: {}", url);
            pingora::Error::new(pingora::ErrorType::InvalidHTTPHeader)
        })?;

        let default_port = match route.upstream.protocol {
            Protocol::Http | Protocol::Ws | Protocol::Grpc => 80,
            Protocol::Https | Protocol::Wss | Protocol::GrpcTls => 443,
        };

        let port = parsed.port().unwrap_or(default_port);

        Ok((host.to_string(), port, use_tls))
    }
}

/// Context passed between request phases
pub struct ProxyContext {
    /// The matched route for this request
    pub route: Option<RouteConfig>,
    /// Whether this is a WebSocket upgrade request
    pub is_websocket: bool,
    /// Whether this is a gRPC request
    pub is_grpc: bool,
}

#[async_trait]
impl ProxyHttp for ProxyService {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext {
            route: None,
            is_websocket: false,
            is_grpc: false,
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool, Box<pingora::Error>> {
        let req_header = session.req_header();
        let path = req_header.uri.path();

        // Handle ACME HTTP-01 challenge
        if path.starts_with("/.well-known/acme-challenge/") {
            let token = path.trim_start_matches("/.well-known/acme-challenge/");
            info!("ACME HTTP-01 challenge request for token: {}", token);
            
            if let Some(key_auth) = self.challenge_store.get(token).await {
                info!("Responding to ACME challenge with key authorization");
                let mut header = pingora::http::ResponseHeader::build(200, None)?;
                header.insert_header("Content-Type", "text/plain")?;
                header.insert_header("Content-Length", key_auth.len().to_string())?;
                
                session.write_response_header(Box::new(header), false).await?;
                session.write_response_body(Some(key_auth.into()), true).await?;
                return Ok(true); // Request handled
            } else {
                warn!("ACME challenge token not found: {}", token);
                let header = pingora::http::ResponseHeader::build(404, Some(1))?;
                session.write_response_header(Box::new(header), true).await?;
                return Ok(true); // Request handled
            }
        }
        
        // Get host(s) from request
        // Check both 'host' header (HTTP/1.1) and ':authority' pseudo-header (HTTP/2/gRPC)
        let mut hosts: Vec<&str> = req_header
            .headers
            .get_all("host")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        
        // For HTTP/2 (gRPC), also check the :authority pseudo-header
        if hosts.is_empty() {
            if let Some(authority) = req_header.headers.get(":authority") {
                if let Ok(auth_str) = authority.to_str() {
                    hosts.push(auth_str);
                }
            }
        }
        
        // Also try to get host from URI authority if still empty
        if hosts.is_empty() {
            if let Some(host) = req_header.uri.host() {
                hosts.push(host);
            }
        }

        // Get path from request
        let path = req_header.uri.path();

        info!(
            "Processing request: hosts={:?}, path={}, is_tls={}",
            hosts,
            path,
            self.is_tls
        );
        info!("Request headers: {:?}", req_header.headers);

        // Find matching route
        let route = self.config.find_route(&hosts, path);
        
        // Check for redirect if not TLS
        if !self.is_tls {
            let should_redirect = if let Some(r) = &route {
                r.force_https_redirect.unwrap_or(self.config.listen.force_https_redirect)
            } else {
                self.config.listen.force_https_redirect
            };

            if should_redirect {
                let https_port = self.config.listen.https_port.unwrap_or(443);
                
                // Construct redirect URL
                let host_str = hosts.first().copied().unwrap_or("localhost").split(':').next().unwrap_or("localhost");
                let port_str = if https_port == 443 {
                    "".to_string()
                } else {
                    format!(":{}", https_port)
                };
                
                let uri = req_header.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
                let location = format!("https://{}{}{}", host_str, port_str, uri);
                
                info!("Redirecting HTTP request to: {}", location);
                
                let mut header = pingora::http::ResponseHeader::build(301, Some(4))?;
                header.insert_header("Location", location)?;
                header.insert_header("Connection", "Close")?;
                
                session.write_response_header(Box::new(header), true).await?;
                return Ok(true); // Short-circuit, request handled
            }
        }

        // If no route found (and no redirect happening), we will fail in upstream_peer
        // But we store what we found
        if let Some(r) = route {
           ctx.route = Some(r.clone());
        }

        Ok(false)
    }

    /// Select upstream peer based on request routing
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<pingora::Error>> {
        // Route should have been found in request_filter
        let route = ctx.route.as_ref().ok_or_else(|| {
             let req_header = session.req_header();
             warn!("No route found for path={}", req_header.uri.path());
             pingora::Error::new(pingora::ErrorType::ConnectNoRoute)
        })?;

        info!(
            "Routing to upstream: hosts={:?}, path_prefix={:?}, upstream={}",
            route.hosts, route.path_prefix, route.upstream.url
        );
        
        let req_header = session.req_header();

        // Check for WebSocket upgrade
        let is_websocket = req_header
            .headers
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
            || route.upstream.protocol.is_websocket();

        // Check for gRPC
        let is_grpc = req_header
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.starts_with("application/grpc"))
            .unwrap_or(false)
            || route.upstream.protocol.is_grpc();

        // Store context
        ctx.is_websocket = is_websocket;
        ctx.is_grpc = is_grpc;

        // Parse upstream and create peer
        let (host, port, use_tls) = Self::parse_upstream(route)?;

        debug!(
            "Upstream peer: {}:{}, TLS={}, WebSocket={}, gRPC={}",
            host, port, use_tls, is_websocket, is_grpc
        );

        let mut peer = HttpPeer::new((host.as_str(), port), use_tls, host.clone());

        // Configure for HTTP/2 if gRPC
        if is_grpc {
            peer.options.alpn = pingora::protocols::ALPN::H2;
        }

        Ok(Box::new(peer))
    }

    /// Modify request headers before sending to upstream
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> {
        // Set proper Host header for upstream
        if let Some(route) = &ctx.route {
            if let Ok(parsed) = Url::parse(&route.upstream.url) {
                if let Some(host) = parsed.host_str() {
                    let host_value = if let Some(port) = parsed.port() {
                        format!("{}:{}", host, port)
                    } else {
                        host.to_string()
                    };

                    upstream_request
                        .insert_header("Host", &host_value)
                        .map_err(|e| {
                            error!("Failed to set Host header: {}", e);
                            pingora::Error::new(pingora::ErrorType::InvalidHTTPHeader)
                        })?;

                    debug!("Set upstream Host header to: {}", host_value);
                }

                // Rewrite URI path to include upstream path
                let upstream_path = parsed.path();
                if !upstream_path.is_empty() && upstream_path != "/" {
                    let original_uri = &upstream_request.uri;
                    let original_path = original_uri.path();
                    let original_query = original_uri.query();
                    
                    // Combine upstream path with request path
                    let new_path = if original_path == "/" {
                        upstream_path.to_string()
                    } else {
                        format!("{}{}", upstream_path.trim_end_matches('/'), original_path)
                    };
                    
                    // Build path_and_query string
                    let path_and_query = if let Some(query) = original_query {
                        format!("{}?{}", new_path, query)
                    } else {
                        new_path
                    };
                    
                    debug!("Rewriting URI path from {} to {}", original_path, path_and_query);
                    
                    // Build new URI
                    let new_uri = http::uri::Uri::builder()
                        .path_and_query(path_and_query.as_str())
                        .build()
                        .map_err(|e| {
                            error!("Failed to build new URI: {}", e);
                            pingora::Error::new(pingora::ErrorType::InvalidHTTPHeader)
                        })?;
                    
                    upstream_request.set_uri(new_uri);
                }
            }

            // Apply custom headers from route configuration
            for (key, value) in &route.headers {
                // Create owned HeaderName and HeaderValue
                let header_name = http::header::HeaderName::from_bytes(key.as_bytes())
                    .map_err(|e| {
                        error!("Invalid header name '{}': {}", key, e);
                        pingora::Error::new(pingora::ErrorType::InvalidHTTPHeader)
                    })?;
                let header_value = http::header::HeaderValue::from_bytes(value.as_bytes())
                    .map_err(|e| {
                        error!("Invalid header value for '{}': {}", key, e);
                        pingora::Error::new(pingora::ErrorType::InvalidHTTPHeader)
                    })?;
                
                // Use insert_header method with owned values
                upstream_request.insert_header(header_name, header_value)
                    .map_err(|e| {
                        error!("Failed to insert header '{}': {}", key, e);
                        pingora::Error::new(pingora::ErrorType::InvalidHTTPHeader)
                    })?;
                debug!("Set custom header: {} = {}", key, value);
            }
        }

        // For WebSocket, ensure proper upgrade headers
        if ctx.is_websocket {
            debug!("WebSocket request, preserving upgrade headers");
            if !upstream_request.headers.contains_key("Upgrade") {
                 debug!("Adding missing Upgrade headers for WebSocket");
                 upstream_request.insert_header("Connection", "Upgrade").map_err(|e| {
                     error!("Failed to set Connection header: {}", e);
                     pingora::Error::new(pingora::ErrorType::InvalidHTTPHeader)
                 })?;
                 upstream_request.insert_header("Upgrade", "websocket").map_err(|e| {
                     error!("Failed to set Upgrade header: {}", e);
                     pingora::Error::new(pingora::ErrorType::InvalidHTTPHeader)
                 })?;
            }
            
            // Also copy Sec-WebSocket-Key and Version if missing
            let ws_headers = ["Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol"];
            for header in ws_headers {
                if !upstream_request.headers.contains_key(header) {
                     if let Some(value) = session.req_header().headers.get(header) {
                         debug!("Copying header {} for WebSocket", header);
                         upstream_request.insert_header(header, value).map_err(|e| {
                             error!("Failed to copy header {}: {}", header, e);
                             pingora::Error::new(pingora::ErrorType::InvalidHTTPHeader)
                         })?;
                     }
                }
            }
            
            debug!("Upstream Headers for WebSocket: {:?}", upstream_request.headers);
        }

        // For gRPC, ensure proper content-type
        if ctx.is_grpc {
            debug!("gRPC request, preserving gRPC headers");
        }

        Ok(())
    }

    /// Log when request completes
    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let req_header = session.req_header();
        let response_code = session.response_written().map(|r| r.status.as_u16());

        let upstream_info = ctx
            .route
            .as_ref()
            .map(|r| r.upstream.url.as_str())
            .unwrap_or("unknown");

        info!(
            "{} {} -> {} (upstream: {})",
            req_header.method,
            req_header.uri,
            response_code.unwrap_or(0),
            upstream_info
        );
    }
}
