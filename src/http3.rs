use async_trait::async_trait;
use boring::ssl::{NameType, SniError, SslContextBuilder, SslMethod, SslRef};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use pingora::connectors::http::Connector as HttpConnector;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::protocols::http::client::HttpSession;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use pingora::upstreams::peer::HttpPeer;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_quiche::http3::driver::{
    H3Event, InboundFrame, IncomingH3Headers, OutboundFrame, OutboundFrameSender,
    ServerEventStream, ServerH3Event,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quiche::h3::{Header, NameValue};
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::{listen, ConnectionParams, ServerH3Driver};
use url::Url;

use crate::acme::{CertStore, ParsedCert};
use crate::config::{Config, Protocol, RouteConfig};

type H3Result<T> = Result<T, Box<dyn Error + Send + Sync>>;

const UPSTREAM_CONNECT_TIMEOUT_SECS: u64 = 3;
const UPSTREAM_TOTAL_CONNECT_TIMEOUT_SECS: u64 = 10;
const UPSTREAM_IO_TIMEOUT_SECS: u64 = 30;
const LOCAL_UPSTREAM_IDLE_TIMEOUT_SECS: u64 = 5;
const REMOTE_UPSTREAM_IDLE_TIMEOUT_SECS: u64 = 15;

/// HTTP/3 UDP ingress service backed by tokio-quiche.
pub struct Http3Service {
    config: Arc<Config>,
    cert_store: Arc<CertStore>,
    connector: Arc<HttpConnector>,
}

impl Http3Service {
    pub fn new(config: Arc<Config>, cert_store: Arc<CertStore>) -> Self {
        Self {
            config,
            cert_store,
            connector: Arc::new(HttpConnector::new(None)),
        }
    }
}

#[async_trait]
impl BackgroundService for Http3Service {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if !self.config.listen.http3 {
            info!("HTTP/3 is disabled globally; UDP listener will not start");
            return;
        }

        let Some(addr) = self.config.https_addr() else {
            info!("HTTP/3 listener skipped because HTTPS is not configured");
            return;
        };

        let socket = match UdpSocket::bind(&addr).await {
            Ok(socket) => socket,
            Err(e) => {
                error!("Failed to bind HTTP/3 UDP listener on {}: {}", addr, e);
                return;
            }
        };

        let hooks = Hooks {
            connection_hook: Some(Arc::new(DynamicQuicCert::new(self.cert_store.clone()))),
        };
        let params = ConnectionParams::new_server(
            QuicSettings::default(),
            TlsCertificatePaths {
                cert: "",
                private_key: "",
                kind: CertificateKind::X509,
            },
            hooks,
        );

        let mut listeners = match listen([socket], params, DefaultMetrics) {
            Ok(listeners) => listeners,
            Err(e) => {
                error!("Failed to initialize HTTP/3 listener on {}: {}", addr, e);
                return;
            }
        };

        info!("HTTP/3 UDP listener started on {}", addr);
        let mut accepted = listeners.remove(0);
        let handler = Http3ConnectionHandler {
            config: self.config.clone(),
            connector: self.connector.clone(),
        };

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    info!("HTTP/3 listener shutting down");
                    return;
                }
                conn = accepted.next() => {
                    match conn {
                        Some(Ok(conn)) => {
                            let (driver, mut controller) =
                                ServerH3Driver::new(Http3Settings::default());
                            conn.start(driver);

                            let handler = handler.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handler
                                    .serve_connection(controller.event_receiver_mut())
                                    .await
                                {
                                    debug!("HTTP/3 connection finished with error: {}", e);
                                }
                            });
                        }
                        Some(Err(e)) => {
                            warn!("Failed to accept HTTP/3 connection: {}", e);
                        }
                        None => {
                            warn!("HTTP/3 accept stream ended");
                            return;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
struct Http3ConnectionHandler {
    config: Arc<Config>,
    connector: Arc<HttpConnector>,
}

impl Http3ConnectionHandler {
    async fn serve_connection(&self, events: &mut ServerEventStream) -> H3Result<()> {
        while let Some(event) = events.recv().await {
            match event {
                ServerH3Event::Core(event) => self.handle_core_event(event)?,
                ServerH3Event::Headers {
                    incoming_headers, ..
                } => {
                    let handler = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle_request(incoming_headers).await {
                            debug!("HTTP/3 request handling failed: {}", e);
                        }
                    });
                }
            }
        }
        Ok(())
    }

    fn handle_core_event(&self, event: H3Event) -> H3Result<()> {
        match event {
            H3Event::ConnectionError(err) => Err(Box::new(err)),
            H3Event::ConnectionShutdown(err) => {
                if let Some(err) = err {
                    Err(Box::new(err))
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    async fn handle_request(&self, incoming: IncomingH3Headers) -> H3Result<()> {
        let H3Request {
            method,
            path,
            authority,
            upstream_request,
            route,
            recv,
            read_fin,
            send,
        } = match self.prepare_request(incoming).await {
            Ok(request) => request,
            Err((mut send, status, body)) => {
                send_simple_response(&mut send, status, body).await;
                return Ok(());
            }
        };

        if !route.http3_enabled() {
            let mut send = send;
            send_simple_response(&mut send, 421, "HTTP/3 is disabled for this route").await;
            return Ok(());
        }

        if route.upstream.protocol.is_grpc() || route.upstream.protocol.is_websocket() {
            let mut send = send;
            send_simple_response(
                &mut send,
                501,
                "HTTP/3 proxying currently supports HTTP and HTTPS upstreams",
            )
            .await;
            return Ok(());
        }

        info!(
            "HTTP/3 request: authority={:?}, method={}, path={}, upstream={}",
            authority, method, path, route.upstream.url
        );

        let (host, port, use_tls) = parse_upstream(&route)?;
        let mut peer = HttpPeer::new((host.as_str(), port), use_tls, host.clone());
        peer.options.set_http_version(1, 1);
        peer.options.connection_timeout = Some(Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS));
        peer.options.total_connection_timeout =
            Some(Duration::from_secs(UPSTREAM_TOTAL_CONNECT_TIMEOUT_SECS));
        peer.options.read_timeout = Some(Duration::from_secs(UPSTREAM_IO_TIMEOUT_SECS));
        peer.options.write_timeout = Some(Duration::from_secs(UPSTREAM_IO_TIMEOUT_SECS));
        peer.options.idle_timeout = Some(Duration::from_secs(if is_local_upstream(&host) {
            LOCAL_UPSTREAM_IDLE_TIMEOUT_SECS
        } else {
            REMOTE_UPSTREAM_IDLE_TIMEOUT_SECS
        }));

        let (mut upstream, _) = self.connector.get_http_session(&peer).await?;
        let proxy_result = async {
            upstream
                .write_request_header(Box::new(upstream_request))
                .await?;
            write_request_body(&mut upstream, recv, read_fin).await?;
            upstream.read_response_header().await?;

            let response = upstream
                .response_header()
                .ok_or("upstream response header missing")?
                .clone();
            let send = send_response_headers(send, &response, &route).await?;
            send_response_body(send, &mut upstream).await
        }
        .await;

        upstream.shutdown().await;
        proxy_result
    }

    async fn prepare_request(
        &self,
        incoming: IncomingH3Headers,
    ) -> Result<H3Request, (OutboundFrameSender, u16, &'static str)> {
        let IncomingH3Headers {
            headers,
            send,
            recv,
            read_fin,
            ..
        } = incoming;

        let parsed = match ParsedH3Headers::from_headers(&headers) {
            Ok(parsed) => parsed,
            Err(_) => return Err((send, 400, "Invalid HTTP/3 request headers")),
        };

        let hosts = parsed.hosts();
        let route = match self.config.find_route(&hosts, &parsed.path) {
            Some(route) => route.clone(),
            None => return Err((send, 404, "No matching route")),
        };

        let mut upstream_request = match build_upstream_request(&headers, &parsed, &route) {
            Ok(request) => request,
            Err(_) => return Err((send, 400, "Invalid upstream request")),
        };

        if let Some(new_uri) = rewrite_uri(&upstream_request.uri, &route).ok().flatten() {
            upstream_request.set_uri(new_uri);
        }
        if add_upstream_path(&mut upstream_request, &route).is_err() {
            return Err((send, 400, "Invalid upstream request URI"));
        }

        Ok(H3Request {
            method: parsed.method,
            path: parsed.path,
            authority: parsed.authority,
            upstream_request,
            route,
            recv,
            read_fin,
            send,
        })
    }
}

struct H3Request {
    method: String,
    path: String,
    authority: Option<String>,
    upstream_request: RequestHeader,
    route: RouteConfig,
    recv: tokio_quiche::http3::driver::InboundFrameStream,
    read_fin: bool,
    send: OutboundFrameSender,
}

struct ParsedH3Headers {
    method: String,
    path: String,
    authority: Option<String>,
    host_header: Option<String>,
}

impl ParsedH3Headers {
    fn from_headers(headers: &[Header]) -> H3Result<Self> {
        let mut method = None;
        let mut path = None;
        let mut authority = None;
        let mut host_header = None;

        for header in headers {
            match header.name() {
                b":method" => method = Some(header_value_to_string(header.value())?),
                b":path" => path = Some(header_value_to_string(header.value())?),
                b":authority" => authority = Some(header_value_to_string(header.value())?),
                b"host" => host_header = Some(header_value_to_string(header.value())?),
                _ => {}
            }
        }

        Ok(Self {
            method: method.ok_or("missing :method")?,
            path: path.unwrap_or_else(|| "/".to_string()),
            authority,
            host_header,
        })
    }

    fn hosts(&self) -> Vec<&str> {
        self.host_header
            .as_deref()
            .into_iter()
            .chain(self.authority.as_deref())
            .collect()
    }

    fn original_host(&self) -> Option<&str> {
        self.host_header.as_deref().or(self.authority.as_deref())
    }
}

fn build_upstream_request(
    headers: &[Header],
    parsed: &ParsedH3Headers,
    route: &RouteConfig,
) -> H3Result<RequestHeader> {
    let method = http::Method::from_bytes(parsed.method.as_bytes())?;
    let mut request = RequestHeader::build(method, parsed.path.as_bytes(), Some(headers.len()))?;

    for header in headers {
        let name = header.name();
        if name.starts_with(b":") || is_hop_by_hop_header(name) {
            continue;
        }

        let header_name = http::header::HeaderName::from_bytes(name)?;
        let header_value = http::header::HeaderValue::from_bytes(header.value())?;
        request.append_header(header_name, header_value)?;
    }

    if let Ok(parsed_upstream) = Url::parse(&route.upstream.url) {
        if let Some(host) = parsed_upstream.host_str() {
            let host_value = if let Some(port) = parsed_upstream.port() {
                format!("{}:{}", host, port)
            } else {
                host.to_string()
            };
            request.insert_header("Host", host_value)?;
        }
    }

    for (key, value) in &route.headers {
        let expanded_value = expand_header_value(value, parsed.original_host());
        let header_name = http::header::HeaderName::from_bytes(key.as_bytes())?;
        let header_value = http::header::HeaderValue::from_bytes(expanded_value.as_bytes())?;
        request.insert_header(header_name, header_value)?;
    }

    Ok(request)
}

fn parse_upstream(route: &RouteConfig) -> H3Result<(String, u16, bool)> {
    let parsed = Url::parse(&route.upstream.url)?;
    let host = parsed.host_str().ok_or("upstream URL has no host")?;
    let default_port = match route.upstream.protocol {
        Protocol::Http | Protocol::Ws | Protocol::Grpc => 80,
        Protocol::Https | Protocol::Wss | Protocol::GrpcTls => 443,
    };
    Ok((
        host.to_string(),
        parsed.port().unwrap_or(default_port),
        route.upstream.protocol.is_tls(),
    ))
}

fn add_upstream_path(request: &mut RequestHeader, route: &RouteConfig) -> H3Result<()> {
    let parsed = Url::parse(&route.upstream.url)?;
    let upstream_path = parsed.path();
    if upstream_path.is_empty() || upstream_path == "/" {
        return Ok(());
    }

    let original_uri = &request.uri;
    let original_path = original_uri.path();
    let original_query = original_uri.query();
    let new_path = if original_path == "/" {
        upstream_path.to_string()
    } else {
        format!("{}{}", upstream_path.trim_end_matches('/'), original_path)
    };
    let path_and_query = if let Some(query) = original_query {
        format!("{}?{}", new_path, query)
    } else {
        new_path
    };

    request.set_uri(
        http::Uri::builder()
            .path_and_query(path_and_query)
            .build()?,
    );
    Ok(())
}

fn rewrite_uri(uri: &http::Uri, route: &RouteConfig) -> H3Result<Option<http::Uri>> {
    let mut rewritten = false;
    let mut parts = uri.clone().into_parts();

    let path = uri.path();
    let mut new_path = path.to_string();
    if let (Some(regex), Some(rewrite)) = (&route.rewrite_regex, &route.rewrite) {
        let res = regex.replace(path, &rewrite.to);
        if res != path {
            new_path = res.to_string();
            rewritten = true;
        }
    }

    let had_query = uri.query().is_some();
    let query = uri.query().unwrap_or("");
    let mut new_query = query.to_string();
    if let (Some(regex), Some(rewrite)) = (&route.rewrite_query_regex, &route.rewrite_query) {
        let res = regex.replace(query, &rewrite.to);
        if res != query {
            new_query = res.to_string();
            rewritten = true;
        }
    }

    if !rewritten {
        return Ok(None);
    }

    let path_and_query = if had_query || !new_query.is_empty() {
        format!("{}?{}", new_path, new_query)
    } else {
        new_path
    };
    parts.path_and_query = Some(path_and_query.parse()?);
    Ok(Some(http::Uri::from_parts(parts)?))
}

async fn write_request_body(
    upstream: &mut HttpSession,
    mut recv: tokio_quiche::http3::driver::InboundFrameStream,
    read_fin: bool,
) -> H3Result<()> {
    if read_fin {
        upstream.finish_request_body().await?;
        return Ok(());
    }

    while let Some(frame) = recv.recv().await {
        match frame {
            InboundFrame::Body(body, fin) => {
                if !body.is_empty() {
                    upstream.write_request_body(body.freeze(), fin).await?;
                }
                if fin {
                    break;
                }
            }
            InboundFrame::Datagram(_) => {}
        }
    }

    upstream.finish_request_body().await?;
    Ok(())
}

async fn send_response_headers(
    mut send: OutboundFrameSender,
    response: &ResponseHeader,
    route: &RouteConfig,
) -> H3Result<OutboundFrameSender> {
    let mut headers = vec![Header::new(b":status", response.status.as_str().as_bytes())];

    for (name, value) in response.headers.iter() {
        if is_hop_by_hop_header(name.as_str().as_bytes())
            || route
                .hide_headers
                .iter()
                .any(|hidden| hidden.eq_ignore_ascii_case(name.as_str()))
        {
            continue;
        }
        headers.push(Header::new(name.as_str().as_bytes(), value.as_bytes()));
    }

    send.send(OutboundFrame::Headers(headers, None)).await?;
    Ok(send)
}

async fn send_response_body(
    mut send: OutboundFrameSender,
    upstream: &mut HttpSession,
) -> H3Result<()> {
    while let Some(chunk) = upstream.read_response_body().await? {
        if !chunk.is_empty() {
            send.send(OutboundFrame::Body(chunk, false)).await?;
        }
    }
    send.send(OutboundFrame::Body(Bytes::new(), true)).await?;
    Ok(())
}

async fn send_simple_response(send: &mut OutboundFrameSender, status: u16, body: &'static str) {
    let status = status.to_string();
    let headers = vec![
        Header::new(b":status", status.as_bytes()),
        Header::new(b"content-type", b"text/plain; charset=utf-8"),
        Header::new(b"content-length", body.len().to_string().as_bytes()),
    ];
    let _ = send.send(OutboundFrame::Headers(headers, None)).await;
    let _ = send
        .send(OutboundFrame::Body(
            Bytes::from_static(body.as_bytes()),
            true,
        ))
        .await;
}

fn header_value_to_string(value: &[u8]) -> H3Result<String> {
    Ok(std::str::from_utf8(value)?.to_string())
}

fn is_hop_by_hop_header(name: &[u8]) -> bool {
    matches!(
        name.to_ascii_lowercase().as_slice(),
        b"connection"
            | b"keep-alive"
            | b"proxy-authenticate"
            | b"proxy-authorization"
            | b"te"
            | b"trailer"
            | b"transfer-encoding"
            | b"upgrade"
            | b"alt-svc"
    )
}

fn expand_header_value(template: &str, host: Option<&str>) -> String {
    let host = host.unwrap_or("");
    template.replace("$http_host", host).replace("$host", host)
}

fn is_local_upstream(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

struct DynamicQuicCert {
    cert_store: Arc<CertStore>,
}

impl DynamicQuicCert {
    fn new(cert_store: Arc<CertStore>) -> Self {
        Self { cert_store }
    }
}

impl tokio_quiche::quic::ConnectionHook for DynamicQuicCert {
    fn create_custom_ssl_context_builder(
        &self,
        _settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        let mut builder = SslContextBuilder::new(SslMethod::tls()).ok()?;

        if let Some(default_cert) = self.cert_store.get_default_parsed() {
            if let Err(e) = apply_cert_to_context(&mut builder, &default_cert) {
                error!("Failed to set default QUIC certificate: {}", e);
                return None;
            }
        } else {
            warn!("HTTP/3 dynamic certificate store has no default certificate");
        }

        let cert_store = self.cert_store.clone();
        builder.set_servername_callback(move |ssl, _alert| {
            let cert = ssl
                .servername(NameType::HOST_NAME)
                .and_then(|domain| cert_store.get_parsed_for_domain_or_default(domain));

            if let Some(cert) = cert {
                apply_cert_to_ssl(ssl, &cert).map_err(|e| {
                    error!("Failed to set QUIC certificate from SNI: {}", e);
                    SniError::ALERT_FATAL
                })?;
            }

            Ok(())
        });

        Some(builder)
    }
}

fn apply_cert_to_context(
    builder: &mut SslContextBuilder,
    cert: &ParsedCert,
) -> Result<(), boring::error::ErrorStack> {
    builder.set_certificate(&cert.leaf_cert)?;
    for chain_cert in &cert.chain_certs {
        builder.add_extra_chain_cert(chain_cert.clone())?;
    }
    builder.set_private_key(&cert.private_key)?;
    Ok(())
}

fn apply_cert_to_ssl(ssl: &mut SslRef, cert: &ParsedCert) -> Result<(), boring::error::ErrorStack> {
    ssl.set_certificate(&cert.leaf_cert)?;
    for chain_cert in &cert.chain_certs {
        ssl.add_chain_cert(chain_cert)?;
    }
    ssl.set_private_key(&cert.private_key)?;
    Ok(())
}
