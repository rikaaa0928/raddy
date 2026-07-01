use async_trait::async_trait;
use boring::ssl::{NameType, SniError, SslContextBuilder, SslMethod, SslRef};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use pingora::connectors::http::Connector as HttpConnector;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::protocols::http::client::HttpSession;
use pingora::protocols::ALPN;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use pingora::upstreams::peer::HttpPeer;
use std::error::Error;
use std::future::poll_fn;
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
                            let http3_settings = Http3Settings {
                                enable_extended_connect: true,
                                ..Http3Settings::default()
                            };
                            let (driver, mut controller) = ServerH3Driver::new(http3_settings);
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
            is_http2_upstream,
            is_websocket,
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

        info!(
            "HTTP/3 request: authority={:?}, method={}, path={}, upstream={}",
            authority, method, path, route.upstream.url
        );

        let (host, port, use_tls) = parse_upstream(&route)?;
        let mut peer = HttpPeer::new((host.as_str(), port), use_tls, host.clone());
        if is_http2_upstream {
            peer.options.alpn = ALPN::H2;
        } else {
            peer.options.set_http_version(1, 1);
        }
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
            if is_websocket {
                proxy_websocket_tunnel(send, &mut upstream, recv, read_fin, &route).await
            } else {
                proxy_http_stream(send, &mut upstream, recv, read_fin, &route).await
            }
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

        let is_websocket = route.upstream.protocol.is_websocket() || parsed.is_websocket_connect();
        if is_websocket && !parsed.is_websocket_connect() {
            return Err((
                send,
                400,
                "HTTP/3 WebSocket proxying requires extended CONNECT",
            ));
        }

        let mut upstream_request =
            match build_upstream_request(&headers, &parsed, &route, is_websocket) {
                Ok(request) => request,
                Err(_) => return Err((send, 400, "Invalid upstream request")),
            };

        if let Some(new_uri) = rewrite_uri(&upstream_request.uri, &route).ok().flatten() {
            upstream_request.set_uri(new_uri);
        }
        if add_upstream_path(&mut upstream_request, &route).is_err() {
            return Err((send, 400, "Invalid upstream request URI"));
        }
        let is_http2_upstream =
            route.upstream.protocol.is_http2() || request_content_type_is_grpc(&upstream_request);
        if is_http2_upstream && upstream_request.insert_header("te", "trailers").is_err() {
            return Err((send, 400, "Invalid upstream request"));
        }
        if is_websocket && ensure_websocket_upgrade_headers(&mut upstream_request).is_err() {
            return Err((send, 400, "Invalid upstream WebSocket request"));
        }

        Ok(H3Request {
            method: parsed.method,
            path: parsed.path,
            authority: parsed.authority,
            upstream_request,
            route,
            is_http2_upstream,
            is_websocket,
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
    is_http2_upstream: bool,
    is_websocket: bool,
    recv: tokio_quiche::http3::driver::InboundFrameStream,
    read_fin: bool,
    send: OutboundFrameSender,
}

struct ParsedH3Headers {
    method: String,
    path: String,
    authority: Option<String>,
    host_header: Option<String>,
    protocol: Option<String>,
}

impl ParsedH3Headers {
    fn from_headers(headers: &[Header]) -> H3Result<Self> {
        let mut method = None;
        let mut path = None;
        let mut authority = None;
        let mut host_header = None;
        let mut protocol = None;

        for header in headers {
            match header.name() {
                b":method" => method = Some(header_value_to_string(header.value())?),
                b":path" => path = Some(header_value_to_string(header.value())?),
                b":authority" => authority = Some(header_value_to_string(header.value())?),
                b":protocol" => protocol = Some(header_value_to_string(header.value())?),
                b"host" => host_header = Some(header_value_to_string(header.value())?),
                _ => {}
            }
        }

        Ok(Self {
            method: method.ok_or("missing :method")?,
            path: path.unwrap_or_else(|| "/".to_string()),
            authority,
            host_header,
            protocol,
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

    fn is_websocket_connect(&self) -> bool {
        self.method.eq_ignore_ascii_case("CONNECT")
            && self
                .protocol
                .as_deref()
                .is_some_and(|protocol| protocol.eq_ignore_ascii_case("websocket"))
    }
}

fn build_upstream_request(
    headers: &[Header],
    parsed: &ParsedH3Headers,
    route: &RouteConfig,
    is_websocket: bool,
) -> H3Result<RequestHeader> {
    let method = if is_websocket {
        http::Method::GET
    } else {
        http::Method::from_bytes(parsed.method.as_bytes())?
    };
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
        Protocol::Http | Protocol::Ws | Protocol::H2c | Protocol::Grpc => 80,
        Protocol::Https | Protocol::Wss | Protocol::H2 | Protocol::GrpcTls => 443,
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

fn request_content_type_is_grpc(request: &RequestHeader) -> bool {
    request
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/grpc"))
}

fn ensure_websocket_upgrade_headers(request: &mut RequestHeader) -> H3Result<()> {
    request.insert_header(http::header::CONNECTION, "Upgrade")?;
    request.insert_header(http::header::UPGRADE, "websocket")?;
    if !request.headers.contains_key("sec-websocket-version") {
        request.insert_header("sec-websocket-version", "13")?;
    }
    Ok(())
}

async fn proxy_http_stream(
    send: OutboundFrameSender,
    upstream: &mut HttpSession,
    mut recv: tokio_quiche::http3::driver::InboundFrameStream,
    read_fin: bool,
    route: &RouteConfig,
) -> H3Result<()> {
    let mut downstream_finished = read_fin;
    if downstream_finished {
        upstream.finish_request_body().await?;
    }

    let mut send = Some(send);

    loop {
        tokio::select! {
            frame = recv.recv(), if !downstream_finished => {
                downstream_finished = forward_request_frame(upstream, frame).await?;
            }
            response = read_response_header_cancel_safe(upstream) => {
                response?;
                let response = upstream
                    .response_header()
                    .ok_or("upstream response header missing")?
                    .clone();
                let sender = send.take().ok_or("downstream response sender missing")?;
                let sender = send_response_headers(sender, &response, route).await?;
                return relay_http_bodies(sender, upstream, recv, downstream_finished, route).await;
            }
        }
    }
}

async fn relay_http_bodies(
    mut send: OutboundFrameSender,
    upstream: &mut HttpSession,
    mut recv: tokio_quiche::http3::driver::InboundFrameStream,
    mut downstream_finished: bool,
    route: &RouteConfig,
) -> H3Result<()> {
    loop {
        tokio::select! {
            frame = recv.recv(), if !downstream_finished => {
                downstream_finished = forward_request_frame(upstream, frame).await?;
            }
            chunk = upstream.read_response_body() => {
                match chunk {
                    Ok(Some(chunk)) => {
                        if !chunk.is_empty() {
                            send.send(OutboundFrame::Body(chunk, false)).await?;
                        }
                    }
                    Ok(None) => {
                        send_response_trailers_or_fin(send, upstream, route).await?;
                        return Ok(());
                    }
                    Err(e) => return Err(Box::new(e)),
                }
            }
        }
    }
}

async fn read_response_header_cancel_safe(upstream: &mut HttpSession) -> H3Result<()> {
    if let HttpSession::H2(h2) = upstream {
        poll_fn(|cx| h2.poll_read_response_header(cx))
            .await
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;
        return Ok(());
    }

    upstream.read_response_header().await?;
    Ok(())
}

async fn forward_request_frame(
    upstream: &mut HttpSession,
    frame: Option<InboundFrame>,
) -> H3Result<bool> {
    match frame {
        Some(InboundFrame::Body(body, fin)) => {
            if !body.is_empty() {
                upstream.write_request_body(body.freeze(), false).await?;
            }
            if fin {
                upstream.finish_request_body().await?;
                return Ok(true);
            }
        }
        Some(InboundFrame::Datagram(_)) => {}
        None => {
            upstream.finish_request_body().await?;
            return Ok(true);
        }
    }

    Ok(false)
}

async fn proxy_websocket_tunnel(
    send: OutboundFrameSender,
    upstream: &mut HttpSession,
    recv: tokio_quiche::http3::driver::InboundFrameStream,
    read_fin: bool,
    route: &RouteConfig,
) -> H3Result<()> {
    upstream.read_response_header().await?;
    let response = upstream
        .response_header()
        .ok_or("upstream response header missing")?
        .clone();

    if response.status != http::StatusCode::SWITCHING_PROTOCOLS {
        let send = send_response_headers(send, &response, route).await?;
        return send_response_body(send, upstream, route).await;
    }

    maybe_upgrade_body_writer(upstream);
    let send = send_websocket_connect_response(send, &response, route).await?;
    relay_websocket_data(send, upstream, recv, read_fin).await
}

fn maybe_upgrade_body_writer(upstream: &mut HttpSession) {
    if let HttpSession::H1(h1) = upstream {
        h1.maybe_upgrade_body_writer();
    }
}

async fn send_websocket_connect_response(
    mut send: OutboundFrameSender,
    response: &ResponseHeader,
    route: &RouteConfig,
) -> H3Result<OutboundFrameSender> {
    let mut headers = vec![Header::new(b":status", b"200")];

    for (name, value) in response.headers.iter() {
        let name_bytes = name.as_str().as_bytes();
        let keep_websocket_response_header = matches!(
            name.as_str().to_ascii_lowercase().as_str(),
            "sec-websocket-accept" | "sec-websocket-protocol" | "sec-websocket-extensions"
        );
        if !keep_websocket_response_header
            || route
                .hide_headers
                .iter()
                .any(|hidden| hidden.eq_ignore_ascii_case(name.as_str()))
        {
            continue;
        }
        headers.push(Header::new(name_bytes, value.as_bytes()));
    }

    send.send(OutboundFrame::Headers(headers, None)).await?;
    Ok(send)
}

async fn relay_websocket_data(
    mut send: OutboundFrameSender,
    upstream: &mut HttpSession,
    mut recv: tokio_quiche::http3::driver::InboundFrameStream,
    read_fin: bool,
) -> H3Result<()> {
    let mut downstream_finished = read_fin;
    if downstream_finished {
        upstream.finish_request_body().await?;
    }

    loop {
        tokio::select! {
            frame = recv.recv(), if !downstream_finished => {
                match frame {
                    Some(InboundFrame::Body(body, fin)) => {
                        if !body.is_empty() {
                            upstream.write_request_body(body.freeze(), false).await?;
                        }
                        if fin {
                            downstream_finished = true;
                            upstream.finish_request_body().await?;
                        }
                    }
                    Some(InboundFrame::Datagram(_)) => {}
                    None => {
                        downstream_finished = true;
                        upstream.finish_request_body().await?;
                    }
                }
            }
            chunk = upstream.read_response_body() => {
                match chunk {
                    Ok(Some(chunk)) => {
                        if !chunk.is_empty() {
                            send.send(OutboundFrame::Body(chunk, false)).await?;
                        }
                    }
                    Ok(None) => {
                        send.send(OutboundFrame::Body(Bytes::new(), true)).await?;
                        return Ok(());
                    }
                    Err(e) => return Err(Box::new(e)),
                }
            }
        }
    }
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
    route: &RouteConfig,
) -> H3Result<()> {
    while let Some(chunk) = upstream.read_response_body().await? {
        if !chunk.is_empty() {
            send.send(OutboundFrame::Body(chunk, false)).await?;
        }
    }

    send_response_trailers_or_fin(send, upstream, route).await
}

async fn send_response_trailers_or_fin(
    mut send: OutboundFrameSender,
    upstream: &mut HttpSession,
    route: &RouteConfig,
) -> H3Result<()> {
    if let Some(trailers) = read_response_trailers(upstream).await? {
        let trailers = response_trailers_to_h3(trailers, route);
        if !trailers.is_empty() {
            send.send(OutboundFrame::Trailers(trailers, None)).await?;
            return Ok(());
        }
    }

    send.send(OutboundFrame::Body(Bytes::new(), true)).await?;
    Ok(())
}

async fn read_response_trailers(upstream: &mut HttpSession) -> H3Result<Option<http::HeaderMap>> {
    match upstream {
        HttpSession::H2(h2) => Ok(h2.read_trailers().await?),
        HttpSession::H1(_) | HttpSession::Custom(_) => Ok(None),
    }
}

fn response_trailers_to_h3(trailers: http::HeaderMap, route: &RouteConfig) -> Vec<Header> {
    let mut headers = Vec::with_capacity(trailers.len());
    for (name, value) in trailers.iter() {
        if name.as_str().starts_with(':')
            || is_hop_by_hop_header(name.as_str().as_bytes())
            || route
                .hide_headers
                .iter()
                .any(|hidden| hidden.eq_ignore_ascii_case(name.as_str()))
        {
            continue;
        }
        headers.push(Header::new(name.as_str().as_bytes(), value.as_bytes()));
    }
    headers
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

        let cert_store = self.cert_store.clone();
        builder.set_servername_callback(move |ssl, _alert| {
            let Some(domain) = ssl.servername(NameType::HOST_NAME) else {
                warn!("HTTP/3 TLS handshake rejected: missing SNI");
                return Err(SniError::ALERT_FATAL);
            };

            let Some(cert) = cert_store.get_parsed_for_domain(domain) else {
                warn!("HTTP/3 TLS handshake rejected: no certificate configured for SNI {domain}");
                return Err(SniError::ALERT_FATAL);
            };

            apply_cert_to_ssl(ssl, &cert).map_err(|e| {
                error!("Failed to set QUIC certificate from SNI: {}", e);
                SniError::ALERT_FATAL
            })?;

            Ok(())
        });

        Some(builder)
    }
}

fn apply_cert_to_ssl(ssl: &mut SslRef, cert: &ParsedCert) -> Result<(), boring::error::ErrorStack> {
    ssl.set_certificate(&cert.leaf_cert)?;
    for chain_cert in &cert.chain_certs {
        ssl.add_chain_cert(chain_cert)?;
    }
    ssl.set_private_key(&cert.private_key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpstreamConfig;
    use std::collections::HashMap;

    fn test_route(protocol: Protocol) -> RouteConfig {
        RouteConfig {
            hosts: None,
            path_prefix: None,
            upstream: UpstreamConfig {
                url: "http://backend.example".to_string(),
                protocol,
            },
            headers: HashMap::new(),
            hide_headers: Vec::new(),
            force_https_redirect: None,
            http3: None,
            rewrite: None,
            rewrite_regex: None,
            rewrite_query: None,
            rewrite_query_regex: None,
        }
    }

    #[test]
    fn parses_websocket_extended_connect() {
        let headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"websocket"),
            Header::new(b":path", b"/chat"),
            Header::new(b":authority", b"example.com"),
        ];

        let parsed = ParsedH3Headers::from_headers(&headers).unwrap();

        assert!(parsed.is_websocket_connect());
        assert_eq!(parsed.path, "/chat");
        assert_eq!(parsed.authority.as_deref(), Some("example.com"));
    }

    #[test]
    fn websocket_upstream_request_uses_get_and_upgrade_headers() {
        let route = test_route(Protocol::Ws);
        let headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"websocket"),
            Header::new(b":path", b"/chat"),
            Header::new(b":authority", b"example.com"),
            Header::new(b"sec-websocket-key", b"test-key"),
        ];
        let parsed = ParsedH3Headers::from_headers(&headers).unwrap();

        let mut request = build_upstream_request(&headers, &parsed, &route, true).unwrap();
        ensure_websocket_upgrade_headers(&mut request).unwrap();

        assert_eq!(request.method, http::Method::GET);
        assert_eq!(request.uri.path(), "/chat");
        assert_eq!(
            request.headers.get(http::header::UPGRADE).unwrap(),
            "websocket"
        );
        assert_eq!(
            request.headers.get(http::header::CONNECTION).unwrap(),
            "Upgrade"
        );
        assert_eq!(
            request.headers.get("sec-websocket-key").unwrap(),
            "test-key"
        );
    }

    #[test]
    fn response_trailers_filter_hidden_and_hop_by_hop_headers() {
        let mut route = test_route(Protocol::Grpc);
        route.hide_headers = vec!["x-hidden".to_string()];
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        trailers.insert("grpc-message", "ok".parse().unwrap());
        trailers.insert("te", "trailers".parse().unwrap());
        trailers.insert("x-hidden", "secret".parse().unwrap());

        let h3_trailers = response_trailers_to_h3(trailers, &route);
        let names = h3_trailers
            .iter()
            .map(|header| header.name().to_vec())
            .collect::<Vec<_>>();

        assert!(names.contains(&b"grpc-status".to_vec()));
        assert!(names.contains(&b"grpc-message".to_vec()));
        assert!(!names.contains(&b"te".to_vec()));
        assert!(!names.contains(&b"x-hidden".to_vec()));
    }
}
