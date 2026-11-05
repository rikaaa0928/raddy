//! HTTP/3 Support via Quinn and h3
//!
//! This module provides HTTP/3 (over QUIC/UDP) proxying powered by `quinn` and `h3`.
//! It dynamically resolves TLS certificates from `CertStore` via SNI (`ResolvesServerCert`),
//! terminates HTTP/3 connections, and reverse-proxies requests to the local
//! HTTP/2 TCP listener with appropriate `X-Forwarded-*` and `X-Real-IP` headers.

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use log::{debug, error, info, trace, warn};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::acme::CertStore;
use crate::config::Config;

const H2_STREAM_WINDOW_SIZE: u32 = 8 * 1024 * 1024;
const H2_CONNECTION_WINDOW_SIZE: u32 = 16 * 1024 * 1024;
const H2_MAX_FRAME_SIZE: u32 = 64 * 1024;

/// Dynamic SNI certificate resolver for Quinn / Rustls backed by `CertStore`.
pub struct DynamicQuicCertResolver {
    cert_store: Arc<CertStore>,
}

impl std::fmt::Debug for DynamicQuicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicQuicCertResolver").finish()
    }
}

impl DynamicQuicCertResolver {
    pub fn new(cert_store: Arc<CertStore>) -> Self {
        Self { cert_store }
    }
}

impl rustls::server::ResolvesServerCert for DynamicQuicCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello
            .server_name()
            .map(|s| s.trim_end_matches('.').to_ascii_lowercase());

        let parsed = if let Some(domain) = sni.as_deref() {
            self.cert_store.get_parsed_for_domain(domain)
        } else {
            None
        }
        .or_else(|| self.cert_store.get_any_parsed_cert());

        match parsed {
            Some(cert) => {
                debug!("HTTP/3 loaded certificate for SNI: {:?}", sni);
                Some(cert.rustls_cert.clone())
            }
            None => {
                warn!("HTTP/3 TLS handshake rejected: no certificate for SNI {:?}", sni);
                None
            }
        }
    }
}

/// Connection pool for local HTTP/2 requests
#[derive(Clone)]
struct H2ClientPool {
    target_addr: String,
    is_tls: bool,
    stream_window_size: u32,
    connection_window_size: u32,
    tls_connector: Option<boring::ssl::SslConnector>,
    current_sender: Arc<Mutex<Option<h2::client::SendRequest<Bytes>>>>,
}

impl H2ClientPool {
    fn new(
        target_addr: String,
        is_tls: bool,
        stream_window_size: u32,
        connection_window_size: u32,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let tls_connector = if is_tls {
            let mut builder = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())?;
            builder.set_verify(boring::ssl::SslVerifyMode::NONE);
            builder.set_alpn_protos(b"\x02h2")?;
            Some(builder.build())
        } else {
            None
        };

        Ok(Self {
            target_addr,
            is_tls,
            stream_window_size,
            connection_window_size,
            tls_connector,
            current_sender: Arc::new(Mutex::new(None)),
        })
    }

    fn h2_client_builder(&self) -> h2::client::Builder {
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(self.stream_window_size)
            .initial_connection_window_size(self.connection_window_size)
            .max_frame_size(H2_MAX_FRAME_SIZE);
        builder
    }

    async fn get_sender(
        &self,
        sni: &str,
    ) -> Result<h2::client::SendRequest<Bytes>, Box<dyn std::error::Error + Send + Sync>> {
        let mut guard = self.current_sender.lock().await;
        if let Some(mut sender) = guard.clone() {
            if std::future::poll_fn(|cx| sender.poll_ready(cx)).await.is_ok() {
                return Ok(sender);
            }
        }

        let tcp = tokio::net::TcpStream::connect(&self.target_addr).await?;
        let _ = tcp.set_nodelay(true);
        let h2_builder = self.h2_client_builder();

        let sender = if self.is_tls {
            let connector = self.tls_connector.as_ref().expect("TLS connector present");
            let mut conf = connector.configure()?;
            conf.set_use_server_name_indication(true);
            let tls = tokio_boring::connect(conf, sni, tcp).await?;
            let (sender, conn) = h2_builder.handshake(tls).await?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("Local H2 TLS connection closed: {}", e);
                }
            });
            sender
        } else {
            let (sender, conn) = h2_builder.handshake(tcp).await?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("Local H2 cleartext connection closed: {}", e);
                }
            });
            sender
        };

        *guard = Some(sender.clone());
        Ok(sender)
    }
}

/// HTTP/3 Background Service for Pingora powered by Quinn
pub struct Http3Service {
    config: Arc<Config>,
    cert_store: Arc<CertStore>,
    listen_addr: String,
    h2_target: (String, bool),
}

impl Http3Service {
    pub fn new(
        config: Arc<Config>,
        cert_store: Arc<CertStore>,
        listen_addr: String,
        h2_target: (String, bool),
    ) -> Self {
        Self {
            config,
            cert_store,
            listen_addr,
            h2_target,
        }
    }

    fn create_quinn_server_config(
        &self,
    ) -> Result<quinn::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(DynamicQuicCertResolver::new(
                self.cert_store.clone(),
            )));

        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        tls_config.max_early_data_size = u32::MAX;

        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));

        let mut transport = quinn::TransportConfig::default();
        let use_bbr = self
            .config
            .listen
            .http3_congestion_control
            .as_deref()
            .map(|s| !s.eq_ignore_ascii_case("cubic"))
            .unwrap_or(true);
        if use_bbr {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }

        if let Some(idle_secs) = self
            .config
            .timeouts
            .http3_max_idle_timeout_secs
            .filter(|&s| s > 0)
        {
            transport.max_idle_timeout(Some(Duration::from_secs(idle_secs).try_into()?));
        } else {
            transport.max_idle_timeout(None);
        }

        let keep_alive = self
            .config
            .timeouts
            .effective_http3_keep_alive_interval_secs()
            .map(Duration::from_secs);
        transport.keep_alive_interval(keep_alive);

        let conn_win = self
            .config
            .listen
            .http3_connection_window_size
            .unwrap_or(H2_CONNECTION_WINDOW_SIZE);
        let stream_win = self
            .config
            .listen
            .http3_stream_window_size
            .unwrap_or(H2_STREAM_WINDOW_SIZE);
        let max_streams = self
            .config
            .listen
            .http3_max_concurrent_streams
            .unwrap_or(256);

        transport.receive_window(quinn::VarInt::from_u32(conn_win));
        transport.stream_receive_window(quinn::VarInt::from_u32(stream_win));
        transport.send_window(u64::from(conn_win));
        transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(max_streams));
        transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(max_streams));

        server_config.transport_config(Arc::new(transport));
        Ok(server_config)
    }
}

#[async_trait]
impl BackgroundService for Http3Service {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        info!("Starting HTTP/3 (Quinn) listener on UDP {}", self.listen_addr);
        info!(
            "HTTP/3 will reverse-proxy requests to HTTP/2 at {} (TLS: {})",
            self.h2_target.0, self.h2_target.1
        );

        let listen_sock_addr: SocketAddr = match self.listen_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                error!("Invalid HTTP/3 listen address '{}': {}", self.listen_addr, e);
                return;
            }
        };

        let server_config = match self.create_quinn_server_config() {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Failed to initialize Quinn server config: {}", e);
                return;
            }
        };

        let endpoint = match quinn::Endpoint::server(server_config, listen_sock_addr) {
            Ok(ep) => ep,
            Err(e) => {
                error!(
                    "Failed to bind HTTP/3 Quinn UDP endpoint on {}: {}",
                    self.listen_addr, e
                );
                return;
            }
        };

        let h3_listen_port = endpoint
            .local_addr()
            .map(|a| a.port())
            .unwrap_or_else(|_| listen_sock_addr.port());

        let stream_win = self
            .config
            .listen
            .http3_stream_window_size
            .unwrap_or(H2_STREAM_WINDOW_SIZE);
        let conn_win = self
            .config
            .listen
            .http3_connection_window_size
            .unwrap_or(H2_CONNECTION_WINDOW_SIZE);

        let h2_pool = match H2ClientPool::new(
            self.h2_target.0.clone(),
            self.h2_target.1,
            stream_win,
            conn_win,
        ) {
            Ok(pool) => pool,
            Err(e) => {
                error!("Failed to initialize local H2 client pool: {}", e);
                return;
            }
        };

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    info!("HTTP/3 listener shutting down");
                    endpoint.close(0u32.into(), b"server shutting down");
                    break;
                }
                incoming_opt = endpoint.accept() => {
                    let Some(incoming) = incoming_opt else {
                        break;
                    };
                    let peer_addr = incoming.remote_address();
                    let h2_pool = h2_pool.clone();

                    tokio::spawn(async move {
                        let quinn_conn = match incoming.await {
                            Ok(c) => c,
                            Err(e) => {
                                trace!("QUIC handshake failed from {}: {}", peer_addr, e);
                                return;
                            }
                        };

                        debug!("QUIC connection established from {}", peer_addr);
                        let mut h3_builder = h3::server::builder();
                        h3_builder.send_grease(false);
                        let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
                            match h3_builder.build(h3_quinn::Connection::new(quinn_conn)).await {
                                Ok(c) => c,
                                Err(e) => {
                                    debug!("Failed to initialize HTTP/3 connection from {}: {}", peer_addr, e);
                                    return;
                                }
                            };

                        loop {
                            match h3_conn.accept().await {
                                Ok(Some(resolver)) => {
                                    let h2_pool = h2_pool.clone();
                                    tokio::spawn(async move {
                                        match resolver.resolve_request().await {
                                            Ok((req, stream)) => {
                                                handle_h3_stream(
                                                    req,
                                                    stream,
                                                    peer_addr,
                                                    h3_listen_port,
                                                    h2_pool,
                                                )
                                                .await;
                                            }
                                            Err(e) => {
                                                debug!(
                                                    "Failed to resolve HTTP/3 request from {}: {}",
                                                    peer_addr, e
                                                );
                                            }
                                        }
                                    });
                                }
                                Ok(None) => {
                                    debug!("HTTP/3 connection closed cleanly by {}", peer_addr);
                                    break;
                                }
                                Err(e) => {
                                    trace!("HTTP/3 accept error from {}: {}", peer_addr, e);
                                    break;
                                }
                            }
                        }
                    });
                }
            }
        }
    }
}

async fn send_h3_error(
    send_stream: &mut h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    status: u16,
    message: &str,
) {
    if let Ok(resp) = http::Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(())
    {
        if send_stream.send_response(resp).await.is_ok() {
            let _ = send_stream.send_data(Bytes::copy_from_slice(message.as_bytes())).await;
            let _ = send_stream.finish().await;
        }
    }
}

async fn send_h2_data_with_flow_control(
    h2_send: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end_of_stream: bool,
) -> Result<(), h2::Error> {
    if data.is_empty() {
        return h2_send.send_data(data, end_of_stream);
    }
    while !data.is_empty() {
        let want = data.len();
        h2_send.reserve_capacity(want);
        match std::future::poll_fn(|cx| h2_send.poll_capacity(cx)).await {
            Some(Ok(cap)) => {
                let to_send = data.split_to(want.min(cap));
                let is_last = data.is_empty() && end_of_stream;
                h2_send.send_data(to_send, is_last)?;
            }
            Some(Err(e)) => return Err(e),
            None => {
                return Err(h2::Reason::CANCEL.into());
            }
        }
    }
    Ok(())
}

async fn handle_h3_stream(
    req: http::Request<()>,
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    client_addr: SocketAddr,
    h3_listen_port: u16,
    h2_pool: H2ClientPool,
) {
    let (mut h3_send, mut h3_recv) = stream.split();

    let (parts, _) = req.into_parts();
    let method = parts.method;
    let orig_uri = parts.uri;

    let scheme = orig_uri.scheme_str().unwrap_or("https").to_string();
    let authority = orig_uri
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            parts
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "localhost".to_string());

    let path_and_query = orig_uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let uri_str = if path_and_query.starts_with('/') {
        format!("{}://{}{}", scheme, authority, path_and_query)
    } else {
        format!("{}://{}/{}", scheme, authority, path_and_query)
    };

    let target_uri: http::Uri = match uri_str.parse() {
        Ok(u) => u,
        Err(_) => {
            send_h3_error(&mut h3_send, 400, "Bad Request URI").await;
            return;
        }
    };

    let is_typically_bodyless = matches!(
        method,
        http::Method::GET
            | http::Method::HEAD
            | http::Method::DELETE
            | http::Method::OPTIONS
            | http::Method::TRACE
    ) && parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
        == 0;

    let mut req_builder = http::Request::builder().method(method).uri(target_uri);

    let mut has_host = false;
    let mut existing_xff: Option<String> = None;

    for (name, val) in parts.headers.iter() {
        let n_str = name.as_str();
        if n_str.starts_with(':') {
            continue;
        }
        if n_str.eq_ignore_ascii_case("connection")
            || n_str.eq_ignore_ascii_case("keep-alive")
            || n_str.eq_ignore_ascii_case("transfer-encoding")
            || n_str.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        if n_str.eq_ignore_ascii_case("x-forwarded-for") {
            if let Ok(v_str) = val.to_str() {
                existing_xff = Some(v_str.to_string());
            }
            continue;
        }
        if n_str.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        req_builder = req_builder.header(name, val);
    }

    if !has_host {
        req_builder = req_builder.header("host", &authority);
    }

    let client_ip_str = client_addr.ip().to_string();
    let new_xff = match existing_xff {
        Some(xff) => format!("{}, {}", xff, client_ip_str),
        None => client_ip_str.clone(),
    };

    req_builder = req_builder
        .header("x-forwarded-for", new_xff)
        .header("x-real-ip", &client_ip_str)
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-port", h3_listen_port.to_string())
        .header("x-forwarded-host", &authority)
        .header("via", "HTTP/3 raddy");

    let h2_request = match req_builder.body(()) {
        Ok(r) => r,
        Err(e) => {
            send_h3_error(
                &mut h3_send,
                500,
                &format!("Failed to build proxy request: {e}"),
            )
            .await;
            return;
        }
    };

    // For GET/HEAD/DELETE without content-length, peek to see if stream is already finished.
    // For POST/PUT/streaming requests, open the H2 stream immediately without blocking on first body frame.
    let first_chunk = if is_typically_bodyless {
        match h3_recv.recv_data().await {
            Ok(Some(mut buf)) => {
                let len = buf.remaining();
                if len > 0 {
                    Some(buf.copy_to_bytes(len))
                } else {
                    None
                }
            }
            Ok(None) => None,
            Err(e) => {
                debug!("Error reading HTTP/3 request body from {}: {}", client_addr, e);
                return;
            }
        }
    } else {
        None
    };

    let sni_host = authority.split(':').next().unwrap_or("localhost");
    let mut sender = match h2_pool.get_sender(sni_host).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to local HTTP/2 listener: {}", e);
            send_h3_error(
                &mut h3_send,
                502,
                "Bad Gateway: unable to connect to local HTTP/2 listener",
            )
            .await;
            return;
        }
    };

    let is_body_empty = is_typically_bodyless && first_chunk.is_none();
    let (response_fut, mut h2_send_stream) = match sender.send_request(h2_request, is_body_empty) {
        Ok(res) => res,
        Err(e) => {
            error!("Failed to send request to local HTTP/2: {}", e);
            send_h3_error(
                &mut h3_send,
                502,
                "Bad Gateway: error sending request to local HTTP/2",
            )
            .await;
            return;
        }
    };

    if !is_body_empty {
        tokio::spawn(async move {
            if let Some(first_bytes) = first_chunk {
                if let Err(e) =
                    send_h2_data_with_flow_control(&mut h2_send_stream, first_bytes, false).await
                {
                    debug!("Error forwarding initial request body chunk to local H2: {}", e);
                    return;
                }
            }
            loop {
                match h3_recv.recv_data().await {
                    Ok(Some(mut buf)) => {
                        let len = buf.remaining();
                        if len > 0 {
                            let chunk = buf.copy_to_bytes(len);
                            if let Err(e) = send_h2_data_with_flow_control(
                                &mut h2_send_stream,
                                chunk,
                                false,
                            )
                            .await
                            {
                                debug!("Error forwarding request body chunk to local H2: {}", e);
                                return;
                            }
                        }
                    }
                    Ok(None) => {
                        if let Ok(Some(trailers)) = h3_recv.recv_trailers().await {
                            let _ = h2_send_stream.send_trailers(trailers);
                        } else {
                            let _ = h2_send_stream.send_data(Bytes::new(), true);
                        }
                        break;
                    }
                    Err(e) => {
                        debug!("Error streaming H3 request body: {}", e);
                        break;
                    }
                }
            }
        });
    }

    let (head, mut recv_body) = match response_fut.await {
        Ok(r) => r.into_parts(),
        Err(e) => {
            error!("Error receiving response from local HTTP/2: {}", e);
            send_h3_error(
                &mut h3_send,
                502,
                "Bad Gateway: error receiving response from local HTTP/2",
            )
            .await;
            return;
        }
    };

    let mut resp_builder = http::Response::builder().status(head.status);
    for (name, val) in head.headers.iter() {
        let n_str = name.as_str();
        if n_str.eq_ignore_ascii_case("connection")
            || n_str.eq_ignore_ascii_case("keep-alive")
            || n_str.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        resp_builder = resp_builder.header(name, val);
    }

    let h3_response = match resp_builder.body(()) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to build HTTP/3 response header: {}", e);
            return;
        }
    };

    if let Err(e) = h3_send.send_response(h3_response).await {
        debug!("Failed to send HTTP/3 response headers to {}: {}", client_addr, e);
        return;
    }

    while let Some(chunk_res) = recv_body.data().await {
        let chunk = match chunk_res {
            Ok(c) => c,
            Err(e) => {
                error!("Error reading response body chunk from HTTP/2: {}", e);
                break;
            }
        };

        let _ = recv_body.flow_control().release_capacity(chunk.len());
        if !chunk.is_empty() {
            if let Err(e) = h3_send.send_data(chunk).await {
                debug!("Failed to send HTTP/3 response body to {}: {}", client_addr, e);
                return;
            }
        }
    }

    if let Ok(Some(trailers)) = recv_body.trailers().await {
        if !trailers.is_empty() {
            let _ = h3_send.send_trailers(trailers).await;
        }
    }

    if let Err(e) = h3_send.finish().await {
        trace!("Failed to finish HTTP/3 stream for {}: {}", client_addr, e);
    }
}
