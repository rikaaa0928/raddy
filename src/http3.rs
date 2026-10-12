//! HTTP/3 Support via Cloudflare Quiche
//!
//! This module provides HTTP/3 (over QUIC/UDP) proxying.
//! It loads dynamic TLS certificates from `CertStore` with SNI support,
//! terminates HTTP/3 connections, and reverse-proxies requests to the local
//! HTTP/2 TCP listener with appropriate `X-Forwarded-*` headers.

use async_trait::async_trait;
use bytes::Bytes;
use log::{debug, error, info, trace, warn};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use quiche::h3::NameValue;
use ring::rand::SystemRandom;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::acme::CertStore;
use crate::config::Config;

const MAX_DATAGRAM_SIZE: usize = 1350;

/// Internal event sent from background HTTP/2 proxy tasks back to the HTTP/3 event loop
enum H3ResponseEvent {
    Headers {
        conn_id: Vec<u8>,
        stream_id: u64,
        status: u16,
        headers: Vec<(String, String)>,
        end_of_stream: bool,
    },
    BodyChunk {
        conn_id: Vec<u8>,
        stream_id: u64,
        chunk: Bytes,
        end_of_stream: bool,
    },
    Error {
        conn_id: Vec<u8>,
        stream_id: u64,
        status: u16,
        message: String,
    },
}

/// Request received on an HTTP/3 stream
#[derive(Default)]
struct IncomingRequest {
    headers: Vec<quiche::h3::Header>,
    body: Vec<u8>,
}

/// Response waiting to be sent on an HTTP/3 stream
#[derive(Default)]
struct PendingResponse {
    headers: Option<Vec<quiche::h3::Header>>,
    body_queue: VecDeque<Bytes>,
    finished: bool,
}

/// State of an active QUIC/HTTP/3 client connection
struct ClientState {
    conn: quiche::Connection,
    http3_conn: Option<quiche::h3::Connection>,
    peer_addr: SocketAddr,
    incoming_requests: HashMap<u64, IncomingRequest>,
    pending_responses: HashMap<u64, PendingResponse>,
}

impl ClientState {
    fn new(conn: quiche::Connection, peer_addr: SocketAddr) -> Self {
        Self {
            conn,
            http3_conn: None,
            peer_addr,
            incoming_requests: HashMap::new(),
            pending_responses: HashMap::new(),
        }
    }
}

/// Connection pool for local HTTP/2 requests
#[derive(Clone)]
struct H2ClientPool {
    target_addr: String,
    is_tls: bool,
    tls_connector: Option<boring::ssl::SslConnector>,
    current_sender: Arc<Mutex<Option<h2::client::SendRequest<Bytes>>>>,
}

impl H2ClientPool {
    fn new(target_addr: String, is_tls: bool) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
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
            tls_connector,
            current_sender: Arc::new(Mutex::new(None)),
        })
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

        // Establish new TCP connection
        let tcp = tokio::net::TcpStream::connect(&self.target_addr).await?;
        let sender = if self.is_tls {
            let connector = self.tls_connector.as_ref().expect("TLS connector present");
            let mut conf = connector.configure()?;
            conf.set_use_server_name_indication(true);
            let tls = tokio_boring::connect(conf, sni, tcp).await?;
            let (sender, conn) = h2::client::handshake(tls).await?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("Local H2 TLS connection closed: {}", e);
                }
            });
            sender
        } else {
            let (sender, conn) = h2::client::handshake(tcp).await?;
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

/// HTTP/3 Background Service for Pingora
pub struct Http3Service {
    _config: Arc<Config>,
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
            _config: config,
            cert_store,
            listen_addr,
            h2_target,
        }
    }

    /// Create quiche configuration with dynamic TLS certificate callback
    fn create_quiche_config(
        cert_store: Arc<CertStore>,
    ) -> Result<quiche::Config, Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls())?;

        let store = cert_store.clone();
        builder.set_select_certificate_callback(move |mut client_hello| {
            let sni = client_hello
                .servername(boring::ssl::NameType::HOST_NAME)
                .map(|s| s.trim_end_matches('.').to_ascii_lowercase());

            let cert_pair = if let Some(domain) = sni.as_deref() {
                store.get_for_domain(domain)
            } else {
                None
            }
            .or_else(|| store.get_any_cert());

            let Some(cert_pair) = cert_pair else {
                warn!("HTTP/3 TLS handshake rejected: no certificate for SNI {:?}", sni);
                return Err(boring::ssl::SelectCertError::ERROR);
            };

            let certs = boring::x509::X509::stack_from_pem(cert_pair.cert_pem.as_bytes())
                .map_err(|e| {
                    error!("HTTP/3 failed to parse cert PEM: {}", e);
                    boring::ssl::SelectCertError::ERROR
                })?;
            if certs.is_empty() {
                return Err(boring::ssl::SelectCertError::ERROR);
            }

            let pkey = boring::pkey::PKey::private_key_from_pem(cert_pair.key_pem.as_bytes())
                .map_err(|e| {
                    error!("HTTP/3 failed to parse key PEM: {}", e);
                    boring::ssl::SelectCertError::ERROR
                })?;

            let ssl = client_hello.ssl_mut();
            ssl.set_certificate(&certs[0])
                .map_err(|_| boring::ssl::SelectCertError::ERROR)?;
            for chain in certs.iter().skip(1) {
                ssl.add_chain_cert(chain)
                    .map_err(|_| boring::ssl::SelectCertError::ERROR)?;
            }
            ssl.set_private_key(&pkey)
                .map_err(|_| boring::ssl::SelectCertError::ERROR)?;

            debug!("HTTP/3 loaded certificate for SNI: {:?}", sni);
            Ok(())
        });

        let mut config = quiche::Config::with_boring_ssl_ctx_builder(
            quiche::PROTOCOL_VERSION,
            builder,
        )?;
        config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
        config.set_max_idle_timeout(30_000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(200);
        config.set_initial_max_streams_uni(200);
        config.set_disable_active_migration(true);
        config.enable_early_data();

        Ok(config)
    }
}

#[async_trait]
impl BackgroundService for Http3Service {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        info!("Starting HTTP/3 listener on UDP {}", self.listen_addr);
        info!(
            "HTTP/3 will reverse-proxy requests to HTTP/2 at {} (TLS: {})",
            self.h2_target.0, self.h2_target.1
        );

        let socket = match UdpSocket::bind(&self.listen_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!("Failed to bind HTTP/3 UDP socket on {}: {}", self.listen_addr, e);
                return;
            }
        };

        let mut quiche_config = match Self::create_quiche_config(self.cert_store.clone()) {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Failed to initialize quiche config: {}", e);
                return;
            }
        };

        let h3_config = match quiche::h3::Config::new() {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Failed to initialize HTTP/3 config: {}", e);
                return;
            }
        };

        let h2_pool = match H2ClientPool::new(self.h2_target.0.clone(), self.h2_target.1) {
            Ok(pool) => pool,
            Err(e) => {
                error!("Failed to initialize local H2 client pool: {}", e);
                return;
            }
        };

        let (resp_tx, mut resp_rx) = mpsc::channel::<H3ResponseEvent>(1024);

        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng)
            .expect("Failed to generate HMAC key for connection IDs");

        let mut clients: HashMap<Vec<u8>, ClientState> = HashMap::new();
        let mut dcid_map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

        let mut recv_buf = [0u8; 65535];
        let mut out_buf = [0u8; MAX_DATAGRAM_SIZE];

        let local_addr = socket.local_addr().expect("Socket local address");
        let h3_listen_port = local_addr.port();

        loop {
            // Determine shortest connection timeout
            let min_timeout = clients.values().filter_map(|c| c.conn.timeout()).min();
            let sleep_duration = min_timeout.unwrap_or(Duration::from_millis(50));

            tokio::select! {
                _ = shutdown.changed() => {
                    info!("HTTP/3 listener shutting down");
                    break;
                }

                // Incoming UDP packets
                recv_res = socket.recv_from(&mut recv_buf) => {
                    match recv_res {
                        Ok((len, peer_addr)) => {
                            let pkt = &mut recv_buf[..len];
                            let hdr = match quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN) {
                                Ok(h) => h,
                                Err(e) => {
                                    trace!("Failed to parse QUIC packet header: {:?}", e);
                                    continue;
                                }
                            };

                            // Lookup connection by DCID or mapped SCID
                            let scid_key = dcid_map.get(&hdr.dcid.to_vec())
                                .cloned()
                                .unwrap_or_else(|| hdr.dcid.to_vec());

                            let client = if !clients.contains_key(&scid_key) {
                                if hdr.ty != quiche::Type::Initial {
                                    trace!("Dropping non-initial packet for unknown connection");
                                    continue;
                                }

                                if !quiche::version_is_supported(hdr.version) {
                                    warn!("HTTP/3 client requested unsupported version, doing negotiation");
                                    if let Ok(len) = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out_buf) {
                                        let _ = socket.send_to(&out_buf[..len], peer_addr).await;
                                    }
                                    continue;
                                }

                                // Generate server connection ID
                                let signed = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                                let server_scid_bytes = &signed.as_ref()[..quiche::MAX_CONN_ID_LEN];
                                let server_scid = quiche::ConnectionId::from_ref(server_scid_bytes);

                                debug!(
                                    "New QUIC connection from {}: client dcid={:?}, server scid={:?}",
                                    peer_addr, hdr.dcid, server_scid
                                );

                                let conn = match quiche::accept(
                                    &server_scid,
                                    None,
                                    local_addr,
                                    peer_addr,
                                    &mut quiche_config,
                                ) {
                                    Ok(c) => c,
                                    Err(e) => {
                                        error!("quiche::accept failed: {:?}", e);
                                        continue;
                                    }
                                };

                                let server_key = server_scid_bytes.to_vec();
                                dcid_map.insert(hdr.dcid.to_vec(), server_key.clone());
                                dcid_map.insert(server_key.clone(), server_key.clone());

                                let client = ClientState::new(conn, peer_addr);
                                clients.insert(server_key.clone(), client);
                                clients.get_mut(&server_key).unwrap()
                            } else {
                                clients.get_mut(&scid_key).unwrap()
                            };

                            let recv_info = quiche::RecvInfo {
                                to: local_addr,
                                from: peer_addr,
                            };

                            if let Err(e) = client.conn.recv(pkt, recv_info) {
                                trace!("quiche::recv error: {:?}", e);
                            }

                            // Initialize HTTP/3 connection when QUIC handshake is ready
                            if (client.conn.is_in_early_data() || client.conn.is_established())
                                && client.http3_conn.is_none()
                            {
                                debug!("QUIC handshake established, initializing HTTP/3");
                                match quiche::h3::Connection::with_transport(&mut client.conn, &h3_config) {
                                    Ok(h3) => {
                                        client.http3_conn = Some(h3);
                                    }
                                    Err(e) => {
                                        error!("Failed to create HTTP/3 connection: {:?}", e);
                                    }
                                }
                            }

                            // Process HTTP/3 events
                            let scid_bytes = client.conn.source_id().as_ref().to_vec();
                            if let Some(http3) = client.http3_conn.as_mut() {
                                loop {
                                    match http3.poll(&mut client.conn) {
                                        Ok((stream_id, quiche::h3::Event::Headers { list, more_frames })) => {
                                            debug!("HTTP/3 request headers received on stream {}", stream_id);
                                            let req = client.incoming_requests.entry(stream_id).or_default();
                                            req.headers = list;

                                            if !more_frames {
                                                // No request body, trigger proxy immediately
                                                let completed_req = client.incoming_requests.remove(&stream_id).unwrap();
                                                spawn_proxy_task(
                                                    scid_bytes.clone(),
                                                    stream_id,
                                                    completed_req,
                                                    peer_addr,
                                                    h3_listen_port,
                                                    h2_pool.clone(),
                                                    resp_tx.clone(),
                                                );
                                            }
                                        }
                                        Ok((stream_id, quiche::h3::Event::Data)) => {
                                            let mut chunk = [0u8; 8192];
                                            if let Ok(read_len) = http3.recv_body(&mut client.conn, stream_id, &mut chunk) {
                                                let req = client.incoming_requests.entry(stream_id).or_default();
                                                req.body.extend_from_slice(&chunk[..read_len]);
                                            }
                                        }
                                        Ok((stream_id, quiche::h3::Event::Finished)) => {
                                            if let Some(completed_req) = client.incoming_requests.remove(&stream_id) {
                                                spawn_proxy_task(
                                                    scid_bytes.clone(),
                                                    stream_id,
                                                    completed_req,
                                                    peer_addr,
                                                    h3_listen_port,
                                                    h2_pool.clone(),
                                                    resp_tx.clone(),
                                                );
                                            }
                                        }
                                        Ok((_stream_id, quiche::h3::Event::Reset { .. })) => {
                                            client.incoming_requests.remove(&_stream_id);
                                            client.pending_responses.remove(&_stream_id);
                                        }
                                        Ok(_) => {}
                                        Err(quiche::h3::Error::Done) => break,
                                        Err(e) => {
                                            trace!("HTTP/3 poll error: {:?}", e);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("UDP recv error: {}", e);
                        }
                    }
                }

                // Response events from local HTTP/2 proxy tasks
                Some(event) = resp_rx.recv() => {
                    match event {
                        H3ResponseEvent::Headers { conn_id, stream_id, status, headers, end_of_stream } => {
                            if let Some(client) = clients.get_mut(&conn_id) {
                                let mut h3_headers = Vec::with_capacity(headers.len() + 1);
                                h3_headers.push(quiche::h3::Header::new(b":status", status.to_string().as_bytes()));
                                for (name, val) in headers {
                                    h3_headers.push(quiche::h3::Header::new(name.as_bytes(), val.as_bytes()));
                                }

                                let pending = client.pending_responses.entry(stream_id).or_default();
                                pending.headers = Some(h3_headers);
                                if end_of_stream {
                                    pending.finished = true;
                                }
                                flush_stream_response(client, stream_id);
                            }
                        }
                        H3ResponseEvent::BodyChunk { conn_id, stream_id, chunk, end_of_stream } => {
                            if let Some(client) = clients.get_mut(&conn_id) {
                                let pending = client.pending_responses.entry(stream_id).or_default();
                                if !chunk.is_empty() {
                                    pending.body_queue.push_back(chunk);
                                }
                                if end_of_stream {
                                    pending.finished = true;
                                }
                                flush_stream_response(client, stream_id);
                            }
                        }
                        H3ResponseEvent::Error { conn_id, stream_id, status, message } => {
                            if let Some(client) = clients.get_mut(&conn_id) {
                                let h3_headers = vec![
                                    quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
                                    quiche::h3::Header::new(b"content-type", b"text/plain; charset=utf-8"),
                                ];
                                let pending = client.pending_responses.entry(stream_id).or_default();
                                pending.headers = Some(h3_headers);
                                pending.body_queue.push_back(Bytes::from(message));
                                pending.finished = true;
                                flush_stream_response(client, stream_id);
                            }
                        }
                    }
                }

                // Timeout ticker
                _ = tokio::time::sleep(sleep_duration) => {
                    for client in clients.values_mut() {
                        client.conn.on_timeout();
                    }
                }
            }

            // Flush pending responses on writable streams
            for client in clients.values_mut() {
                if client.http3_conn.is_some() {
                    let writable_streams: Vec<u64> = client.conn.writable().collect();
                    for stream_id in writable_streams {
                        flush_stream_response(client, stream_id);
                    }
                }
            }

            // Send pending QUIC packets on UDP socket
            for client in clients.values_mut() {
                loop {
                    match client.conn.send(&mut out_buf) {
                        Ok((write_len, send_info)) => {
                            let _ = socket.send_to(&out_buf[..write_len], send_info.to).await;
                        }
                        Err(quiche::Error::Done) => break,
                        Err(e) => {
                            trace!("quiche::send error: {:?}", e);
                            break;
                        }
                    }
                }
            }

            // Clean up closed connections
            clients.retain(|_, client| {
                if client.conn.is_closed() {
                    debug!("HTTP/3 connection with {} collected", client.peer_addr);
                    false
                } else {
                    true
                }
            });
            dcid_map.retain(|_, scid| clients.contains_key(scid));
        }
    }
}

/// Flush pending response headers and body chunks to the HTTP/3 stream
fn flush_stream_response(client: &mut ClientState, stream_id: u64) {
    let Some(http3) = client.http3_conn.as_mut() else {
        return;
    };
    let Some(pending) = client.pending_responses.get_mut(&stream_id) else {
        return;
    };

    // 1. Send headers if still pending
    if let Some(headers) = pending.headers.take() {
        let is_empty_end = pending.finished && pending.body_queue.is_empty();
        match http3.send_response(&mut client.conn, stream_id, &headers, is_empty_end) {
            Ok(()) => {
                if is_empty_end {
                    client.pending_responses.remove(&stream_id);
                    return;
                }
            }
            Err(quiche::h3::Error::StreamBlocked) => {
                pending.headers = Some(headers);
                return;
            }
            Err(e) => {
                debug!("Failed to send HTTP/3 headers on stream {}: {:?}", stream_id, e);
                client.pending_responses.remove(&stream_id);
                return;
            }
        }
    }

    // 2. Send body chunks from the queue
    while let Some(front) = pending.body_queue.front() {
        let is_last = pending.finished && pending.body_queue.len() == 1;
        match http3.send_body(&mut client.conn, stream_id, front, is_last) {
            Ok(written) => {
                if written == front.len() {
                    pending.body_queue.pop_front();
                } else {
                    let rem = front.slice(written..);
                    *pending.body_queue.front_mut().unwrap() = rem;
                    return;
                }
            }
            Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {
                return;
            }
            Err(e) => {
                debug!("Failed to send HTTP/3 body on stream {}: {:?}", stream_id, e);
                client.pending_responses.remove(&stream_id);
                return;
            }
        }
    }

    if pending.finished && pending.body_queue.is_empty() {
        // Send empty fin body to close the stream if needed
        let _ = http3.send_body(&mut client.conn, stream_id, b"", true);
        client.pending_responses.remove(&stream_id);
    }
}

/// Spawn an asynchronous task to forward the HTTP/3 request to the local HTTP/2 listener
fn spawn_proxy_task(
    conn_id: Vec<u8>,
    stream_id: u64,
    req: IncomingRequest,
    client_addr: SocketAddr,
    h3_listen_port: u16,
    h2_pool: H2ClientPool,
    resp_tx: mpsc::Sender<H3ResponseEvent>,
) {
    tokio::spawn(async move {
        let mut method = "GET".to_string();
        let mut scheme = "https".to_string();
        let mut authority = "localhost".to_string();
        let mut path = "/".to_string();
        let mut headers = Vec::new();
        let mut existing_xff: Option<String> = None;

        for h in req.headers {
            let name = match std::str::from_utf8(h.name()) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let val = match std::str::from_utf8(h.value()) {
                Ok(v) => v,
                Err(_) => continue,
            };

            match name {
                ":method" => method = val.to_string(),
                ":scheme" => scheme = val.to_string(),
                ":authority" => authority = val.to_string(),
                ":path" => path = val.to_string(),
                _ => {
                    if name.starts_with(':') {
                        continue;
                    }
                    if name.eq_ignore_ascii_case("connection")
                        || name.eq_ignore_ascii_case("keep-alive")
                        || name.eq_ignore_ascii_case("transfer-encoding")
                        || name.eq_ignore_ascii_case("upgrade")
                    {
                        continue;
                    }
                    if name.eq_ignore_ascii_case("x-forwarded-for") {
                        existing_xff = Some(val.to_string());
                        continue;
                    }
                    headers.push((name.to_string(), val.to_string()));
                }
            }
        }

        // Build target URI
        let uri_str = if path.starts_with('/') {
            format!("{}://{}{}", scheme, authority, path)
        } else {
            format!("{}://{}/{}", scheme, authority, path)
        };
        let uri: http::Uri = match uri_str.parse() {
            Ok(u) => u,
            Err(_) => {
                resp_tx
                    .send(H3ResponseEvent::Error {
                        conn_id,
                        stream_id,
                        status: 400,
                        message: "Bad Request URI".to_string(),
                    })
                    .await
                    .ok();
                return;
            }
        };

        let mut req_builder = http::Request::builder()
            .method(method.as_str())
            .uri(uri);

        // Copy regular headers
        let mut has_host = false;
        for (name, val) in &headers {
            if name.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            req_builder = req_builder.header(name, val);
        }
        if !has_host {
            req_builder = req_builder.header("host", &authority);
        }

        // Process X-Forwarded-* and X-Real-IP headers
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
                resp_tx
                    .send(H3ResponseEvent::Error {
                        conn_id,
                        stream_id,
                        status: 500,
                        message: format!("Failed to build proxy request: {}", e),
                    })
                    .await
                    .ok();
                return;
            }
        };

        // Extract SNI for TLS connection
        let sni_host = authority.split(':').next().unwrap_or("localhost");

        let mut sender = match h2_pool.get_sender(sni_host).await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to connect to local HTTP/2 listener: {}", e);
                resp_tx
                    .send(H3ResponseEvent::Error {
                        conn_id,
                        stream_id,
                        status: 502,
                        message: "Bad Gateway: unable to connect to local HTTP/2 listener".to_string(),
                    })
                    .await
                    .ok();
                return;
            }
        };

        let is_body_empty = req.body.is_empty();
        let (response_fut, mut send_stream) = match sender.send_request(h2_request, is_body_empty) {
            Ok(res) => res,
            Err(e) => {
                error!("Failed to send request to local HTTP/2: {}", e);
                resp_tx
                    .send(H3ResponseEvent::Error {
                        conn_id,
                        stream_id,
                        status: 502,
                        message: "Bad Gateway: error sending request to local HTTP/2".to_string(),
                    })
                    .await
                    .ok();
                return;
            }
        };

        // Send request body if present
        if !is_body_empty {
            if let Err(e) = send_stream.send_data(Bytes::from(req.body), true) {
                error!("Failed to send request body to local HTTP/2: {}", e);
                resp_tx
                    .send(H3ResponseEvent::Error {
                        conn_id,
                        stream_id,
                        status: 502,
                        message: "Bad Gateway: error sending request body to local HTTP/2".to_string(),
                    })
                    .await
                    .ok();
                return;
            }
        }

        // Wait for response
        let (head, mut recv_body) = match response_fut.await {
            Ok(r) => r.into_parts(),
            Err(e) => {
                error!("Error receiving response from local HTTP/2: {}", e);
                resp_tx
                    .send(H3ResponseEvent::Error {
                        conn_id,
                        stream_id,
                        status: 502,
                        message: "Bad Gateway: error receiving response from local HTTP/2".to_string(),
                    })
                    .await
                    .ok();
                return;
            }
        };

        let status = head.status.as_u16();
        let mut resp_headers = Vec::new();
        for (name, val) in head.headers.iter() {
            if let Ok(v_str) = val.to_str() {
                let n_str = name.as_str().to_ascii_lowercase();
                if n_str == "connection" || n_str == "keep-alive" || n_str == "transfer-encoding" {
                    continue;
                }
                resp_headers.push((n_str, v_str.to_string()));
            }
        }

        let is_end_stream = recv_body.is_end_stream();
        if resp_tx
            .send(H3ResponseEvent::Headers {
                conn_id: conn_id.clone(),
                stream_id,
                status,
                headers: resp_headers,
                end_of_stream: is_end_stream,
            })
            .await
            .is_err()
        {
            return;
        }

        if is_end_stream {
            return;
        }

        // Stream response body chunks back
        let mut finished = false;
        while let Some(chunk_res) = recv_body.data().await {
            let chunk = match chunk_res {
                Ok(c) => c,
                Err(e) => {
                    error!("Error reading response body chunk from HTTP/2: {}", e);
                    break;
                }
            };

            let _ = recv_body.flow_control().release_capacity(chunk.len());
            let is_end = recv_body.is_end_stream();
            if resp_tx
                .send(H3ResponseEvent::BodyChunk {
                    conn_id: conn_id.clone(),
                    stream_id,
                    chunk,
                    end_of_stream: is_end,
                })
                .await
                .is_err()
            {
                return;
            }

            if is_end {
                finished = true;
                break;
            }
        }

        if !finished {
            let _ = resp_tx
                .send(H3ResponseEvent::BodyChunk {
                    conn_id,
                    stream_id,
                    chunk: Bytes::new(),
                    end_of_stream: true,
                })
                .await;
        }
    });
}
