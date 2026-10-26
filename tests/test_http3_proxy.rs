use bytes::{Buf, Bytes};
use rcgen::{CertificateParams, KeyPair};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

fn create_quinn_client_endpoint(cert_pem: &str) -> quinn::Endpoint {
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).unwrap();
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let quic_client_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap();
    let client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

#[tokio::test]
async fn test_http3_reverse_proxy_to_h2() {
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Generate self-signed certificate for "test.example.com"
    let key_pair = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // 2. Setup mock HTTP/2 backend server
    let h2_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let h2_addr = h2_listener.local_addr().unwrap();

    let request_received = Arc::new(Notify::new());
    let req_received_clone = request_received.clone();

    let captured_headers = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let captured_body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let captured_headers_clone = captured_headers.clone();
    let captured_body_clone = captured_body.clone();

    tokio::spawn(async move {
        while let Ok((socket, _)) = h2_listener.accept().await {
            let captured_headers = captured_headers_clone.clone();
            let captured_body = captured_body_clone.clone();
            let req_received = req_received_clone.clone();

            tokio::spawn(async move {
                if let Ok(mut connection) = h2::server::handshake(socket).await {
                    while let Some(Ok((request, mut respond))) = connection.accept().await {
                        let mut hdrs = std::collections::HashMap::new();
                        for (k, v) in request.headers() {
                            hdrs.insert(k.as_str().to_string(), v.to_str().unwrap().to_string());
                        }
                        *captured_headers.lock().await = hdrs;

                        let mut body_bytes = Vec::new();
                        let mut body = request.into_body();
                        while let Some(chunk) = body.data().await {
                            if let Ok(data) = chunk {
                                let _ = body.flow_control().release_capacity(data.len());
                                body_bytes.extend_from_slice(&data);
                            }
                        }
                        *captured_body.lock().await = body_bytes;

                        let response = http::Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .header("x-backend-resp", "from-h2")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(response, false).unwrap();
                        send.send_data(Bytes::from("hello from backend h2"), true)
                            .unwrap();

                        req_received.notify_waiters();
                    }
                }
            });
        }
    });

    // 3. Setup CertStore and load certificate
    let cert_store = Arc::new(raddy::acme::CertStore::new());
    let cert_pair = raddy::acme::CertKeyPair {
        cert_pem: cert_pem.clone(),
        key_pem: key_pem.clone(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(1),
    };
    cert_store.store_for_domains(&["test.example.com".to_string()], cert_pair);

    // 4. Create YAML configuration with HTTP/3 enabled
    let yaml = format!(
        r#"
listen:
  address: "127.0.0.1"
  https_port: 8443
  http3_port: 0
  h2_target_addr: "http://{}"
  tls:
    - domains: ["test.example.com"]
      source:
        type: file
        cert_path: "none"
        key_path: "none"
routes:
  - host: "test.example.com"
    upstream:
      url: "http://{}"
      protocol: http
"#,
        h2_addr, h2_addr
    );

    let config: Arc<raddy::config::Config> = Arc::new(serde_yaml::from_str(&yaml).unwrap());
    let h2_target = config.h2_target().unwrap();

    // 5. Start Http3Service on an ephemeral UDP port
    let h3_udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let h3_addr = h3_udp_socket.local_addr().unwrap();
    drop(h3_udp_socket);

    let h3_service = raddy::http3::Http3Service::new(
        config.clone(),
        cert_store.clone(),
        h3_addr.to_string(),
        h2_target,
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let service_handle = tokio::spawn(async move {
        use pingora::services::background::BackgroundService;
        h3_service.start(shutdown_rx).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // 6. Connect HTTP/3 client using Quinn + h3
    let client_endpoint = create_quinn_client_endpoint(&cert_pem);
    let conn = client_endpoint
        .connect(h3_addr, "test.example.com")
        .unwrap()
        .await
        .unwrap();

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = http::Request::builder()
        .method("POST")
        .uri("https://test.example.com/api/test")
        .header("x-custom-req", "custom-val")
        .body(())
        .unwrap();

    let mut req_stream = send_request.send_request(req).await.unwrap();
    req_stream
        .send_data(Bytes::from("ping payload"))
        .await
        .unwrap();
    req_stream.finish().await.unwrap();

    let resp = req_stream.recv_response().await.unwrap();
    let got_resp_status = resp.status().as_u16();
    let got_resp_header_val = resp
        .headers()
        .get("x-backend-resp")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let mut got_resp_body = Vec::new();
    while let Some(mut chunk) = req_stream.recv_data().await.unwrap() {
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        got_resp_body.extend_from_slice(&bytes);
    }

    // 7. Verify response received by HTTP/3 client
    assert_eq!(got_resp_status, 200, "Expected 200 OK from HTTP/3 response");
    assert_eq!(
        got_resp_header_val.as_deref(),
        Some("from-h2"),
        "Expected x-backend-resp header from HTTP/2 response"
    );
    assert_eq!(
        std::str::from_utf8(&got_resp_body).unwrap(),
        "hello from backend h2",
        "Expected response body from backend"
    );

    // 8. Verify headers and body received by backend HTTP/2
    let backend_headers = captured_headers.lock().await;
    assert_eq!(
        backend_headers.get("x-custom-req").map(String::as_str),
        Some("custom-val")
    );
    assert_eq!(
        backend_headers.get("x-forwarded-proto").map(String::as_str),
        Some("https"),
        "Expected x-forwarded-proto: https"
    );
    assert_eq!(
        backend_headers.get("x-real-ip").map(String::as_str),
        Some("127.0.0.1"),
        "Expected x-real-ip: 127.0.0.1"
    );
    assert_eq!(
        backend_headers.get("x-forwarded-for").map(String::as_str),
        Some("127.0.0.1"),
        "Expected x-forwarded-for: 127.0.0.1"
    );
    assert!(
        backend_headers.get("x-forwarded-port").is_some(),
        "Expected x-forwarded-port header"
    );
    assert_eq!(
        backend_headers.get("x-forwarded-host").map(String::as_str),
        Some("test.example.com"),
        "Expected x-forwarded-host: test.example.com"
    );
    assert_eq!(
        backend_headers.get("via").map(String::as_str),
        Some("HTTP/3 raddy"),
        "Expected via header"
    );

    let backend_body = captured_body.lock().await;
    assert_eq!(
        std::str::from_utf8(&backend_body).unwrap(),
        "ping payload",
        "Expected request body forwarded to backend"
    );

    drop(shutdown_tx);
    let _ = service_handle.await;
}

#[tokio::test]
async fn test_http3_reverse_proxy_to_h2_tls() {
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Generate self-signed certificate for "test2.example.com"
    let key_pair = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec!["test2.example.com".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // 2. Setup mock HTTP/2 TLS backend server
    let certs = boring::x509::X509::stack_from_pem(cert_pem.as_bytes()).unwrap();
    let pkey = boring::pkey::PKey::private_key_from_pem(key_pem.as_bytes()).unwrap();
    let mut server_builder =
        boring::ssl::SslAcceptor::mozilla_intermediate(boring::ssl::SslMethod::tls()).unwrap();
    server_builder.set_certificate(&certs[0]).unwrap();
    server_builder.set_private_key(&pkey).unwrap();
    server_builder.set_alpn_select_callback(|_, client_alpn| {
        boring::ssl::select_next_proto(b"\x02h2", client_alpn).ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = server_builder.build();

    let h2_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let h2_addr = h2_listener.local_addr().unwrap();

    let captured_headers = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let captured_headers_clone = captured_headers.clone();

    tokio::spawn(async move {
        while let Ok((socket, _)) = h2_listener.accept().await {
            let captured_headers = captured_headers_clone.clone();
            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                if let Ok(tls_stream) = tokio_boring::accept(&acceptor, socket).await {
                    if let Ok(mut connection) = h2::server::handshake(tls_stream).await {
                        while let Some(Ok((request, mut respond))) = connection.accept().await {
                            let mut hdrs = std::collections::HashMap::new();
                            for (k, v) in request.headers() {
                                hdrs.insert(k.as_str().to_string(), v.to_str().unwrap().to_string());
                            }
                            *captured_headers.lock().await = hdrs;

                            let response = http::Response::builder().status(200).body(()).unwrap();
                            let mut send = respond.send_response(response, false).unwrap();
                            send.send_data(Bytes::from("hello tls h2 backend"), true)
                                .unwrap();
                        }
                    }
                }
            });
        }
    });

    // 3. Setup CertStore and load certificate
    let cert_store = Arc::new(raddy::acme::CertStore::new());
    let cert_pair = raddy::acme::CertKeyPair {
        cert_pem: cert_pem.clone(),
        key_pem: key_pem.clone(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(1),
    };
    cert_store.store_for_domains(&["test2.example.com".to_string()], cert_pair);

    // 4. Create YAML configuration pointing to TLS backend
    let yaml = format!(
        r#"
listen:
  address: "127.0.0.1"
  https_port: 8443
  http3_port: 0
  h2_target_addr: "https://{}"
  tls:
    - domains: ["test2.example.com"]
      source:
        type: file
        cert_path: "none"
        key_path: "none"
routes:
  - host: "test2.example.com"
    upstream:
      url: "https://{}"
      protocol: https
"#,
        h2_addr, h2_addr
    );

    let config: Arc<raddy::config::Config> = Arc::new(serde_yaml::from_str(&yaml).unwrap());
    let h2_target = config.h2_target().unwrap();
    assert!(h2_target.1, "Target should be TLS");

    // 5. Start Http3Service
    let h3_udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let h3_addr = h3_udp_socket.local_addr().unwrap();
    drop(h3_udp_socket);

    let h3_service = raddy::http3::Http3Service::new(
        config.clone(),
        cert_store.clone(),
        h3_addr.to_string(),
        h2_target,
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let service_handle = tokio::spawn(async move {
        use pingora::services::background::BackgroundService;
        h3_service.start(shutdown_rx).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // 6. Connect HTTP/3 client using Quinn + h3
    let client_endpoint = create_quinn_client_endpoint(&cert_pem);
    let conn = client_endpoint
        .connect(h3_addr, "test2.example.com")
        .unwrap()
        .await
        .unwrap();

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = http::Request::builder()
        .method("GET")
        .uri("https://test2.example.com/tls-test")
        .body(())
        .unwrap();

    let mut req_stream = send_request.send_request(req).await.unwrap();
    req_stream.finish().await.unwrap();

    let resp = req_stream.recv_response().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let mut got_resp_body = Vec::new();
    while let Some(mut chunk) = req_stream.recv_data().await.unwrap() {
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        got_resp_body.extend_from_slice(&bytes);
    }

    assert_eq!(
        std::str::from_utf8(&got_resp_body).unwrap(),
        "hello tls h2 backend"
    );

    let backend_headers = captured_headers.lock().await;
    assert_eq!(
        backend_headers.get("x-forwarded-proto").map(String::as_str),
        Some("https")
    );
    assert_eq!(
        backend_headers.get("x-forwarded-host").map(String::as_str),
        Some("test2.example.com")
    );

    drop(shutdown_tx);
    let _ = service_handle.await;
}

#[tokio::test]
async fn test_http3_dynamic_sni_cert_selection() {
    let _ = env_logger::builder().is_test(true).try_init();

    // Generate two distinct certificates for alpha.example.com and beta.example.com
    let key_a = KeyPair::generate().unwrap();
    let cert_a = CertificateParams::new(vec!["alpha.example.com".to_string()])
        .unwrap()
        .self_signed(&key_a)
        .unwrap();
    let cert_a_pem = cert_a.pem();
    let key_a_pem = key_a.serialize_pem();

    let key_b = KeyPair::generate().unwrap();
    let cert_b = CertificateParams::new(vec!["beta.example.com".to_string()])
        .unwrap()
        .self_signed(&key_b)
        .unwrap();
    let cert_b_pem = cert_b.pem();
    let key_b_pem = key_b.serialize_pem();

    let h2_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let h2_addr = h2_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((socket, _)) = h2_listener.accept().await {
            tokio::spawn(async move {
                if let Ok(mut connection) = h2::server::handshake(socket).await {
                    while let Some(Ok((request, mut respond))) = connection.accept().await {
                        let host = request
                            .headers()
                            .get("x-forwarded-host")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("unknown")
                            .to_string();
                        let response = http::Response::builder().status(200).body(()).unwrap();
                        let mut send = respond.send_response(response, false).unwrap();
                        send.send_data(Bytes::from(format!("served:{host}")), true)
                            .unwrap();
                    }
                }
            });
        }
    });

    let cert_store = Arc::new(raddy::acme::CertStore::new());
    cert_store.store_for_domains(
        &["alpha.example.com".to_string()],
        raddy::acme::CertKeyPair {
            cert_pem: cert_a_pem.clone(),
            key_pem: key_a_pem,
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        },
    );
    cert_store.store_for_domains(
        &["beta.example.com".to_string()],
        raddy::acme::CertKeyPair {
            cert_pem: cert_b_pem.clone(),
            key_pem: key_b_pem,
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
        },
    );

    let yaml = format!(
        r#"
listen:
  address: "127.0.0.1"
  https_port: 8443
  http3_port: 0
  h2_target_addr: "http://{}"
  tls:
    - domains: ["alpha.example.com", "beta.example.com"]
      source:
        type: file
        cert_path: "none"
        key_path: "none"
routes:
  - host: "alpha.example.com"
    upstream:
      url: "http://{}"
      protocol: http
"#,
        h2_addr, h2_addr
    );

    let config: Arc<raddy::config::Config> = Arc::new(serde_yaml::from_str(&yaml).unwrap());
    let h2_target = config.h2_target().unwrap();

    let h3_udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let h3_addr = h3_udp_socket.local_addr().unwrap();
    drop(h3_udp_socket);

    let h3_service = raddy::http3::Http3Service::new(
        config,
        cert_store,
        h3_addr.to_string(),
        h2_target,
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let service_handle = tokio::spawn(async move {
        use pingora::services::background::BackgroundService;
        h3_service.start(shutdown_rx).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    for (domain, cert_pem) in [
        ("alpha.example.com", &cert_a_pem),
        ("beta.example.com", &cert_b_pem),
    ] {
        // Each client only trusts its own domain's certificate
        let client_ep = create_quinn_client_endpoint(cert_pem);
        let conn = client_ep.connect(h3_addr, domain).unwrap().await.unwrap();
        let (mut driver, mut send_req) =
            h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = http::Request::builder()
            .method("GET")
            .uri(format!("https://{domain}/check"))
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        assert_eq!(std::str::from_utf8(&body).unwrap(), format!("served:{domain}"));
    }

    drop(shutdown_tx);
    let _ = service_handle.await;
}
