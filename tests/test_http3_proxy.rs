use quiche::h3::NameValue;
use rcgen::{CertificateParams, KeyPair};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

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
                        send.send_data(bytes::Bytes::from("hello from backend h2"), true).unwrap();

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
    drop(h3_udp_socket); // release port for Http3Service to bind

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

    // Wait a brief moment for UDP socket to be bound
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 6. Setup client using quiche
    let mut client_builder = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
    client_builder.set_verify(boring::ssl::SslVerifyMode::NONE);
    let mut client_config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, client_builder).unwrap();
    client_config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();
    client_config.set_max_idle_timeout(5000);
    client_config.set_initial_max_data(10_000_000);
    client_config.set_initial_max_stream_data_bidi_local(1_000_000);
    client_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    client_config.set_initial_max_stream_data_uni(1_000_000);
    client_config.set_initial_max_streams_bidi(100);
    client_config.set_initial_max_streams_uni(100);

    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_udp.local_addr().unwrap();

    let scid = [7u8; quiche::MAX_CONN_ID_LEN];
    let mut client_conn = quiche::connect(
        Some("test.example.com"),
        &quiche::ConnectionId::from_ref(&scid),
        client_addr,
        h3_addr,
        &mut client_config,
    ).unwrap();

    let mut out = [0u8; 1350];
    let mut in_buf = [0u8; 65535];

    // Drive initial packet
    let (write_len, send_info) = client_conn.send(&mut out).unwrap();
    client_udp.send_to(&out[..write_len], send_info.to).await.unwrap();

    let mut client_h3 = None;
    let mut request_sent = false;
    let mut stream_id = 0;

    let mut got_resp_status = None;
    let mut got_resp_body = Vec::new();
    let mut got_resp_header_val = None;

    // Loop until response received or timeout
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        // Check for incoming packets
        tokio::select! {
            recv_res = client_udp.recv_from(&mut in_buf) => {
                if let Ok((len, from)) = recv_res {
                    let recv_info = quiche::RecvInfo {
                        to: client_addr,
                        from,
                    };
                    let _ = client_conn.recv(&mut in_buf[..len], recv_info);
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                client_conn.on_timeout();
            }
        }

        // Check if connection established
        if (client_conn.is_in_early_data() || client_conn.is_established()) && client_h3.is_none() {
            let h3_config = quiche::h3::Config::new().unwrap();
            let h3 = quiche::h3::Connection::with_transport(&mut client_conn, &h3_config).unwrap();
            client_h3 = Some(h3);
        }

        // Send request if not yet sent
        if let Some(h3) = client_h3.as_mut() {
            if !request_sent && client_conn.is_established() {
                let req_headers = vec![
                    quiche::h3::Header::new(b":method", b"POST"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"test.example.com"),
                    quiche::h3::Header::new(b":path", b"/api/test"),
                    quiche::h3::Header::new(b"x-custom-req", b"custom-val"),
                ];

                let sid = h3.send_request(&mut client_conn, &req_headers, false).unwrap();
                let _ = h3.send_body(&mut client_conn, sid, b"ping payload", true);
                stream_id = sid;
                request_sent = true;
            }

            // Poll H3 events on client
            loop {
                match h3.poll(&mut client_conn) {
                    Ok((sid, quiche::h3::Event::Headers { list, .. })) if sid == stream_id => {
                        for h in list {
                            if h.name() == b":status" {
                                got_resp_status = Some(std::str::from_utf8(h.value()).unwrap().to_string());
                            }
                            if h.name() == b"x-backend-resp" {
                                got_resp_header_val = Some(std::str::from_utf8(h.value()).unwrap().to_string());
                            }
                        }
                    }
                    Ok((sid, quiche::h3::Event::Data)) if sid == stream_id => {
                        let mut body_buf = [0u8; 1024];
                        if let Ok(len) = h3.recv_body(&mut client_conn, sid, &mut body_buf) {
                            got_resp_body.extend_from_slice(&body_buf[..len]);
                        }
                    }
                    Ok((sid, quiche::h3::Event::Finished)) if sid == stream_id => {
                        break;
                    }
                    Err(quiche::h3::Error::Done) => break,
                    _ => break,
                }
            }
        }

        // Send any outgoing QUIC packets from client
        loop {
            match client_conn.send(&mut out) {
                Ok((len, send_info)) => {
                    let _ = client_udp.send_to(&out[..len], send_info.to).await;
                }
                Err(quiche::Error::Done) => break,
                Err(_) => break,
            }
        }

        if got_resp_status.is_some() && !got_resp_body.is_empty() {
            break;
        }
    }

    // 7. Verify response received by HTTP/3 client
    assert_eq!(got_resp_status.as_deref(), Some("200"), "Expected 200 OK from HTTP/3 response");
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

    println!("HTTP/3 reverse proxy end-to-end integration test passed successfully!");

    // Clean shutdown
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
    let mut server_builder = boring::ssl::SslAcceptor::mozilla_intermediate(boring::ssl::SslMethod::tls()).unwrap();
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

                            let response = http::Response::builder()
                                .status(200)
                                .body(())
                                .unwrap();
                            let mut send = respond.send_response(response, false).unwrap();
                            send.send_data(bytes::Bytes::from("hello tls h2 backend"), true).unwrap();
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

    // 6. Connect HTTP/3 client
    let mut client_builder = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
    client_builder.set_verify(boring::ssl::SslVerifyMode::NONE);
    let mut client_config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, client_builder).unwrap();
    client_config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();
    client_config.set_max_idle_timeout(5000);
    client_config.set_initial_max_data(10_000_000);
    client_config.set_initial_max_stream_data_bidi_local(1_000_000);
    client_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    client_config.set_initial_max_stream_data_uni(1_000_000);
    client_config.set_initial_max_streams_bidi(100);
    client_config.set_initial_max_streams_uni(100);

    let client_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_udp.local_addr().unwrap();

    let scid = [8u8; quiche::MAX_CONN_ID_LEN];
    let mut client_conn = quiche::connect(
        Some("test2.example.com"),
        &quiche::ConnectionId::from_ref(&scid),
        client_addr,
        h3_addr,
        &mut client_config,
    ).unwrap();

    let mut out = [0u8; 1350];
    let mut in_buf = [0u8; 65535];

    let (write_len, send_info) = client_conn.send(&mut out).unwrap();
    client_udp.send_to(&out[..write_len], send_info.to).await.unwrap();

    let mut client_h3 = None;
    let mut request_sent = false;
    let mut stream_id = 0;
    let mut got_resp_body = Vec::new();

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        tokio::select! {
            recv_res = client_udp.recv_from(&mut in_buf) => {
                if let Ok((len, from)) = recv_res {
                    let _ = client_conn.recv(&mut in_buf[..len], quiche::RecvInfo { to: client_addr, from });
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                client_conn.on_timeout();
            }
        }

        if (client_conn.is_in_early_data() || client_conn.is_established()) && client_h3.is_none() {
            let h3_config = quiche::h3::Config::new().unwrap();
            let h3 = quiche::h3::Connection::with_transport(&mut client_conn, &h3_config).unwrap();
            client_h3 = Some(h3);
        }

        if let Some(h3) = client_h3.as_mut() {
            if !request_sent && client_conn.is_established() {
                let req_headers = vec![
                    quiche::h3::Header::new(b":method", b"GET"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"test2.example.com"),
                    quiche::h3::Header::new(b":path", b"/tls-test"),
                ];

                let sid = h3.send_request(&mut client_conn, &req_headers, true).unwrap();
                stream_id = sid;
                request_sent = true;
            }

            loop {
                match h3.poll(&mut client_conn) {
                    Ok((sid, quiche::h3::Event::Data)) if sid == stream_id => {
                        let mut body_buf = [0u8; 1024];
                        if let Ok(len) = h3.recv_body(&mut client_conn, sid, &mut body_buf) {
                            got_resp_body.extend_from_slice(&body_buf[..len]);
                        }
                    }
                    Ok((sid, quiche::h3::Event::Finished)) if sid == stream_id => break,
                    Err(quiche::h3::Error::Done) => break,
                    _ => break,
                }
            }
        }

        loop {
            match client_conn.send(&mut out) {
                Ok((len, send_info)) => {
                    let _ = client_udp.send_to(&out[..len], send_info.to).await;
                }
                Err(quiche::Error::Done) => break,
                Err(_) => break,
            }
        }

        if !got_resp_body.is_empty() {
            break;
        }
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

    println!("HTTP/3 to TLS HTTP/2 backend test passed successfully!");

    drop(shutdown_tx);
    let _ = service_handle.await;
}
