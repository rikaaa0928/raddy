# Raddy

Raddy is a high-performance, lightweight reverse proxy built on [Cloudflare Pingora](https://github.com/cloudflare/pingora). It is designed to be safe, fast, and easy to configure, with built-in support for modern protocols and automatic SSL certificate management.

## Features

- **Built on Pingora**: Leverages the high-performance, memory-safe architecture of Cloudflare's proxy framework.
- **Protocol Support**: Full support for HTTP/1.1, HTTP/2, gRPC, and WebSockets (WS/WSS).
- **Auto SSL (ACME)**: Built-in integration with Let's Encrypt for automatic certificate issuance and renewal.
- **Flexible Routing**: Route requests based on Hostnames and Path prefixes.
- **TLS Termination**: Support for both static certificates and automatic ACME certificates.
- **Custom Headers**: Easy configuration for adding or overriding request headers.

## Installation

### Build from Source

Ensure you have Rust installed (1.75+ recommended).

```bash
git clone https://github.com/your-username/raddy.git
cd raddy
cargo build --release
```

The binary will be available at `target/release/raddy`.

## Usage

Run the server with the default configuration:

```bash
./target/release/raddy
```

By default, it looks for `config.yaml` in the current directory. You can specify a custom configuration file using the `RADDY_CONFIG` environment variable:

```bash
RADDY_CONFIG=/path/to/my-config.yaml ./target/release/raddy
```

## Configuration

Raddy uses a YAML configuration file. Below is a comprehensive example:

```yaml
listen:
  # Bind address
  address: "0.0.0.0"
  
  # Port configurations
  http_port: 80
  https_port: 443
  
  # Global HTTPS redirect
  force_https_redirect: false
  
  # TLS Configuration (Choose either Static or ACME)
  tls:
    # Option 1: Automatic ACME (Let's Encrypt)
    acme:
      email: "user@example.com"
      domains: 
        - "example.com"
        - "www.example.com"
      cert_dir: "./certs"
      staging: false # Set to true for testing
      
    # Option 2: Static Certificates
    # cert_path: "/path/to/cert.pem"
    # key_path: "/path/to/key.pem"

routes:
  - host: "example.com"
    path_prefix: "/"
    upstream:
      url: "127.0.0.1:3000"
      protocol: "http" # Options: http, https, grpc, grpc_tls, ws, wss
    force_https_redirect: true
    headers:
      X-Custom-Header: "Raddy-Proxy"

  - host: "api.example.com"
    path_prefix: "/v1"
    upstream:
      url: "127.0.0.1:8080"
      protocol: "grpc"
```

### Upstream Protocols

- `http`: Plain HTTP
- `https`: HTTPS with TLS
- `grpc`: gRPC over HTTP/2
- `grpc_tls`: gRPC over HTTP/2 with TLS
- `ws`: WebSocket
- `wss`: WebSocket Secure

## License

[MIT License](LICENSE)
