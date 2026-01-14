# Raddy

Raddy is a high-performance, lightweight reverse proxy built on [Cloudflare Pingora](https://github.com/cloudflare/pingora). It is designed to be safe, fast, and easy to configure, with built-in support for modern protocols and automatic SSL certificate management.

[中文文档](README_ZH.md)

## Features

- **Built on Pingora**: Leverages the high-performance, memory-safe architecture of Cloudflare's proxy framework.
- **Protocol Support**: Full support for HTTP/1.1, HTTP/2, gRPC (h2c/TLS), and WebSockets (WS/WSS).
- **Auto SSL (ACME)**: Built-in integration with Let's Encrypt for automatic certificate issuance and renewal.
- **TLS Hot-Reload**: Certificates are automatically reloaded after renewal without server restart.
- **Per-Domain TLS**: Flexible per-domain certificate configuration with SNI-based certificate selection.
- **Multi-Host Routing**: Route configuration supports matching multiple hosts for the same upstream.
- **Flexible Routing**: Route requests based on hostnames and path prefixes.
- **Custom Headers**: Easy configuration for adding or overriding request headers.
- **High Performance**: Uses MiMalloc allocator for optimal memory performance.

## Installation

### Download Pre-built Binaries

Download the latest release from the [Releases](https://github.com/rikaaa0928/raddy/releases) page.

### Build from Source

Ensure you have Rust installed (1.75+ recommended).

```bash
git clone https://github.com/rikaaa0928/raddy.git
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
  address: "0.0.0.0"
  http_port: 80
  https_port: 443
  
  # Per-domain TLS configuration
  tls:
    # ACME automatic certificate
    - domains:
        - "example.com"
        - "www.example.com"
      source:
        type: acme
        email: "admin@example.com"
        staging: false           # Set to true for testing
        cert_dir: "./certs"
        renew_before_days: 30
    
    # Static certificate from files
    - domains:
        - "api.example.com"
      source:
        type: file
        cert_path: "/path/to/cert.pem"
        key_path: "/path/to/key.pem"

routes:
  # Multi-host routing
  - host:
      - "example.com"
      - "www.example.com"
    path_prefix: "/"
    upstream:
      url: "127.0.0.1:3000"
      protocol: http
    force_https_redirect: true
    headers:
      X-Custom-Header: "Raddy-Proxy"

  # gRPC with TLS
  - host: "grpc.example.com"
    upstream:
      url: "127.0.0.1:50051"
      protocol: grpc_tls

  # WebSocket
  - host: "ws.example.com"
    upstream:
      url: "127.0.0.1:8080"
      protocol: ws
```

### Upstream Protocols

| Protocol   | Description                 |
|------------|-----------------------------|
| `http`     | Plain HTTP                  |
| `https`    | HTTPS with TLS              |
| `grpc`     | gRPC over HTTP/2 (h2c)      |
| `grpc_tls` | gRPC over HTTP/2 with TLS   |
| `ws`       | WebSocket                   |
| `wss`      | WebSocket Secure            |

## License

[MIT License](LICENSE)
