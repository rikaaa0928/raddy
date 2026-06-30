# Raddy

Raddy is a high-performance, lightweight reverse proxy built on [Cloudflare Pingora](https://github.com/cloudflare/pingora). It is designed to be safe, fast, and easy to configure, with built-in support for modern protocols and automatic SSL certificate management.

[中文文档](README_ZH.md)

## Features

- **Built on Pingora**: Leverages the high-performance, memory-safe architecture of Cloudflare's proxy framework.
- **Protocol Support**: Full support for HTTP/1.1, HTTP/2, HTTP/3, gRPC (h2c/TLS), and WebSockets (WS/WSS).
- **Auto SSL (ACME)**: Built-in integration with Let's Encrypt for automatic certificate issuance and renewal.
- **TLS Hot-Reload**: Certificates are automatically reloaded after renewal without server restart.
- **Per-Domain TLS**: Flexible per-domain certificate configuration with SNI-based certificate selection.
- **Multi-Host Routing**: Route configuration supports matching multiple hosts for the same upstream.
- **Multiple Paths per Host**: Group several path rules under the same host list to keep configuration compact.
- **Flexible Routing**: Route requests based on hostnames and path prefixes.
- **Custom Headers**: Easy configuration for adding or overriding request headers, including `$host` variable expansion.
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
  # HTTP/3 is enabled by default and listens on the HTTPS port over UDP.
  # Set this to false to avoid starting the UDP listener.
  http3: true
  
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
    # Route-level HTTP/3 is enabled by default. Set to false to reject H3 for this route.
    http3: true
    headers:
      Host: "$host"
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

### Multiple Paths per Host

When several routes share the same host or host list, you can group them with `paths`. Each item under `paths` is expanded into a normal route.

```yaml
routes:
  - hosts:
      - "example.com"
      - "www.example.com"
    paths:
      - path_prefix: "/api/"
        upstream:
          url: "127.0.0.1:3000"
          protocol: http

      - path_prefix: "/grpc.Service/"
        upstream:
          url: "127.0.0.1:50051"
          protocol: grpc

      # Default route for the same hosts
      - upstream:
          url: "127.0.0.1:8080"
          protocol: http
```

Only `host`/`hosts` and `http3` are inherited from the parent route group. Other route settings such as `headers`, `hide_headers`, `rewrite`, `rewrite_query`, and `force_https_redirect` must be configured on each `paths` item that needs them.

### HTTP/3

HTTP/3 is enabled by default when HTTPS and TLS are configured. Raddy listens on the same port as HTTPS, using TCP for HTTP/1.1 and HTTP/2 and UDP for HTTP/3. To disable the UDP listener globally:

```yaml
listen:
  address: "0.0.0.0"
  https_port: 443
  http3: false
```

You can disable HTTP/3 for a single route or a grouped set of paths:

```yaml
routes:
  - host: "example.com"
    http3: false
    upstream:
      url: "http://127.0.0.1:3000"
      protocol: http

  - hosts: ["api.example.com"]
    http3: false
    paths:
      - path_prefix: "/internal/"
        upstream:
          url: "http://127.0.0.1:3001"
          protocol: http
      - path_prefix: "/public/"
        http3: true
        upstream:
          url: "http://127.0.0.1:3002"
          protocol: http
```

### Path Rewriting Logic

When configuring routes with both `path_prefix` and an upstream `url` containing a path, Raddy concatenates the paths. It does **not** strip the matched `path_prefix`.

Examples of request handling for a request to `/a/c`:


1. **Prefix with Upstream Path**

   ```yaml
   path_prefix: "/a"
   upstream:
     url: "127.0.0.1:3000/b"
   ```

   Result: `127.0.0.1:3000/b/a/c` (Original path `/a/c` appended to upstream path `/b`)

2. **Root Prefix with Upstream Path**

   ```yaml
   path_prefix: "/"
   upstream:
     url: "127.0.0.1:3000/b"
   ```

   Result: `127.0.0.1:3000/b/a/c` (Original path `/a/c` appended to upstream path `/b`)

3. **Prefix with Root Upstream**

   ```yaml
   path_prefix: "/a"
   upstream:
     url: "127.0.0.1:3000"
   ```

   Result: `127.0.0.1:3000/a/c` (No upstream path to prepend, so original path `/a/c` is preserved)

### Regex Path Rewriting

Raddy supports rewriting request paths using regular expressions. This allows for complex path transformations before forwarding to the upstream.

```yaml
routes:
  - host: "api.example.com"
    rewrite:
      pattern: "^/api/v1/(.*)$"
      to: "/services/v1/$1"
    upstream:
      url: "http://backend-service"
      protocol: http
```

When `rewrite` is configured, the transformed path is used. The `pattern` is a standard Regex, and `to` is the replacement string which supports capture groups (e.g., `$1`).

### Header Variables

Header values support simple request-derived variables:

- `$host`: original request host, falling back to HTTP/2 `:authority`
- `$http_host`: alias of `$host`

To preserve the downstream `Host` header when proxying, set:

```yaml
headers:
  Host: "$host"
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
