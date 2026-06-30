# Raddy

Raddy 是一个基于 [Cloudflare Pingora](https://github.com/cloudflare/pingora) 构建的高性能轻量级反向代理。它旨在提供安全、快速且易于配置的代理服务，内置了对现代协议的支持以及自动 SSL 证书管理功能。

## 功能特性

- **基于 Pingora**: 利用 Cloudflare 代理框架的高性能和内存安全架构。
- **多协议支持**: 全面支持 HTTP/1.1、HTTP/2、HTTP/3、gRPC (h2c/TLS) 以及 WebSocket (WS/WSS)。
- **自动 SSL (ACME)**: 内置集成 Let's Encrypt，支持自动申请和续期 SSL 证书。
- **TLS 热更新**: 证书续期后自动重新加载，无需重启服务器。
- **域名级 TLS 配置**: 灵活的按域名证书配置，支持基于 SNI 的证书选择。
- **多主机路由**: 路由配置支持为同一上游匹配多个主机。
- **单主机多路径**: 可以把同一组 Host 下的多个路径规则合并到一个配置块中。
- **灵活路由**: 支持基于域名 (Host) 和路径前缀 (Path prefix) 的路由规则。
- **自定义 Header**: 轻松配置添加或覆盖请求头。
- **高性能**: 使用 MiMalloc 内存分配器获得最佳性能。

## 安装指南

### 下载预编译二进制文件

从 [Releases](https://github.com/rikaaa0928/raddy/releases) 页面下载最新版本。

### 源码编译

请确保已安装 Rust 环境 (建议 1.75+)。

```bash
git clone https://github.com/rikaaa0928/raddy.git
cd raddy
cargo build --release
```

编译完成后，二进制文件位于 `target/release/raddy`。

## 使用方法

使用默认配置运行服务器：

```bash
./target/release/raddy
```

默认情况下，程序会在当前目录查找 `config.yaml`。你可以通过 `RADDY_CONFIG` 环境变量指定配置文件路径：

```bash
RADDY_CONFIG=/path/to/my-config.yaml ./target/release/raddy
```

## 配置说明

Raddy 使用 YAML 格式的配置文件。以下是一个详细的配置示例：

```yaml
listen:
  address: "0.0.0.0"
  http_port: 80
  https_port: 443
  # HTTP/3 默认开启，通过 HTTPS 端口的 UDP 监听。
  # 设置为 false 后不会启动 UDP listener。
  http3: true
  
  # 按域名配置 TLS
  tls:
    # ACME 自动证书
    - domains:
        - "example.com"
        - "www.example.com"
      source:
        type: acme
        email: "admin@example.com"
        staging: false           # 设置为 true 用于测试
        cert_dir: "./certs"
        renew_before_days: 30
    
    # 静态证书文件
    - domains:
        - "api.example.com"
      source:
        type: file
        cert_path: "/path/to/cert.pem"
        key_path: "/path/to/key.pem"

routes:
  # 多主机路由
  - host:
      - "example.com"
      - "www.example.com"
    path_prefix: "/"
    upstream:
      url: "127.0.0.1:3000"
      protocol: http
    force_https_redirect: true
    # 路由级 HTTP/3 默认开启。设置为 false 后该路由拒绝 H3 请求。
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

### 单主机多路径配置

当多个路由共享同一个 `host` 或 `hosts` 列表时，可以使用 `paths` 把它们合并到同一个配置块里。`paths` 下的每一项都会展开成一条普通路由。

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

      # 同一组 hosts 的默认路由
      - upstream:
          url: "127.0.0.1:8080"
          protocol: http
```

父级配置只会向子项继承 `host`/`hosts` 和 `http3`。其他路由设置，例如 `headers`、`hide_headers`、`rewrite`、`rewrite_query` 和 `force_https_redirect`，需要写在对应的 `paths` 子项里。

### HTTP/3

当 HTTPS 和 TLS 配置完整时，HTTP/3 默认开启。Raddy 会复用 HTTPS 端口：TCP 处理 HTTP/1.1 和 HTTP/2，UDP 处理 HTTP/3。全局关闭 HTTP/3 后不会启动 UDP listener：

```yaml
listen:
  address: "0.0.0.0"
  https_port: 443
  http3: false
```

也可以针对单条路由或一组 `paths` 关闭 HTTP/3：

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

### 路径重写逻辑 (Path Rewriting Logic)

当配置了 `path_prefix` 且上游 `url` 包含路径时，Raddy 会将路径进行拼接。它**不会**去除匹配到的 `path_prefix`。

针对 `/a/c` 请求的处理示例：

1. **Prefix with Upstream Path**

   ```yaml
   path_prefix: "/a"
   upstream:
     url: "127.0.0.1:3000/b"
   ```

   结果: `127.0.0.1:3000/b/a/c` (原始路径 `/a/c` 追加到上游路径 `/b` 之后)

2. **Root Prefix with Upstream Path**

   ```yaml
   path_prefix: "/"
   upstream:
     url: "127.0.0.1:3000/b"
   ```

   结果: `127.0.0.1:3000/b/a/c` (原始路径 `/a/c` 追加到上游路径 `/b` 之后)

3. **Prefix with Root Upstream**

   ```yaml
   path_prefix: "/a"
   upstream:
     url: "127.0.0.1:3000"
   ```

   结果: `127.0.0.1:3000/a/c` (上游无路径，保留原始路径 `/a/c`)

### 正则路径重写 (Regex Path Rewriting)

Raddy 支持使用正则表达式重写请求路径。这允许在转发到上游之前进行复杂的路径转换。

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

当配置了 `rewrite` 时，使用转换后的路径。`pattern` 是标准的正则表达式，`to` 是替换字符串，支持捕获组（例如 `$1`）。

### Header 变量

`headers` 的值支持简单变量替换：

- `$host`: 原始请求的 host，如果没有则回退到 HTTP/2 的 `:authority`
- `$http_host`: `$host` 的别名

如果你希望转发时保留下游传入的 `Host`，可以这样写：

```yaml
headers:
  Host: "$host"
```

### 上游协议支持

| 协议       | 描述                        |
|------------|-----------------------------|
| `http`     | 纯 HTTP                     |
| `https`    | 带 TLS 的 HTTPS             |
| `grpc`     | 基于 HTTP/2 的 gRPC (h2c)   |
| `grpc_tls` | 带 TLS 的 HTTP/2 gRPC       |
| `ws`       | WebSocket                   |
| `wss`      | 安全 WebSocket              |

## 许可证

[MIT License](LICENSE)
