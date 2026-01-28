# Raddy

Raddy 是一个基于 [Cloudflare Pingora](https://github.com/cloudflare/pingora) 构建的高性能轻量级反向代理。它旨在提供安全、快速且易于配置的代理服务，内置了对现代协议的支持以及自动 SSL 证书管理功能。

## 功能特性

- **基于 Pingora**: 利用 Cloudflare 代理框架的高性能和内存安全架构。
- **多协议支持**: 全面支持 HTTP/1.1、HTTP/2、gRPC (h2c/TLS) 以及 WebSocket (WS/WSS)。
- **自动 SSL (ACME)**: 内置集成 Let's Encrypt，支持自动申请和续期 SSL 证书。
- **TLS 热更新**: 证书续期后自动重新加载，无需重启服务器。
- **域名级 TLS 配置**: 灵活的按域名证书配置，支持基于 SNI 的证书选择。
- **多主机路由**: 路由配置支持为同一上游匹配多个主机。
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
