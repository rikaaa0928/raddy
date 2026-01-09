# Raddy

Raddy 是一个基于 [Cloudflare Pingora](https://github.com/cloudflare/pingora) 构建的高性能轻量级反向代理。它旨在提供安全、快速且易于配置的代理服务，内置了对现代协议的支持以及自动 SSL 证书管理功能。

## 功能特性

- **基于 Pingora**: 利用 Cloudflare 代理框架的高性能和内存安全架构。
- **多协议支持**: 全面支持 HTTP/1.1, HTTP/2, gRPC 以及 WebSocket (WS/WSS)。
- **自动 SSL (ACME)**: 内置集成 Let's Encrypt，支持自动申请和续期 SSL 证书。
- **灵活路由**: 支持基于域名 (Host) 和路径前缀 (Path prefix) 的路由规则。
- **TLS 终止**: 支持静态证书文件和 ACME 自动证书模式。
- **自定义 Header**: 轻松配置添加或覆盖请求头。

## 安装指南

### 源码编译

请确保已安装 Rust 环境 (建议 1.75+)。

```bash
git clone https://github.com/your-username/raddy.git
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
  # 监听地址
  address: "0.0.0.0"
  
  # 端口配置
  http_port: 80
  https_port: 443
  
  # 全局强制 HTTPS 跳转
  force_https_redirect: false
  
  # TLS 配置 (二选一：自动 ACME 或 静态证书)
  tls:
    # 选项 1: 自动 ACME (Let's Encrypt)
    acme:
      email: "user@example.com"
      domains: 
        - "example.com"
        - "www.example.com"
      cert_dir: "./certs" # 证书存储目录
      staging: false # 测试时设为 true
      
    # 选项 2: 静态证书
    # cert_path: "/path/to/cert.pem"
    # key_path: "/path/to/key.pem"

routes:
  - host: "example.com"
    path_prefix: "/"
    upstream:
      url: "127.0.0.1:3000"
      protocol: "http" # 可选协议: http, https, grpc, grpc_tls, ws, wss
    force_https_redirect: true
    headers:
      X-Custom-Header: "Raddy-Proxy"

  - host: "api.example.com"
    path_prefix: "/v1"
    upstream:
      url: "127.0.0.1:8080"
      protocol: "grpc"
```

### 上游协议支持 (Upstream Protocols)

- `http`: 普通 HTTP
- `https`: 带 TLS 的 HTTPS
- `grpc`: 基于 HTTP/2 的 gRPC
- `grpc_tls`: 基于 HTTP/2 且带 TLS 的 gRPC
- `ws`: WebSocket
- `wss`: WebSocket Secure

## 许可证

[MIT License](LICENSE)
