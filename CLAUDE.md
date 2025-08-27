# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- **Build:** `cargo build`
- **Run:** `cargo run -- --config raddy.toml`
- **Test:** `cargo test`
- **Lint:** `cargo clippy`
- **Format:** `cargo fmt`
- **Check:** `cargo check`

## Architecture

This is a reverse proxy server built with the Pingora framework. The server's behavior is configured via a TOML file (`raddy.toml`).

- **`src/main.rs`**: The main entry point of the application. It reads the configuration file, sets up the Pingora server, and defines the proxy logic.
- **`src/config.rs`**: Defines the data structures for parsing the TOML configuration file.
- **`raddy.toml`**: The configuration file for the server. It defines listeners, routes, and backends.

### Route Matching

The proxy implements a route matching system with two types of patterns:
1. **Exact matching**: Direct path matches take priority
2. **Wildcard matching**: Patterns ending with `/*` match path prefixes, with longest patterns taking priority

### Route Types

- **Echo routes**: Return static text responses directly
- **Proxy routes**: Forward requests to upstream servers with configurable TLS, headers, and host overrides

The proxy automatically adds `X-Forwarded-For` headers unless explicitly overridden in route configuration.