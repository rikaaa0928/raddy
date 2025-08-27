mod config;

use crate::config::Config;
use async_trait::async_trait;
use clap::Parser;
use log::{info, warn, error};
use pingora::proxy::{http_proxy_service, ProxyHttp, Session};
use pingora::server::Server;
use pingora::prelude::*;
use pingora::http::ResponseHeader;
use std::collections::HashMap;
use std::sync::Arc;
use std::fs;

#[derive(Parser)]
struct Opts {
    #[clap(short, long)]
    config: String,
}

pub struct RaddyApp {
    routes: Arc<HashMap<String, config::Route>>,
}

impl RaddyApp {
    fn find_matching_route(&self, path: &str) -> Option<(&String, &config::Route)> {
        // 1. 首先尝试精确匹配
        if let Some(_route) = self.routes.get(path) {
            return Some(self.routes.iter().find(|(k, _)| *k == path).unwrap());
        }

        // 2. 寻找 wildcard 匹配，按路径长度降序排列（最长匹配优先）
        let mut wildcard_matches: Vec<_> = self.routes.iter()
            .filter(|(pattern, _)| {
                pattern.ends_with("/*") && {
                    let prefix = &pattern[..pattern.len() - 2]; // 去掉 "/*"
                    path.starts_with(prefix) && (
                        path.len() == prefix.len() || 
                        path.chars().nth(prefix.len()) == Some('/')
                    )
                }
            })
            .collect();

        // 按模式长度降序排序（最长的模式优先）
        wildcard_matches.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        wildcard_matches.into_iter().next()
    }
}

#[async_trait]
impl ProxyHttp for RaddyApp {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<Box<HttpPeer>, Box<pingora::Error>> {
        let path = session.req_header().uri.path();
        
        if let Some((pattern, route)) = self.find_matching_route(path) {
            if let config::Route::Proxy(proxy_config) = route {
                match proxy_config.parse_upstream() {
                    Ok(parsed) => {
                        let upstream_addr = format!("{}:{}", parsed.host, parsed.port);
                        let sni = if parsed.use_tls { parsed.host.clone() } else { "".to_string() };
                        info!("Path '{}' matched pattern '{}', proxying to: {} (TLS: {}, SNI: {})", 
                              path, pattern, upstream_addr, parsed.use_tls, sni);
                        let upstream = HttpPeer::new(&upstream_addr, parsed.use_tls, sni);
                        return Ok(Box::new(upstream));
                    }
                    Err(e) => {
                        error!("Failed to parse upstream '{}': {}", proxy_config.upstream, e);
                        return Err(pingora::Error::new(pingora::ErrorType::InternalError));
                    }
                }
            }
        }
        
        warn!("No route found for path: {}", path);
        Err(pingora::Error::new(pingora::ErrorType::InternalError))
    }

    async fn upstream_request_filter(&self, session: &mut Session, upstream_request: &mut pingora::http::RequestHeader, _ctx: &mut Self::CTX) -> Result<(), Box<pingora::Error>> {
        // 获取当前路径对应的路由配置
        let path = session.req_header().uri.path();
        if let Some((_, route)) = self.find_matching_route(path) {
            if let config::Route::Proxy(proxy_config) = route {
                // 应用用户配置的 header 覆盖
                if let Some(ref headers) = proxy_config.headers {
                    for (key, value) in headers {
                        info!("Setting header: {} = {}", key, value);
                        upstream_request.insert_header(key.clone(), value.clone()).unwrap();
                    }
                }
            }
        }

        // 默认添加 X-Forwarded-For 头部（如果用户没有显式配置的话）
        let path = session.req_header().uri.path();
        let has_custom_xff = self.find_matching_route(path)
            .and_then(|(_, route)| match route {
                config::Route::Proxy(proxy_config) => proxy_config.headers.as_ref(),
                _ => None,
            })
            .map(|headers| headers.contains_key("X-Forwarded-For") || headers.contains_key("x-forwarded-for"))
            .unwrap_or(false);

        if !has_custom_xff {
            let client_ip = session.client_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            
            let client_ip = if let Some(colon_pos) = client_ip.rfind(':') {
                client_ip[..colon_pos].to_string()
            } else {
                client_ip
            };

            if let Some(existing_xff) = upstream_request.headers.get("x-forwarded-for") {
                if let Ok(existing_xff_str) = existing_xff.to_str() {
                    let new_xff = format!("{}, {}", existing_xff_str, client_ip);
                    upstream_request.insert_header("X-Forwarded-For", &new_xff).unwrap();
                }
            } else {
                upstream_request.insert_header("X-Forwarded-For", &client_ip).unwrap();
            }
        }

        Ok(())
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool, Box<pingora::Error>> {
        let path = session.req_header().uri.path();
        if let Some((_, route)) = self.find_matching_route(path) {
            match route {
                config::Route::Echo(body) => {
                    let mut headers = ResponseHeader::build(200, None).unwrap();
                    headers.insert_header("Content-Length", body.len().to_string().as_str()).unwrap();
                    headers.insert_header("Content-Type", "text/plain").unwrap();
                    session.write_response_header(Box::new(headers), false).await.unwrap();
                    session.write_response_body(Some(body.clone().into()), true).await.unwrap();
                    return Ok(true);
                }
                config::Route::Proxy(_) => {
                    return Ok(false);
                }
            }
        }

        let mut headers = ResponseHeader::build(404, None).unwrap();
        headers.insert_header("Content-Length", "9").unwrap();
        headers.insert_header("Content-Type", "text/plain").unwrap();
        session.write_response_header(Box::new(headers), false).await.unwrap();
        session.write_response_body(Some("Not Found".into()), true).await.unwrap();
        Ok(true)
    }
}

fn main() {
    env_logger::init();
    let opts = Opts::parse();

    let config: Config = toml::from_str(&fs::read_to_string(&opts.config).unwrap()).unwrap();

    let mut my_server = Server::new(None).unwrap();
    my_server.bootstrap();

    for (name, server_config) in config.servers {
        info!("Starting server: {}", name);
        let routes = Arc::new(server_config.routes);
        let mut service = http_proxy_service(
            &my_server.configuration,
            RaddyApp {
                routes: routes.clone(),
            },
        );

        service.add_tcp(&server_config.listen);
        my_server.add_service(service);
    }

    my_server.run_forever();
}
