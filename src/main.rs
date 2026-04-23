pub mod l4_security;
pub mod l5_shaper;
pub mod l6_neomux;
pub mod l7_router;

use anyhow::{Context, Result};
use l4_security::client::{build_tls_connector, connect_tls};
use l4_security::server::{accept_tls, build_tls_acceptor};
use l5_shaper::{parse_script, ShaperStream};
use l6_neomux::{Config as NeoMuxConfig, Session};
use l7_router::{handle_socks5, handle_stream, PoolConfig, SessionPool};
use serde::Deserialize;
use std::env;
use std::fs;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Debug, Deserialize)]
struct AppConfig {
    pub role: String,
    #[serde(default = "default_security")]
    pub security: String,
    pub listen: Option<String>,
    pub remote: Option<String>,
    #[serde(default = "default_sni")]
    pub sni: String,
    pub dest: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub password: Option<String>,
    #[serde(default = "default_padding")]
    pub padding: String,
}

fn default_security() -> String {
    "tls".to_string()
}
fn default_sni() -> String {
    "www.microsoft.com".to_string()
}
fn default_padding() -> String {
    "Fixed(ConnRand(200,800)); Inject(ConnRand(100,300));".to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    tracing::info!("🚀 NeoProxy-RS (Rust 极致性能版) 正在启动...");

    let args: Vec<String> = env::args().collect();
    let mut config_path = "config.json";
    if args.len() >= 3 && args[1] == "-c" {
        config_path = &args[2];
    }

    let config_data = fs::read_to_string(config_path)
        .with_context(|| format!("读取配置文件 {} 失败", config_path))?;
    let app_cfg: AppConfig =
        serde_json::from_str(&config_data).with_context(|| "解析 JSON 配置文件失败")?;

    match app_cfg.role.as_str() {
        "server" => run_server(app_cfg).await?,
        "client" => run_client(app_cfg).await?,
        _ => anyhow::bail!("未知的 role: {}, 必须是 'server' 或 'client'", app_cfg.role),
    }

    Ok(())
}

async fn run_server(app_cfg: AppConfig) -> Result<()> {
    if app_cfg.security != "tls" {
        tracing::warn!(
            "当前 Rust 版本暂且仅支持 'tls' 模式，配置的 '{}' 将作 tls 处理",
            app_cfg.security
        );
    }

    let listen_addr = app_cfg.listen.unwrap_or_else(|| "0.0.0.0:8443".to_string());
    let dest = app_cfg.dest.unwrap_or_else(|| "127.0.0.1:80".to_string());
    let password = app_cfg
        .password
        .context("TLS 模式服务端必须提供 password 进行鉴权")?;
    let cert_path = app_cfg.cert.context("必须提供 cert 证书路径")?;
    let key_path = app_cfg.key.context("必须提供 key 私钥路径")?;

    // 1. 构建 L4 TLS 接收器
    let tls_acceptor =
        build_tls_acceptor(&cert_path, &key_path).with_context(|| "构建 TLS 证书套件失败")?;

    let padding_script = app_cfg.padding.clone();

    let mut neomux_cfg = NeoMuxConfig::default();
    neomux_cfg.is_client = false;
    neomux_cfg.require_auth = true;
    neomux_cfg.password = password;
    neomux_cfg.fallback_target = dest;

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!("✅ [服务端] 已启动，监听于: {}", listen_addr);

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        tracing::debug!("收到 TCP 连接: {}", peer_addr);

        let acceptor = tls_acceptor.clone();
        let cfg = neomux_cfg.clone();
        let script = padding_script.clone();

        tokio::spawn(async move {
            let tls_stream = match accept_tls(&acceptor, tcp_stream).await {
                Ok(s) => s,
                Err(_) => return,
            };

            let scheme = parse_script(&script).ok();
            let shaper_stream = ShaperStream::new(tls_stream, scheme);

            let session = match Session::new(shaper_stream, cfg).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("构建 L6 Session 失败: {}", e);
                    return;
                }
            };

            loop {
                let stream = match session.accept_stream().await {
                    Ok(s) => s,
                    Err(_) => break,
                };

                tokio::spawn(async move {
                    handle_stream(stream).await;
                });
            }
        });
    }
}

async fn run_client(app_cfg: AppConfig) -> Result<()> {
    if app_cfg.security != "tls" {
        tracing::warn!(
            "当前 Rust 版本暂且仅支持 'tls' 模式，配置的 '{}' 将作 tls 处理",
            app_cfg.security
        );
    }

    // 补充之前遗漏的变量定义
    let listen_addr = app_cfg
        .listen
        .unwrap_or_else(|| "127.0.0.1:1080".to_string());
    let remote_addr = app_cfg.remote.context("客户端必须提供 remote 服务端地址")?;
    let sni = app_cfg.sni;
    let password = app_cfg
        .password
        .context("TLS 模式客户端必须提供 password 进行鉴权")?;

    let tls_connector = build_tls_connector();
    let padding_script = app_cfg.padding.clone();

    let dial_func: l7_router::session_pool::DialFunc = Arc::new(move || {
        let remote_addr = remote_addr.clone();
        let sni = sni.clone();
        let password = password.clone();
        let connector = tls_connector.clone();
        let script = padding_script.clone();

        Box::pin(async move {
            let tcp_stream = tokio::net::TcpStream::connect(&remote_addr).await?;
            let tls_stream = connect_tls(&connector, &sni, tcp_stream).await?;

            let scheme = parse_script(&script).ok();
            let shaper_stream = ShaperStream::new(tls_stream, scheme);

            let mut neomux_cfg = NeoMuxConfig::default();
            neomux_cfg.is_client = true;
            neomux_cfg.require_auth = true;
            neomux_cfg.password = password;

            Session::new(shaper_stream, neomux_cfg).await
        })
    });

    let pool_config = PoolConfig {
        max_streams_per_session: 100,
        pre_dial_threshold: 80,
        max_sessions: 10,
    };

    tracing::info!("⏳ 正在初始化客户端连接池...");
    let pool = Arc::new(SessionPool::new(dial_func, pool_config));

    pool.warm_up()
        .await
        .with_context(|| "❌ 连接远端服务器预热失败")?;
    tracing::info!("✅ 核心引擎鉴权成功，连接池已就绪！");

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!("🚀 [客户端] SOCKS5 代理已运行在 {}", listen_addr);

    loop {
        let (conn, _peer_addr) = listener.accept().await?;
        let pool_clone = pool.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_socks5(conn, pool_clone).await {
                tracing::debug!("SOCKS5 代理异常: {}", e);
            }
        });
    }
}
