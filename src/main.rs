pub mod l4_security;
pub mod l5_shaper;
pub mod l6_neomux;
pub mod l7_router;

use anyhow::{Context, Result};
use l4_security::client::{build_tls_connector, connect_tls};
use l4_security::server::{accept_tls, build_tls_acceptor, build_tls_acceptor_generated};
use l5_shaper::{parse_script, ShaperStream};
use l6_neomux::{Config as NeoMuxConfig, Session};
use l7_router::{handle_socks5, handle_stream, PoolConfig, SessionPool};
use serde::Deserialize;
use std::env;
use std::fs;
use std::sync::Arc;
use tokio::net::TcpListener;

/// 核心配置结构体
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
    // 初始化日志系统
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    tracing::info!("🚀 NeoProxy-RS (Rust 极致性能版) 正在启动...");

    // 解析命令行参数 -c
    let args: Vec<String> = env::args().collect();
    let mut config_path = "config.json";
    if args.len() >= 3 && args[1] == "-c" {
        config_path = &args[2];
    }

    // 加载 JSON 配置
    let config_data = fs::read_to_string(config_path)
        .with_context(|| format!("读取配置文件 {} 失败", config_path))?;
    let app_cfg: AppConfig =
        serde_json::from_str(&config_data).with_context(|| "解析 JSON 失败")?;

    match app_cfg.role.as_str() {
        "server" => run_server(app_cfg).await?,
        "client" => run_client(app_cfg).await?,
        _ => anyhow::bail!("未知的 role: {}", app_cfg.role),
    }

    Ok(())
}

// ============================================================================
// 服务端逻辑
// ============================================================================
async fn run_server(app_cfg: AppConfig) -> Result<()> {
    if app_cfg.security != "tls" {
        tracing::warn!(
            "注意: 当前版本暂仅支持 'tls' 模式，配置的 '{}' 将作 tls 处理",
            app_cfg.security
        );
    }

    let listen_addr = app_cfg.listen.unwrap_or_else(|| "0.0.0.0:8443".to_string());
    let dest = app_cfg.dest.unwrap_or_else(|| "127.0.0.1:80".to_string());
    let password = app_cfg.password.context("服务端必须提供 password")?;
    let sni = app_cfg.sni.clone();
    let padding_script = app_cfg.padding.clone();

    // 1. L4: 智能构建 TLS 接收器
    let tls_acceptor = if let (Some(cert_path), Some(key_path)) = (&app_cfg.cert, &app_cfg.key) {
        tracing::info!("🔒 加载外部证书: {} / {}", cert_path, key_path);
        build_tls_acceptor(cert_path, key_path)?
    } else {
        tracing::info!("⚡ 自动为 SNI [{}] 生成临时自签证书...", sni);
        build_tls_acceptor_generated(&sni)?
    };

    // 2. L6: 预配置 NeoMux
    let mut neomux_cfg = NeoMuxConfig::default();
    neomux_cfg.is_client = false;
    neomux_cfg.require_auth = true;
    neomux_cfg.password = password;
    neomux_cfg.fallback_target = dest;

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!("✅ [服务端] 监听于: {}", listen_addr);

    loop {
        let (tcp_stream, _peer_addr) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        let cfg = neomux_cfg.clone();
        let script = padding_script.clone();

        tokio::spawn(async move {
            // [L4] TLS 握手
            let tls_stream = match accept_tls(&acceptor, tcp_stream).await {
                Ok(s) => s,
                Err(_) => return,
            };

            // [L5] 流量整形
            let scheme = parse_script(&script).ok();
            let shaper_stream = ShaperStream::new(tls_stream, scheme);

            // [L6] 多路复用会话
            let session = match Session::new(shaper_stream, cfg).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Session 建立失败: {}", e);
                    return;
                }
            };

            // [L7] 循环接受逻辑流并路由
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

// ============================================================================
// 客户端逻辑
// ============================================================================
async fn run_client(app_cfg: AppConfig) -> Result<()> {
    if app_cfg.security != "tls" {
        tracing::warn!(
            "注意: 当前版本暂仅支持 'tls' 模式，配置的 '{}' 将作 tls 处理",
            app_cfg.security
        );
    }

    let listen_addr = app_cfg
        .listen
        .unwrap_or_else(|| "127.0.0.1:1080".to_string());
    let remote_addr = app_cfg.remote.context("客户端必须提供 remote 地址")?;
    let sni = app_cfg.sni;
    let password = app_cfg.password.context("客户端必须提供 password")?;
    let padding_script = app_cfg.padding.clone();

    // 1. L4: 构建拨号器
    let tls_connector = build_tls_connector();

    // 2. 构造连接工厂 (供连接池使用)
    let dial_func: l7_router::session_pool::DialFunc = Arc::new(move || {
        let remote = remote_addr.clone();
        let sni_clone = sni.clone();
        let pwd = password.clone();
        let connector = tls_connector.clone();
        let script = padding_script.clone();

        Box::pin(async move {
            let tcp = tokio::net::TcpStream::connect(&remote).await?;
            let tls = connect_tls(&connector, &sni_clone, tcp).await?;

            let scheme = parse_script(&script).ok();
            let shaper = ShaperStream::new(tls, scheme);

            let mut cfg = NeoMuxConfig::default();
            cfg.is_client = true;
            cfg.require_auth = true;
            cfg.password = pwd;

            Session::new(shaper, cfg).await
        })
    });

    // 3. L7: 初始化高可用连接池
    let pool_config = PoolConfig {
        max_streams_per_session: 100,
        pre_dial_threshold: 80,
        max_sessions: 10,
    };

    tracing::info!("⏳ 正在初始化客户端连接池...");
    let pool = Arc::new(SessionPool::new(dial_func, pool_config));
    pool.warm_up().await.context("连接池预热失败")?;
    tracing::info!("✅ 远端握手成功，连接池已就绪！");

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!("🚀 [客户端] SOCKS5 代理运行在 {}", listen_addr);

    loop {
        let (conn, _) = listener.accept().await?;
        let p_clone = pool.clone();
        tokio::spawn(async move {
            let _ = handle_socks5(conn, p_clone).await;
        });
    }
}
