pub mod l4_security;
// pub mod l5_shaper; // 暂未实现 L5 流量整形，先注释掉
pub mod l6_neomux;
pub mod l7_router;

use anyhow::{Context, Result};
use l4_security::client::{build_tls_connector, connect_tls};
use l4_security::server::{accept_tls, build_tls_acceptor};
use l6_neomux::{Config as NeoMuxConfig, Session};
use l7_router::{handle_socks5, handle_stream, PoolConfig, SessionPool};
use serde::Deserialize;
use std::env;
use std::fs;
use std::sync::Arc;
use tokio::net::TcpListener;

/// 与 Go 版本 config.json 对应的配置结构体
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
}

fn default_security() -> String {
    "tls".to_string()
}
fn default_sni() -> String {
    "www.microsoft.com".to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    // 1. 初始化结构化日志
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    tracing::info!("🚀 NeoProxy-RS (Rust 极致性能版) 正在启动...");

    // 2. 解析命令行参数获取配置文件路径 (-c config.json)
    let args: Vec<String> = env::args().collect();
    let mut config_path = "config.json";
    if args.len() >= 3 && args[1] == "-c" {
        config_path = &args[2];
    }

    // 3. 读取并反序列化配置
    let config_data = fs::read_to_string(config_path)
        .with_context(|| format!("读取配置文件 {} 失败", config_path))?;
    let app_cfg: AppConfig =
        serde_json::from_str(&config_data).with_context(|| "解析 JSON 配置文件失败")?;

    // 4. 根据角色启动相应的模式
    match app_cfg.role.as_str() {
        "server" => run_server(app_cfg).await?,
        "client" => run_client(app_cfg).await?,
        _ => anyhow::bail!("未知的 role: {}, 必须是 'server' 或 'client'", app_cfg.role),
    }

    Ok(())
}

// ============================================================================
// 服务端主逻辑 (Server)
// ============================================================================
async fn run_server(app_cfg: AppConfig) -> Result<()> {
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

    // 2. 配置 L6 NeoMux 参数
    let mut neomux_cfg = NeoMuxConfig::default();
    neomux_cfg.is_client = false;
    neomux_cfg.require_auth = true;
    neomux_cfg.password = password;
    neomux_cfg.fallback_target = dest;

    // 3. 监听公网端口
    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!("✅ [服务端] 已启动，监听于: {}", listen_addr);

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        tracing::debug!("收到 TCP 连接: {}", peer_addr);

        let acceptor = tls_acceptor.clone();
        let cfg = neomux_cfg.clone();

        // 为每个物理连接 Spawn 一个新任务
        tokio::spawn(async move {
            // [L4] 将普通 TCP 升级为加密 TLS 流
            let tls_stream = match accept_tls(&acceptor, tcp_stream).await {
                Ok(s) => s,
                Err(_) => return, // TLS 握手失败，直接丢弃或交给回落逻辑
            };

            // [L6] 建立多路复用会话
            let session = match Session::new(tls_stream, cfg).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("构建 L6 Session 失败: {}", e);
                    return;
                }
            };

            // 循环接收远端发来的逻辑流 (Stream)
            loop {
                let stream = match session.accept_stream().await {
                    Ok(s) => s,
                    Err(_) => break, // 会话结束
                };

                // [L7] 将逻辑流丢给路由器处理 (连接到真正的目标网站)
                tokio::spawn(async move {
                    handle_stream(stream).await;
                });
            }
        });
    }
}

// ============================================================================
// 客户端主逻辑 (Client)
// ============================================================================
async fn run_client(app_cfg: AppConfig) -> Result<()> {
    let listen_addr = app_cfg
        .listen
        .unwrap_or_else(|| "127.0.0.1:1080".to_string());
    let remote_addr = app_cfg.remote.context("客户端必须提供 remote 服务端地址")?;
    let password = app_cfg
        .password
        .context("TLS 模式客户端必须提供 password 进行鉴权")?;
    let sni = app_cfg.sni;

    // 1. 构建 L4 TLS 拨号器 (自带 InsecureSkipVerify 和指纹伪装能力)
    let tls_connector = build_tls_connector();

    // 2. 构造闭包工厂：负责建立一条直达 L6 的多路复用隧道
    // 供 L7 SessionPool 在需要扩容时调用
    let dial_func: l7_router::session_pool::DialFunc = Arc::new(move || {
        let remote_addr = remote_addr.clone();
        let sni = sni.clone();
        let password = password.clone();
        let connector = tls_connector.clone();

        Box::pin(async move {
            // [L4] 拨号 TCP
            let tcp_stream = tokio::net::TcpStream::connect(&remote_addr).await?;
            // [L4] 升级为 TLS 流
            let tls_stream = connect_tls(&connector, &sni, tcp_stream).await?;

            // [L6] 建立多路复用 Session
            let mut neomux_cfg = NeoMuxConfig::default();
            neomux_cfg.is_client = true;
            neomux_cfg.require_auth = true;
            neomux_cfg.password = password;

            Session::new(tls_stream, neomux_cfg).await
        })
    });

    // 3. 配置并初始化 L7 高可用连接池
    let pool_config = PoolConfig {
        max_streams_per_session: 100, // 每个 TCP 连接最多 100 个并发流
        pre_dial_threshold: 80,       // 达到 80 个流时触发后台异步预拨号
        max_sessions: 10,             // 最多保持 10 个 TCP 物理连接
    };

    tracing::info!("⏳ 正在初始化客户端连接池...");
    let pool = Arc::new(SessionPool::new(dial_func, pool_config));

    // 预热：强制建立第一条物理连接，测试服务器连通性
    pool.warm_up()
        .await
        .with_context(|| "❌ 连接远端服务器预热失败")?;
    tracing::info!("✅ 核心引擎鉴权成功，连接池已就绪！");

    // 4. 监听本地 SOCKS5 端口
    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!("🚀 [客户端] SOCKS5 代理已运行在 {}", listen_addr);

    loop {
        let (conn, _peer_addr) = listener.accept().await?;
        let pool_clone = pool.clone();

        // 为每一个浏览器/客户端的接入派发任务
        tokio::spawn(async move {
            // [L7] 处理 SOCKS5 握手并利用 pool 分发到多路复用流
            if let Err(e) = handle_socks5(conn, pool_clone).await {
                tracing::debug!("SOCKS5 代理异常: {}", e);
            }
        });
    }
}
