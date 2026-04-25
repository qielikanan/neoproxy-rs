pub mod l4_security;
pub mod l5_shaper;
pub mod l6_neomux;
pub mod l7_router;

use anyhow::{Context, Result};
use l4_security::client::{build_tls_connector, build_tls_connector_jls, connect_tls};
use l4_security::server::{
    accept_tls, build_tls_acceptor, build_tls_acceptor_generated, build_tls_acceptor_jls,
    build_tls_acceptor_jls_generated,
};
use l4_security::tokio_jls::TlsStream;
use l5_shaper::{parse_script, ShaperStream};
use l6_neomux::{Config as NeoMuxConfig, Session};
use l7_router::{handle_socks5, handle_stream, PoolConfig, SessionPool};
use serde::Deserialize;
use std::env;
use std::fs;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    pub jls_iv: Option<String>,
    pub pinnedhash: Option<String>,
    #[serde(default = "default_padding")]
    pub padding: String,
}

fn default_security() -> String {
    "jls".to_string()
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

    tracing::info!("🚀 NeoProxy-RS (JLS Edition) 正在启动...");

    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() >= 3 && args[1] == "-c" {
        &args[2]
    } else {
        "config.json"
    };

    let config_data = fs::read_to_string(config_path)?;
    let app_cfg: AppConfig = serde_json::from_str(&config_data)?;

    match app_cfg.role.as_str() {
        "server" => run_server(app_cfg).await?,
        "client" => run_client(app_cfg).await?,
        _ => anyhow::bail!("未知的 role"),
    }
    Ok(())
}

async fn do_fallback(stream: TlsStream<tokio::net::TcpStream>, dest: String) {
    tracing::warn!(
        "🛡️ [Fallback] JLS 鉴权失败或未携带认证，将流量无感路由至本地伪装站点: {}",
        dest
    );
    if let Ok(target) = tokio::net::TcpStream::connect(&dest).await {
        let (mut ri, mut wi) = tokio::io::split(stream);
        let (mut ro, mut wo) = tokio::io::split(target);
        let _ = tokio::try_join!(
            // 浏览器到 Nginx 的方向 (通常是客户端主动发包，普通 copy 即可)
            async {
                let _ = tokio::io::copy(&mut ri, &mut wo).await;
                let _ = wo.shutdown().await;
                Ok::<(), io::Error>(())
            },
            async {
                let mut buf = [0u8; 8192];
                loop {
                    match tokio::io::AsyncReadExt::read(&mut ro, &mut buf).await {
                        Ok(0) => break, // Nginx 断开连接
                        Ok(n) => {
                            if tokio::io::AsyncWriteExt::write_all(&mut wi, &buf[..n])
                                .await
                                .is_err()
                            {
                                break;
                            }
                            if tokio::io::AsyncWriteExt::flush(&mut wi).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = wi.shutdown().await;
                Ok::<(), io::Error>(())
            }
        );
    }
}

async fn start_spider(mut stream: TlsStream<tokio::net::TcpStream>, sni: String) {
    tracing::error!("🕷️ [Spider Mode] 遭遇中间人(MITM)或连接到真实服务器！启动防篡改爬虫伪装...");
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: text/html\r\nConnection: close\r\n\r\n",
        sni
    );
    if stream.write_all(req.as_bytes()).await.is_ok() {
        let mut buf = vec![0u8; 8192];
        let _ = stream.read(&mut buf).await;
        tracing::info!("🕷️ 伪装抓取完成，隐蔽断开。");
    }
}

async fn run_server(app_cfg: AppConfig) -> Result<()> {
    let listen_addr = app_cfg.listen.unwrap_or_else(|| "0.0.0.0:8443".to_string());
    let dest = app_cfg.dest.unwrap_or_else(|| "127.0.0.1:80".to_string());
    let password = app_cfg.password.context("服务端必须提供 password")?;
    let iv = app_cfg
        .jls_iv
        .unwrap_or_else(|| "3070111071563328618171495819203123318".to_string());
    let sni = app_cfg.sni.clone();
    let _padding_script = app_cfg.padding.clone();
    let security_mode = app_cfg.security.clone();

    let tls_config = if security_mode == "jls" {
        if let (Some(cert), Some(key)) = (&app_cfg.cert, &app_cfg.key) {
            build_tls_acceptor_jls(cert, key, &iv, &password)?
        } else {
            tracing::info!("⚡ 自动为 JLS 生成临时自签证书...");
            build_tls_acceptor_jls_generated(&sni, &iv, &password)?
        }
    } else {
        if let (Some(cert), Some(key)) = (&app_cfg.cert, &app_cfg.key) {
            build_tls_acceptor(cert, key)?
        } else {
            build_tls_acceptor_generated(&sni)?
        }
    };

    let mut neomux_cfg = NeoMuxConfig::default();
    neomux_cfg.is_client = false;
    neomux_cfg.fallback_target = dest.clone();
    if security_mode == "tls" {
        neomux_cfg.require_auth = true;
        neomux_cfg.password = password.clone();
    }

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(
        "✅ [服务端] 监听于: {} (模式: {})",
        listen_addr,
        security_mode
    );

    loop {
        let (tcp_stream, _) = listener.accept().await?;
        let config = tls_config.clone();
        let neomux_cfg_clone = neomux_cfg.clone();
        let mode_clone = security_mode.clone();
        let fallback_target = dest.clone();

        tokio::spawn(async move {
            let tls_stream = match accept_tls(&config, tcp_stream).await {
                Ok(s) => s,
                Err(_) => return,
            };

            if mode_clone == "jls" {
                if !matches!(
                    tls_stream.jls_state(),
                    rustls::jls::JlsState::AuthSuccess(_)
                ) {
                    do_fallback(tls_stream, fallback_target).await;
                    return;
                }
            }

            let shaper_stream = ShaperStream::new(tls_stream, None);
            let session = match Session::new(shaper_stream, neomux_cfg_clone).await {
                Ok(s) => s,
                Err(_) => return,
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
    let listen_addr = app_cfg
        .listen
        .unwrap_or_else(|| "127.0.0.1:1080".to_string());
    let remote_addr = app_cfg.remote.context("必须提供 remote")?;
    let sni = app_cfg.sni;
    let password = app_cfg.password.context("必须提供 password")?;
    let iv = app_cfg
        .jls_iv
        .unwrap_or_else(|| "3070111071563328618171495819203123318".to_string());
    let security_mode = app_cfg.security.clone();
    let padding_script = app_cfg.padding.clone();
    let pinnedhash = app_cfg.pinnedhash.clone();

    let tls_config = if security_mode == "jls" {
        build_tls_connector_jls(&iv, &password)
    } else {
        build_tls_connector(pinnedhash.as_deref())
    };

    let dial_func: l7_router::session_pool::DialFunc = Arc::new(move || {
        let remote = remote_addr.clone();
        let sni_clone = sni.clone();
        let pwd = password.clone();
        let config_clone = tls_config.clone();
        let script = padding_script.clone();
        let mode_clone = security_mode.clone();

        Box::pin(async move {
            let tcp = tokio::net::TcpStream::connect(&remote).await?;
            let tls = connect_tls(&config_clone, &sni_clone, tcp).await?;

            if mode_clone == "jls" {
                if !matches!(tls.jls_state(), rustls::jls::JlsState::AuthSuccess(_)) {
                    start_spider(tls, sni_clone).await;
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "MITM"));
                }
            }

            let scheme = parse_script(&script).ok();
            let shaper = ShaperStream::new(tls, scheme);
            let mut cfg = NeoMuxConfig::default();
            cfg.is_client = true;
            if mode_clone == "tls" {
                cfg.require_auth = true;
                cfg.password = pwd;
            }

            Session::new(shaper, cfg).await
        })
    });

    let pool_config = PoolConfig {
        max_streams_per_session: 100,
        pre_dial_threshold: 80,
        max_sessions: 10,
    };
    let pool = Arc::new(SessionPool::new(dial_func, pool_config));

    tracing::info!("⏳ 正在进行 JLS/TLS 安全握手与预热...");
    pool.warm_up()
        .await
        .context("连接池预热失败 (握手失败或鉴权未通过)")?;
    tracing::info!("✅ 远端握手成功，连接池已就绪！");

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!("🚀 [客户端] 代理运行在 {}", listen_addr);

    loop {
        let (conn, _) = listener.accept().await?;
        let p_clone = pool.clone();
        tokio::spawn(async move {
            let _ = handle_socks5(conn, p_clone).await;
        });
    }
}
