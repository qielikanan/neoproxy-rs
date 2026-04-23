use super::cert::{load_certs, load_private_key};
use rustls::ServerConfig;
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// 构建服务端 TLS 接收器
/// 建议在程序启动时调用一次，然后克隆 Arc<TlsAcceptor> 给每个连接使用
pub fn build_tls_acceptor<P: AsRef<Path>>(cert_path: P, key_path: P) -> io::Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    // 配置 TLS，强制使用安全协议，禁用客户端证书验证
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// 将普通的 TcpStream 升级为加密的 TlsStream
pub async fn accept_tls(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
) -> io::Result<TlsStream<TcpStream>> {
    // 进行 TLS 握手
    let tls_stream = acceptor.accept(stream).await?;
    Ok(tls_stream)
}
