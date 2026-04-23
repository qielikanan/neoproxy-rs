use super::cert::{generate_dummy_cert, load_certs, load_private_key};
use rustls::ServerConfig;
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// 构建服务端 TLS 接收器 (使用外部证书文件)
pub fn build_tls_acceptor<P: AsRef<Path>>(cert_path: P, key_path: P) -> io::Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// 构建服务端 TLS 接收器 (在内存中动态生成自签名证书)
pub fn build_tls_acceptor_generated(domain: &str) -> io::Result<TlsAcceptor> {
    let (certs, key) = generate_dummy_cert(domain)?;

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
    let tls_stream = acceptor.accept(stream).await?;
    Ok(tls_stream)
}
