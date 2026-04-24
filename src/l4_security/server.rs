use super::cert::{generate_dummy_cert, load_certs, load_private_key};
use super::tokio_jls::TlsStream;
use rustls::jls::JlsServerConfig;
use rustls::ServerConfig;
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;

pub fn build_tls_acceptor<P: AsRef<Path>>(
    cert_path: P,
    key_path: P,
) -> io::Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok(Arc::new(config))
}

pub fn build_tls_acceptor_jls<P: AsRef<Path>>(
    cert_path: P,
    key_path: P,
    iv: &str,
    pwd: &str,
) -> io::Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let jls_cfg = JlsServerConfig::new(iv.into(), pwd.into(), None, None);
    config.jls_config = jls_cfg.into();
    Ok(Arc::new(config))
}
pub fn build_tls_acceptor_generated(domain: &str) -> io::Result<Arc<ServerConfig>> {
    let (certs, key) = generate_dummy_cert(domain)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok(Arc::new(config))
}

pub fn build_tls_acceptor_jls_generated(
    domain: &str,
    iv: &str,
    pwd: &str,
) -> io::Result<Arc<ServerConfig>> {
    let (certs, key) = generate_dummy_cert(domain)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let jls_cfg = JlsServerConfig::new(iv.into(), pwd.into(), None, None);
    config.jls_config = jls_cfg.into();
    Ok(Arc::new(config))
}

pub async fn accept_tls(
    config: &Arc<ServerConfig>,
    stream: TcpStream,
) -> io::Result<TlsStream<TcpStream>> {
    let conn = rustls::ServerConnection::new(Arc::clone(config))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let mut tls = TlsStream::new(rustls::Connection::Server(conn), stream);
    tls.handshake().await?;
    Ok(tls)
}
