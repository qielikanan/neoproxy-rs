use super::tokio_jls::TlsStream;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::jls::JlsClientConfig;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::io;
use std::sync::Arc;
use tokio::net::TcpStream;

#[derive(Debug)]
struct PinnedVerifier {
    expected_hash: String,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let hash = hasher.finalize();
        let hash_str = hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        if hash_str.eq_ignore_ascii_case(&self.expected_hash) {
            Ok(ServerCertVerified::assertion())
        } else {
            tracing::warn!(
                "⚠️ 证书固定校验失败！期待: {}, 实际收到: {}",
                self.expected_hash,
                hash_str
            );
            Err(RustlsError::General(format!(
                "certificate pinning verification failed! Expected {}, got {}",
                self.expected_hash, hash_str
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

pub fn build_tls_connector(pinned_hash: Option<&str>) -> Arc<ClientConfig> {
    let mut config = if let Some(hash) = pinned_hash {
        // 使用自签证书并进行 Hash 固定校验
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                expected_hash: hash.to_string(),
            }))
            .with_no_client_auth()
    } else {
        // 默认行为：严谨校验系统信任的 CA 证书与 SNI
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

pub fn build_tls_connector_jls(iv: &str, pwd: &str) -> Arc<ClientConfig> {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.jls_config = JlsClientConfig::new(iv.into(), pwd.into());
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Arc::new(config)
}

pub async fn connect_tls(
    config: &Arc<ClientConfig>,
    domain_sni: &str,
    stream: TcpStream,
) -> io::Result<TlsStream<TcpStream>> {
    let domain = ServerName::try_from(domain_sni)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid SNI domain"))?
        .to_owned();

    let conn = rustls::ClientConnection::new(Arc::clone(config), domain)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let mut tls = TlsStream::new(rustls::Connection::Client(conn), stream);
    tls.handshake().await?;
    Ok(tls)
}
