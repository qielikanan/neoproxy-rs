use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

/// 从 PEM 文件中读取证书链
pub fn load_certs<P: AsRef<Path>>(path: P) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut certs_vec = Vec::new();

    for item in certs(&mut reader) {
        let cert = item.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        certs_vec.push(cert);
    }
    Ok(certs_vec)
}

/// 从 PEM 文件中读取私钥
pub fn load_private_key<P: AsRef<Path>>(path: P) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    private_key(&mut reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "未在文件中找到有效的私钥"))
}

/// 在内存中自动生成一张自签名证书 (供服务端零配置启动使用)
pub fn generate_dummy_cert(
    domain: &str,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // 使用 rcgen 生成自签名证书，指定 SNI 域名
    let cert = rcgen::generate_simple_self_signed(vec![domain.to_string()])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("证书生成失败: {}", e)))?;

    // 序列化为 DER 二进制格式
    let cert_der_bytes = cert
        .serialize_der()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("证书序列化失败: {}", e)))?;
    let key_der_bytes = cert.serialize_private_key_der();

    // 转换为 rustls 支持的强类型
    let cert_der = CertificateDer::from(cert_der_bytes);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der_bytes));

    Ok((vec![cert_der], key_der))
}
