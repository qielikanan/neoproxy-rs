use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

/// 从 PEM 文件中读取证书链
pub fn load_certs<P: AsRef<Path>>(path: P) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut certs_vec = Vec::new();

    // rustls_pemfile::certs 返回一个迭代器，我们需要处理其中的错误
    for item in certs(&mut reader) {
        let cert = item.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        certs_vec.push(cert);
    }
    Ok(certs_vec)
}

/// 从 PEM 文件中读取私钥 (支持 RSA, PKCS8, EC 等)
pub fn load_private_key<P: AsRef<Path>>(path: P) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    private_key(&mut reader)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "No valid private key found in file",
        )
    })
}
