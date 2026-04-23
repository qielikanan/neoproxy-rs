use bytes::{BufMut, BytesMut};
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr}; // 移除了未使用到的 IpAddr
use tokio::io::{AsyncRead, AsyncReadExt};

pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAIN: u8 = 3;
pub const ATYP_IPV6: u8 = 4;

pub const UDP_OVER_TCP_DOMAIN: &str = "udp-over-tcp.arpa";

#[derive(Debug, Clone)]
pub enum Address {
    IPv4(Ipv4Addr, u16),
    Domain(String, u16),
    IPv6(Ipv6Addr, u16),
}

impl Address {
    /// 编码为标准的 SOCKS5 目标地址格式
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        match self {
            Address::IPv4(ip, port) => {
                buf.put_u8(ATYP_IPV4);
                buf.put_slice(&ip.octets());
                buf.put_u16(*port);
            }
            Address::IPv6(ip, port) => {
                buf.put_u8(ATYP_IPV6);
                buf.put_slice(&ip.octets());
                buf.put_u16(*port);
            }
            Address::Domain(domain, port) => {
                buf.put_u8(ATYP_DOMAIN);
                let bytes = domain.as_bytes();
                buf.put_u8(bytes.len() as u8);
                buf.put_slice(bytes);
                buf.put_u16(*port);
            }
        }
        buf.to_vec()
    }

    /// 从异步流中解码 SOCKS5 目标地址
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let atyp = reader.read_u8().await?;
        match atyp {
            ATYP_IPV4 => {
                let mut ip_buf = [0u8; 4];
                reader.read_exact(&mut ip_buf).await?;
                let port = reader.read_u16().await?;
                Ok(Address::IPv4(Ipv4Addr::from(ip_buf), port))
            }
            ATYP_DOMAIN => {
                let len = reader.read_u8().await? as usize;
                let mut domain_buf = vec![0u8; len];
                reader.read_exact(&mut domain_buf).await?;
                let port = reader.read_u16().await?;
                let domain = String::from_utf8(domain_buf).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid domain utf8")
                })?;
                Ok(Address::Domain(domain, port))
            }
            ATYP_IPV6 => {
                let mut ip_buf = [0u8; 16];
                reader.read_exact(&mut ip_buf).await?;
                let port = reader.read_u16().await?;
                Ok(Address::IPv6(Ipv6Addr::from(ip_buf), port))
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ATYP")),
        }
    }

    /// 转换为可用于标准库 Dial 的字符串格式 (如 "google.com:443")
    pub fn to_string_addr(&self) -> String {
        match self {
            Address::IPv4(ip, port) => format!("{}:{}", ip, port),
            Address::IPv6(ip, port) => format!("[{}]:{}", ip, port),
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }
}

// 修正了 Display 特性的返回类型和写法
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_addr())
    }
}
