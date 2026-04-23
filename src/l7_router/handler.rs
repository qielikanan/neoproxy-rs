// 移除了未使用的 ATYP_DOMAIN
use super::address::{Address, ATYP_IPV4, ATYP_IPV6, UDP_OVER_TCP_DOMAIN};
use crate::l6_neomux::Stream;
use bytes::{BufMut, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub async fn handle_stream(mut stream: Stream) {
    // 1. 读取并解析客户端想访问的真实目标地址
    let addr = match Address::decode(&mut stream).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("[L7 服务端] 读取地址失败: {:?}", e);
            return;
        }
    };

    // ⚡️ 拦截 UDP 隧道请求
    if let Address::Domain(ref name, _) = addr {
        if name == UDP_OVER_TCP_DOMAIN {
            tracing::info!("[L7 服务端] 收到 UDP 隧道代理请求，启动虚拟 Socket 通道");
            handle_udp_stream(stream).await;
            return;
        }
    }

    let target_str = addr.to_string_addr();
    tracing::info!(
        "[L7 服务端] 收到代理请求，准备连接 TCP 目标: {}",
        target_str
    );

    // 2. 拨号连接到真实目标 (例如 google.com:443)
    // 移除了 target_conn 前面多余的 mut
    let target_conn = match TcpStream::connect(&target_str).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("[L7 服务端] 无法连接到目标 {}: {:?}", target_str, e);
            return;
        }
    };

    // 3. 建立双向零拷贝透传
    let (mut ri, mut wi) = tokio::io::split(stream);
    let (mut ro, mut wo) = tokio::io::split(target_conn);

    let _ = tokio::try_join!(
        tokio::io::copy(&mut ri, &mut wo),
        tokio::io::copy(&mut ro, &mut wi)
    );
}

// ============================================================================
// UDP 解析与转发服务
// ============================================================================

async fn handle_udp_stream(stream: Stream) {
    // 为该隧道分配独立的 UDP Socket 与公网交互
    let udp_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(_) => return,
    };

    let (mut stream_r, mut stream_w) = tokio::io::split(stream);
    let udp_out = udp_socket.clone();

    // 协程 A: Stream -> 公网 UDP 目标
    let up_task = tokio::spawn(async move {
        loop {
            let len = match stream_r.read_u16().await {
                Ok(l) => l,
                Err(_) => break,
            };
            if len == 0 {
                continue;
            }

            let mut payload = vec![0u8; len as usize];
            if stream_r.read_exact(&mut payload).await.is_err() {
                break;
            }

            // 浏览器传来的包裹自带 SOCKS5 UDP 头，我们需要从中解析出真实目标
            if let Ok((target_addr, offset)) = parse_socks5_udp_header(&payload) {
                let _ = udp_out.send_to(&payload[offset..], target_addr).await;
            }
        }
    });

    // 协程 B: 公网 UDP 目标 -> Stream
    let down_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, source_addr) = match udp_socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(_) => break,
            };

            // 将来自公网的真实 IP 包装成 SOCKS5 UDP 头塞回去
            let header = build_socks5_udp_header(source_addr);
            let total_len = header.len() + n;

            let mut out_buf = BytesMut::with_capacity(2 + total_len);
            out_buf.put_u16(total_len as u16);
            out_buf.put_slice(&header);
            out_buf.put_slice(&buf[..n]);

            if stream_w.write_all(&out_buf).await.is_err() {
                break;
            }
        }
    });

    let _ = tokio::try_join!(up_task, down_task);
}

fn parse_socks5_udp_header(data: &[u8]) -> Result<(SocketAddr, usize), &'static str> {
    if data.len() < 10 {
        return Err("packet too short");
    }
    if data[2] != 0 {
        return Err("fragmented udp not supported");
    }

    let atyp = data[3];
    let mut offset = 4;
    let ip: IpAddr;

    match atyp {
        ATYP_IPV4 => {
            if data.len() < offset + 4 + 2 {
                return Err("too short for ipv4");
            }
            let mut ip_buf = [0u8; 4];
            ip_buf.copy_from_slice(&data[offset..offset + 4]);
            ip = IpAddr::V4(Ipv4Addr::from(ip_buf));
            offset += 4;
        }
        ATYP_IPV6 => {
            if data.len() < offset + 16 + 2 {
                return Err("too short for ipv6");
            }
            let mut ip_buf = [0u8; 16];
            ip_buf.copy_from_slice(&data[offset..offset + 16]);
            ip = IpAddr::V6(Ipv6Addr::from(ip_buf));
            offset += 16;
        }
        _ => return Err("domain parsing not supported for udp server in this context"),
    }

    let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    Ok((SocketAddr::new(ip, port), offset))
}

fn build_socks5_udp_header(addr: SocketAddr) -> Vec<u8> {
    let mut buf = BytesMut::new();
    buf.put_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&ip.octets());
        }
    }
    buf.put_u16(addr.port());
    buf.to_vec()
}
