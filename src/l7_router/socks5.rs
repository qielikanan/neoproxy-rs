use super::address::{Address, ATYP_IPV4, ATYP_IPV6, UDP_OVER_TCP_DOMAIN};
use super::session_pool::SessionPool;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

pub async fn handle_socks5(mut conn: TcpStream, pool: Arc<SessionPool>) -> io::Result<()> {
    let mut buf = [0u8; 256];

    conn.read_exact(&mut buf[..2]).await?;
    if buf[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not socks5"));
    }
    let num_methods = buf[1] as usize;
    conn.read_exact(&mut buf[..num_methods]).await?;
    conn.write_all(&[0x05, 0x00]).await?;

    conn.read_exact(&mut buf[..3]).await?;
    if buf[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socks5 request",
        ));
    }

    let cmd = buf[1];
    match cmd {
        0x01 => {
            // ==========================================
            // TCP CONNECT 代理逻辑
            // ==========================================
            let addr = Address::decode(&mut conn).await?;
            let mut stream = pool.open_stream().await?;

            let encoded_addr = addr.encode();
            stream.write_all(&encoded_addr).await?;

            conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;

            let (mut ri, mut wi) = tokio::io::split(conn);
            let (mut ro, mut wo) = tokio::io::split(stream);

            // 修复：添加优雅半关闭 (Half-Close)，防浏览器请求卡死
            let browser_to_target = async {
                let _ = tokio::io::copy(&mut ri, &mut wo).await;
                let _ = wo.shutdown().await;
                Ok::<(), std::io::Error>(())
            };

            let target_to_browser = async {
                let _ = tokio::io::copy(&mut ro, &mut wi).await;
                let _ = wi.shutdown().await;
                Ok::<(), std::io::Error>(())
            };

            let _ = tokio::try_join!(browser_to_target, target_to_browser);
        }
        0x03 => {
            // ==========================================
            // UDP ASSOCIATE 隧道逻辑 (UDP over TCP)
            // ==========================================
            let _client_addr = Address::decode(&mut conn).await?;

            let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
            let local_addr = udp_socket.local_addr()?;

            let reply = build_socks5_udp_reply(0x00, local_addr);
            conn.write_all(&reply).await?;

            let mut stream = pool.open_stream().await?;
            let special_addr = Address::Domain(UDP_OVER_TCP_DOMAIN.to_string(), 0).encode();
            stream.write_all(&special_addr).await?;

            tracing::info!("[SOCKS5] 开启本地 UDP 透传中继: {}", local_addr);

            let browser_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
            let udp_socket = Arc::new(udp_socket);

            let (mut stream_r, mut stream_w) = tokio::io::split(stream);
            let udp_in = udp_socket.clone();
            let addr_in = browser_addr.clone();

            let up_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let (n, addr) = match udp_in.recv_from(&mut buf).await {
                        Ok(res) => res,
                        Err(_) => break,
                    };
                    *addr_in.lock().await = Some(addr);

                    let _ = stream_w.write_u16(n as u16).await;
                    if stream_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });

            let udp_out = udp_socket.clone();
            let addr_out = browser_addr.clone();
            let down_task = tokio::spawn(async move {
                loop {
                    let len = match stream_r.read_u16().await {
                        Ok(l) => l,
                        Err(_) => break,
                    };
                    let mut payload = vec![0u8; len as usize];
                    if stream_r.read_exact(&mut payload).await.is_err() {
                        break;
                    }

                    if let Some(target) = *addr_out.lock().await {
                        let _ = udp_out.send_to(&payload, target).await;
                    }
                }
            });

            let _ = tokio::io::copy(&mut conn, &mut tokio::io::sink()).await;
            up_task.abort();
            down_task.abort();
        }
        _ => {
            let _ = conn
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
        }
    }
    Ok(())
}

fn build_socks5_udp_reply(rep: u8, addr: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x05, rep, 0x00]);
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
    buf
}
