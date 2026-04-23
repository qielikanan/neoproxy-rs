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

    // 1. SOCKS5 握手 (No Auth)
    conn.read_exact(&mut buf[..2]).await?;
    if buf[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not socks5"));
    }
    let num_methods = buf[1] as usize;
    conn.read_exact(&mut buf[..num_methods]).await?;
    conn.write_all(&[0x05, 0x00]).await?;

    // 2. 读取请求命令
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

            // 0-RTT: 拨号成功后立刻把目标地址封包发给远端服务器
            let encoded_addr = addr.encode();
            stream.write_all(&encoded_addr).await?;

            // 告诉浏览器连接成功
            conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;

            // 建立双向无拷贝转发
            let (mut ri, mut wi) = tokio::io::split(conn);
            let (mut ro, mut wo) = tokio::io::split(stream);
            let _ = tokio::try_join!(
                tokio::io::copy(&mut ri, &mut wo),
                tokio::io::copy(&mut ro, &mut wi)
            );
        }
        0x03 => {
            // ==========================================
            // UDP ASSOCIATE 隧道逻辑 (UDP over TCP)
            // ==========================================
            let _client_addr = Address::decode(&mut conn).await?; // 忽略浏览器传来的源地址

            // 绑定本地一个随机 UDP 端口
            let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
            let local_addr = udp_socket.local_addr()?;

            // 响应浏览器，让它把 UDP 包发到我们刚绑定的端口
            let reply = build_socks5_udp_reply(0x00, local_addr);
            conn.write_all(&reply).await?;

            // 开启一个指向保留域名的 L6 隧道
            let mut stream = pool.open_stream().await?;
            let special_addr = Address::Domain(UDP_OVER_TCP_DOMAIN.to_string(), 0).encode();
            stream.write_all(&special_addr).await?;

            tracing::info!("[SOCKS5] 开启本地 UDP 透传中继: {}", local_addr);

            // 记录最近一个向我们发包的浏览器 UDP 端口，用于下行回包
            let browser_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
            let udp_socket = Arc::new(udp_socket);

            let (mut stream_r, mut stream_w) = tokio::io::split(stream);
            let udp_in = udp_socket.clone();
            let addr_in = browser_addr.clone();

            // 协程 A：上行 (UDP -> TCP Stream)
            let up_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let (n, addr) = match udp_in.recv_from(&mut buf).await {
                        Ok(res) => res,
                        Err(_) => break,
                    };
                    *addr_in.lock().await = Some(addr); // 更新回包地址

                    // 为 UDP 包加上 2 字节的长度头并写入 L6 流
                    let _ = stream_w.write_u16(n as u16).await;
                    if stream_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });

            // 协程 B：下行 (TCP Stream -> UDP)
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

            // 协程 C：维持 TCP 控制流
            // SOCKS5 规范：如果原本的 TCP 控制流断开，UDP 中继必须立刻终止
            let _ = tokio::io::copy(&mut conn, &mut tokio::io::sink()).await;
            up_task.abort();
            down_task.abort();
        }
        _ => {
            // Command not supported
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
