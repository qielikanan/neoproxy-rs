use rustls::Connection;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 适配器：将 Tokio 的异步上下文桥接到 Rustls 所需的同步 io::Read / io::Write 接口。
/// 修复生命周期：彻底解耦了 T 的生命周期 ('a) 和 Context 的生命周期 ('b, 'c)，防止借用检查器误判。
struct SyncIo<'a, 'b, 'c, T> {
    io: &'a mut T,
    cx: &'b mut Context<'c>,
}

impl<'a, 'b, 'c, T: AsyncRead + Unpin> Read for SyncIo<'a, 'b, 'c, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = ReadBuf::new(buf);
        match Pin::new(&mut *self.io).poll_read(self.cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled().len();
                if filled == 0 && !buf.is_empty() {
                    Ok(0) // EOF
                } else {
                    Ok(filled)
                }
            }
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::Error::new(io::ErrorKind::WouldBlock, "would block")),
        }
    }
}

impl<'a, 'b, 'c, T: AsyncWrite + Unpin> Write for SyncIo<'a, 'b, 'c, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write(self.cx, buf) {
            Poll::Ready(Ok(n)) => Ok(n),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::Error::new(io::ErrorKind::WouldBlock, "would block")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut *self.io).poll_flush(self.cx) {
            Poll::Ready(Ok(())) => Ok(()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::Error::new(io::ErrorKind::WouldBlock, "would block")),
        }
    }
}

/// 核心：自己实现的高性能异步 TLS 流封装 (彻底摆脱 tokio-rustls 的依赖限制)
pub struct TlsStream<T> {
    pub conn: Connection,
    pub io: T,
}

impl<T: AsyncRead + AsyncWrite + Unpin> TlsStream<T> {
    pub fn new(conn: Connection, io: T) -> Self {
        Self { conn, io }
    }

    /// 提取 JLS 的鉴权状态 (修复：jls_authed 是属性，并且返回 JlsState 枚举)
    pub fn jls_state(&self) -> rustls::jls::JlsState {
        match &self.conn {
            Connection::Client(c) => c.jls_authed.clone(),
            Connection::Server(s) => s.jls_authed.clone(),
        }
    }

    /// 异步驱动 TLS 握手
    pub async fn handshake(&mut self) -> io::Result<()> {
        Handshake { stream: self }.await
    }
}

// 将 Handshake 提取为一个独立的 Future，完美规避 async fn + 闭包 的双重借用生命周期难题
struct Handshake<'a, T> {
    stream: &'a mut TlsStream<T>,
}

impl<'a, T: AsyncRead + AsyncWrite + Unpin> std::future::Future for Handshake<'a, T> {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let stream = &mut self.stream;

        while stream.conn.is_handshaking() {
            let mut progressed = false;
            // 短生命周期的包装器，用完即扔，绝不占用 stream.io
            let mut sync_io = SyncIo {
                io: &mut stream.io,
                cx: &mut *cx,
            };

            // 1. 尝试写出握手数据包
            while stream.conn.wants_write() {
                match stream.conn.write_tls(&mut sync_io) {
                    Ok(0) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero",
                        )))
                    }
                    Ok(_) => progressed = true,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            // 2. 尝试读取握手数据包
            if stream.conn.is_handshaking() && stream.conn.wants_read() {
                match stream.conn.read_tls(&mut sync_io) {
                    Ok(0) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "eof during handshake",
                        )))
                    }
                    Ok(_) => {
                        if let Err(e) = stream.conn.process_new_packets() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                e.to_string(),
                            )));
                        }
                        progressed = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            if !progressed {
                return Poll::Pending;
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 使用 get_mut 明确分离借用，告诉借用检查器 io 和 conn 是互不干扰的独立字段
        let this = self.get_mut();
        let mut active = true;

        while active {
            active = false;

            // 尝试读取已被 Rustls 解密好的明文数据
            let slice = buf.initialize_unfilled();
            match this.conn.reader().read(slice) {
                Ok(0) => {}
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }

            let mut sync_io = SyncIo {
                io: &mut this.io,
                cx: &mut *cx,
            };

            // 写入可能积压的握手或控制数据
            if this.conn.wants_write() {
                match this.conn.write_tls(&mut sync_io) {
                    Ok(0) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero",
                        )))
                    }
                    Ok(_) => active = true,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            // 从底层 TCP 读取密文，喂给 Rustls 解析
            if this.conn.wants_read() {
                match this.conn.read_tls(&mut sync_io) {
                    Ok(0) => {
                        if let Err(e) = this.conn.process_new_packets() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                e.to_string(),
                            )));
                        }
                        return Poll::Ready(Ok(())); // TCP EOF
                    }
                    Ok(_) => {
                        if let Err(e) = this.conn.process_new_packets() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                e.to_string(),
                            )));
                        }
                        active = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        }
        Poll::Pending
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 1. 将明文写入 Rustls 的内部加密缓冲区
        let written = match this.conn.writer().write(buf) {
            Ok(n) => n,
            Err(e) => return Poll::Ready(Err(e)),
        };

        // 2. 把加密好的数据推送到真正的底层 TCP 管道
        let mut sync_io = SyncIo {
            io: &mut this.io,
            cx: &mut *cx,
        };
        while this.conn.wants_write() {
            match this.conn.write_tls(&mut sync_io) {
                Ok(0) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        let _ = std::io::Write::flush(&mut this.conn.writer());

        let mut sync_io = SyncIo {
            io: &mut this.io,
            cx: &mut *cx,
        };

        while this.conn.wants_write() {
            match this.conn.write_tls(&mut sync_io) {
                Ok(0) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.conn.send_close_notify();

        let mut sync_io = SyncIo {
            io: &mut this.io,
            cx: &mut *cx,
        };
        while this.conn.wants_write() {
            match this.conn.write_tls(&mut sync_io) {
                Ok(0) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}
