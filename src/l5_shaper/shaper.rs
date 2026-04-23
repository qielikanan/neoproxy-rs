use super::ast::ConnContext;
use super::scheme::{ActionType, Scheme, SchemeIterator};
use bytes::{Buf, BufMut, BytesMut};
use std::io;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

static WASTE_POOL: OnceLock<Vec<u8>> = OnceLock::new();

fn get_waste_pool() -> &'static [u8] {
    WASTE_POOL.get_or_init(|| {
        let mut pool = vec![0u8; 65535];
        for i in 0..pool.len() {
            pool[i] = (i % 256) as u8;
        }
        pool
    })
}

pub struct ShaperStream<T> {
    inner: T,
    iter: Option<SchemeIterator>,
    ctx: ConnContext,
    write_buf: BytesMut,
}

impl<T> ShaperStream<T> {
    pub fn new(inner: T, scheme: Option<Scheme>) -> Self {
        Self {
            inner,
            iter: scheme.map(SchemeIterator::new),
            ctx: ConnContext::new(),
            write_buf: BytesMut::new(),
        }
    }

    fn write_waste(&mut self, mut target_len: usize) {
        if target_len < 8 {
            target_len = 8;
        }
        let payload_len = target_len - 8;

        self.write_buf.put_u8(0x14);
        self.write_buf.put_u8(0x00);
        self.write_buf.put_u16(payload_len as u16);
        self.write_buf.put_u32(0);
        self.write_buf.put_slice(&get_waste_pool()[..payload_len]);
    }

    // 修复了未使用 mut 的警告
    fn write_fixed(&mut self, data: &[u8], target_len: usize) {
        let padding = target_len.saturating_sub(data.len());
        if padding == 0 {
            self.write_buf.put_slice(data);
            return;
        }

        let padding = if padding < 8 { 8 } else { padding };
        let payload_len = padding - 8;

        self.write_buf.put_slice(data);
        self.write_buf.put_u8(0x14);
        self.write_buf.put_u8(0x00);
        self.write_buf.put_u16(payload_len as u16);
        self.write_buf.put_u32(0);
        self.write_buf.put_slice(&get_waste_pool()[..payload_len]);
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ShaperStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut(); // 解除 Pin 限制，允许字段分离借用
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ShaperStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut(); // 获取普通的可变引用，避免借用冲突

        if this.iter.is_none() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        if !this.write_buf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.write_buf))?;
            this.write_buf.advance(n);
            if !this.write_buf.is_empty() {
                return Poll::Pending;
            }
        }

        let mut consumed_from_buf = 0;

        while consumed_from_buf < buf.len() {
            let (action, target_len) = this.iter.as_mut().unwrap().next_action(&mut this.ctx);

            match action {
                ActionType::Inject => {
                    this.write_waste(target_len);
                }
                ActionType::SendData => {
                    let available = buf.len() - consumed_from_buf;
                    let consume = std::cmp::min(available, target_len);
                    this.write_fixed(
                        &buf[consumed_from_buf..consumed_from_buf + consume],
                        target_len,
                    );
                    consumed_from_buf += consume;
                    break;
                }
                ActionType::Done => {
                    this.iter = None;
                    if consumed_from_buf == 0 {
                        return Pin::new(&mut this.inner).poll_write(cx, buf);
                    }
                    break;
                }
            }
        }

        if !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    if consumed_from_buf > 0 {
                        return Poll::Ready(Ok(consumed_from_buf));
                    }
                    return Poll::Pending;
                }
            }
        }

        if consumed_from_buf > 0 {
            Poll::Ready(Ok(consumed_from_buf))
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        if !this.write_buf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.write_buf))?;
            this.write_buf.advance(n);
            if !this.write_buf.is_empty() {
                return Poll::Pending;
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
