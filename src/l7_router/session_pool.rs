use crate::l6_neomux::{Session, Stream};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone)]
pub struct PoolConfig {
    pub max_streams_per_session: i32,
    pub pre_dial_threshold: i32,
    pub max_sessions: usize,
}

/// 定义拨号函数的类型别名：使用标准库的 Pin 和 Box 替代第三方 BoxFuture，零额外依赖
pub type DialFunc = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<Arc<Session>>> + Send + 'static>>
        + Send
        + Sync,
>;

struct PoolSession {
    session: Arc<Session>,
    stream_count: Arc<AtomicI32>,
    is_dead: Arc<AtomicBool>,
}

impl PoolSession {
    fn mark_dead(&self) {
        self.is_dead.store(true, Ordering::Release);
        // 注意：无需显式 Close session，当 Arc 计数归零且通道断开时，它会自动清理
    }
}

pub struct SessionPool {
    dial_func: DialFunc,
    config: PoolConfig,
    sessions: Arc<tokio::sync::RwLock<Vec<Arc<PoolSession>>>>,
    dialing: Arc<AtomicBool>,
}

impl SessionPool {
    pub fn new(dial_func: DialFunc, config: PoolConfig) -> Self {
        Self {
            dial_func,
            config,
            sessions: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            dialing: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 预热池子，建立第一个连接
    pub async fn warm_up(&self) -> io::Result<()> {
        let session = (self.dial_func)().await?;
        self.add_session(session).await;
        Ok(())
    }

    /// 从池中获取一个最优的流，包含负载均衡和自动重试
    pub async fn open_stream(&self) -> io::Result<PooledStream> {
        loop {
            if let Some(ps) = self.get_best_session().await {
                match ps.session.open_stream().await {
                    Ok(stream) => {
                        return Ok(PooledStream {
                            inner: stream,
                            stream_count: ps.stream_count.clone(),
                            closed: false,
                        });
                    }
                    Err(_) => {
                        // 该会话已损坏，标记为死亡，回滚计数，继续循环寻找下一个
                        ps.mark_dead();
                        ps.stream_count.fetch_sub(1, Ordering::Relaxed);
                        continue;
                    }
                }
            }

            // 整个池子为空，或所有会话全部满载，必须同步拨号
            let session = (self.dial_func)().await?;
            self.add_session(session).await;
        }
    }

    async fn get_best_session(&self) -> Option<Arc<PoolSession>> {
        let mut sessions_guard = self.sessions.write().await;
        let mut best: Option<Arc<PoolSession>> = None;
        let mut min_load = i32::MAX;

        // 清理并筛选
        sessions_guard.retain(|ps| !ps.is_dead.load(Ordering::Acquire));

        for ps in sessions_guard.iter() {
            let load = ps.stream_count.load(Ordering::Acquire);
            if load < self.config.max_streams_per_session {
                if best.is_none() || load < min_load {
                    best = Some(ps.clone());
                    min_load = load;
                }
            }
        }

        // 异步预拨号触发机制
        if (best.is_none() || min_load >= self.config.pre_dial_threshold)
            && sessions_guard.len() < self.config.max_sessions
        {
            self.trigger_async_dial();
        }

        if let Some(ref best_ps) = best {
            best_ps.stream_count.fetch_add(1, Ordering::Relaxed); // 提前占位
        }
        best
    }

    fn trigger_async_dial(&self) {
        if self
            .dialing
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            let dial_func = self.dial_func.clone();
            let sessions = self.sessions.clone();
            let dialing = self.dialing.clone();
            let max_sessions = self.config.max_sessions;

            tokio::spawn(async move {
                // 后台静默拨号
                if let Ok(session) = dial_func().await {
                    let mut guard = sessions.write().await;
                    if guard.len() < max_sessions {
                        guard.push(Arc::new(PoolSession {
                            session,
                            stream_count: Arc::new(AtomicI32::new(0)),
                            is_dead: Arc::new(AtomicBool::new(false)),
                        }));
                        tracing::info!(
                            "🌊 [Session Pool] 流量洪峰预警，后台成功异步扩容物理连接！"
                        );
                    }
                }
                dialing.store(false, Ordering::Release);
            });
        }
    }

    async fn add_session(&self, session: Arc<Session>) {
        let mut guard = self.sessions.write().await;
        if guard.len() < self.config.max_sessions {
            guard.push(Arc::new(PoolSession {
                session,
                stream_count: Arc::new(AtomicI32::new(0)),
                is_dead: Arc::new(AtomicBool::new(false)),
            }));
        }
    }
}

/// 包装 L6 Stream，实现在 Drop 时自动归还池内的并发负载计数
pub struct PooledStream {
    inner: Stream,
    stream_count: Arc<AtomicI32>,
    closed: bool,
}

impl AsyncRead for PooledStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PooledStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for PooledStream {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            self.stream_count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
