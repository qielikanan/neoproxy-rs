use super::config::Config;
use super::frame::{
    Frame, CMD_CTRL, CMD_DATA, CMD_PING, CMD_WASTE, CMD_WINDOW_UPDATE, FLAG_ACK, FLAG_FIN,
    FLAG_RST, FLAG_SYN, HEADER_SIZE,
};
use super::stream::{Stream, StreamInternal};
use bytes::BytesMut;
use clashmap::ClashMap;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io::{self};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::Waker;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex as AsyncMutex, Notify};

pub(crate) struct SessionState {
    pub streams: ClashMap<u32, Arc<StreamInternal>>,
    pub global_send_window: AtomicI32,
    pub stream_count: AtomicU32,

    // 高性能优化：精准唤醒队列，解决惊群效应
    pub global_tx_wakers: StdMutex<Vec<Waker>>,
    // 高性能优化：写就绪通知与队列 (拉模式)
    pub write_notify: Arc<Notify>,
    pub ready_streams: StdMutex<VecDeque<u32>>,
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            streams: ClashMap::new(),
            global_send_window: AtomicI32::new(10 * 1024 * 1024), // 10MB
            stream_count: AtomicU32::new(0),
            global_tx_wakers: StdMutex::new(Vec::new()),
            write_notify: Arc::new(Notify::new()),
            ready_streams: StdMutex::new(VecDeque::new()),
        }
    }

    pub fn insert_stream(&self, stream_id: u32, stream: Arc<StreamInternal>) {
        self.streams.insert(stream_id, stream);
        self.stream_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn remove_stream(&self, stream_id: u32) {
        if self.streams.remove(&stream_id).is_some() {
            self.stream_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn get_stream(&self, stream_id: u32) -> Option<Arc<StreamInternal>> {
        self.streams
            .get(&stream_id)
            .map(|ref_kv| ref_kv.value().clone())
    }

    pub fn reset_all_streams(&self) {
        let streams_to_reset: Vec<Arc<StreamInternal>> = self
            .streams
            .iter()
            .map(|ref_kv| ref_kv.value().clone())
            .collect();

        self.streams.clear();
        self.stream_count.store(0, Ordering::Release);

        for s in streams_to_reset {
            s.handle_rst();
        }
    }
}

pub struct Session {
    state: Arc<SessionState>,
    next_stream_id: AtomicU32,
    prio_tx: mpsc::UnboundedSender<Frame>,
    accept_rx: AsyncMutex<mpsc::Receiver<Stream>>,
}

impl Session {
    pub async fn new<T>(conn: T, config: Config) -> io::Result<Arc<Self>>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // 优先队列仅用于极少量、关键的控制帧 (RST, WINDOW_UPDATE)
        let (prio_tx, prio_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::channel(128);
        let (fallback_tx, fallback_rx) = mpsc::channel::<tokio::net::tcp::OwnedReadHalf>(1);

        let state = Arc::new(SessionState::new());
        let next_stream_id = if config.is_client { 1 } else { 2 };

        let session = Arc::new(Self {
            state: state.clone(),
            next_stream_id: AtomicU32::new(next_stream_id),
            prio_tx: prio_tx.clone(),
            accept_rx: AsyncMutex::new(accept_rx),
        });

        if config.is_client && config.require_auth {
            let mut hasher = Sha256::new();
            hasher.update(config.password.as_bytes());
            let hash = hasher.finalize();

            let mut payload = BytesMut::with_capacity(32);
            payload.extend_from_slice(&hash);

            let _ = prio_tx.send(Frame {
                cmd: CMD_CTRL,
                flags: FLAG_SYN,
                length: payload.len() as u16,
                stream_id: 0,
                payload: Some(payload.freeze()),
            });
        }

        let (mut rh, mut wh) = tokio::io::split(conn);

        let write_state = state.clone();
        tokio::spawn(async move {
            Self::write_loop(&mut wh, write_state, prio_rx, fallback_rx).await;
        });

        let read_state = state.clone();
        let read_prio_tx = prio_tx.clone();
        tokio::spawn(async move {
            Self::read_loop(
                &mut rh,
                read_state,
                read_prio_tx,
                accept_tx,
                config,
                Some(fallback_tx),
            )
            .await;
        });

        Ok(session)
    }

    pub async fn accept_stream(&self) -> io::Result<Stream> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "session closed"))
    }

    pub async fn open_stream(&self) -> io::Result<Stream> {
        let stream_id = self.next_stream_id.fetch_add(2, Ordering::Relaxed);

        let internal = Arc::new(StreamInternal::new(
            stream_id,
            self.prio_tx.clone(),
            self.state.clone(),
        ));

        self.state.insert_stream(stream_id, internal.clone());

        let _ = self.prio_tx.send(Frame {
            cmd: CMD_CTRL,
            flags: FLAG_SYN,
            length: 0,
            stream_id,
            payload: None,
        });

        Ok(Stream { internal })
    }

    /// 高效的事件驱动写循环
    async fn write_loop<W>(
        writer: &mut W,
        state: Arc<SessionState>,
        mut prio_rx: mpsc::UnboundedReceiver<Frame>,
        mut fallback_rx: mpsc::Receiver<tokio::net::tcp::OwnedReadHalf>,
    ) where
        W: AsyncWrite + Unpin,
    {
        let mut fallback_active = true;
        // 使用一个大的统一缓冲区合并系统调用
        let mut write_buf = BytesMut::with_capacity(65536 * 2);

        loop {
            tokio::select! {
                biased;
                opt_rh = fallback_rx.recv(), if fallback_active => {
                    if let Some(mut target_rh) = opt_rh {
                        let mut buf = [0u8; 8192];
                        loop {
                            match tokio::io::AsyncReadExt::read(&mut target_rh, &mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if writer.write_all(&buf[..n]).await.is_err() { break; }
                                }
                            }
                        }
                        let _ = writer.shutdown().await;
                        return;
                    } else {
                        fallback_active = false;
                        continue;
                    }
                }

                // 处理高优先级控制帧
                Some(f) = prio_rx.recv() => {
                    let mut header = [0u8; HEADER_SIZE];
                    f.encode_header_to_slice(&mut header);
                    write_buf.extend_from_slice(&header);
                    if let Some(p) = f.payload {
                        write_buf.extend_from_slice(&p);
                    }
                }

                // 处理大批量数据流就绪事件 (拉模式)
                _ = state.write_notify.notified() => {
                    let mut frames = Vec::new();
                    {
                        let mut ready = state.ready_streams.lock().unwrap();
                        while let Some(id) = ready.pop_front() {
                            if let Some(stream) = state.get_stream(id) {
                                let mut tx_state = stream.state.lock().unwrap();
                                frames.extend(tx_state.tx_queue.drain(..));
                                // 缓冲区腾出空间，唤醒等待写入的流
                                if let Some(w) = tx_state.tx_waker.take() {
                                    w.wake();
                                }
                            }
                        }
                    }

                    for f in frames {
                        let mut header = [0u8; HEADER_SIZE];
                        f.encode_header_to_slice(&mut header);
                        write_buf.extend_from_slice(&header);
                        if let Some(p) = f.payload {
                            write_buf.extend_from_slice(&p);
                        }
                        // 防止缓冲区暴涨，分批写出
                        if write_buf.len() >= 65536 {
                            if writer.write_all(&write_buf).await.is_err() { return; }
                            write_buf.clear();
                        }
                    }
                }
                else => break,
            }

            // 清理并刷入内核
            if !write_buf.is_empty() {
                if writer.write_all(&write_buf).await.is_err() {
                    break;
                }
                write_buf.clear();
            }
        }
    }

    async fn read_loop<R>(
        reader: &mut R,
        state: Arc<SessionState>,
        prio_tx: mpsc::UnboundedSender<Frame>,
        accept_tx: mpsc::Sender<Stream>,
        config: Config,
        mut fallback_tx: Option<mpsc::Sender<tokio::net::tcp::OwnedReadHalf>>,
    ) where
        R: AsyncRead + Unpin,
    {
        let mut read_buf = BytesMut::with_capacity(65536 * 2);
        let mut auth_passed = !config.require_auth || config.is_client;

        loop {
            while read_buf.len() >= HEADER_SIZE {
                let (cmd, flags, length, stream_id) =
                    match Frame::decode_header(&read_buf[..HEADER_SIZE]) {
                        Ok(h) => h,
                        Err(_) => {
                            // 协议解析失败，触发 Fallback 机制
                            if let Some(tx) = fallback_tx.take() {
                                if !config.is_client && !config.fallback_target.is_empty() {
                                    if let Ok(target_stream) =
                                        tokio::net::TcpStream::connect(&config.fallback_target)
                                            .await
                                    {
                                        let (target_rh, mut target_wh) = target_stream.into_split();
                                        let _ = tx.try_send(target_rh);
                                        let _ = target_wh.write_all(&read_buf).await; // 转移残留数据
                                        let _ = tokio::io::copy(reader, &mut target_wh).await;
                                        let _ = target_wh.shutdown().await;
                                    }
                                }
                            }
                            return;
                        }
                    };

                let total_len = HEADER_SIZE + length as usize;
                if read_buf.len() < total_len {
                    break;
                }

                let frame_data = read_buf.split_to(total_len);
                let payload = if length > 0 {
                    Some(frame_data.freeze().slice(HEADER_SIZE..))
                } else {
                    None
                };

                // ---- 鉴权处理逻辑 ----
                if !auth_passed {
                    if cmd == CMD_WASTE {
                        continue;
                    }
                    let mut matched = false;
                    if stream_id == 0 && cmd == CMD_CTRL && (flags & FLAG_SYN != 0) {
                        if let Some(ref p) = payload {
                            if p.len() >= 32 {
                                let mut hasher = Sha256::new();
                                hasher.update(config.password.as_bytes());
                                let expected_hash = hasher.finalize();
                                let is_match: subtle::Choice = p[..32].ct_eq(&expected_hash[..32]);
                                if is_match.unwrap_u8() == 1 {
                                    matched = true;
                                    tracing::info!(
                                        "🔒 [Security] 首包哈希鉴权成功，建立 NeoMux 会话。"
                                    );
                                } else {
                                    tracing::warn!(
                                        "⚠️ [Security] 收到非法连接，哈希鉴权失败，触发伪装回落机制。"
                                    );
                                }
                            } else {
                                tracing::warn!(
                                    "⚠️ [Security] 收到畸形首包，长度不足以进行哈希校验。"
                                );
                            }
                        }
                    }

                    if matched {
                        auth_passed = true;
                        continue;
                    } else {
                        // 回落逻辑
                        if let Some(tx) = fallback_tx.take() {
                            if !config.is_client && !config.fallback_target.is_empty() {
                                if let Ok(target_stream) =
                                    tokio::net::TcpStream::connect(&config.fallback_target).await
                                {
                                    let (target_rh, mut target_wh) = target_stream.into_split();
                                    let _ = tx.try_send(target_rh);
                                    let mut h_buf = [0u8; HEADER_SIZE];
                                    let f = Frame {
                                        cmd,
                                        flags,
                                        length,
                                        stream_id,
                                        payload: None,
                                    };
                                    f.encode_header_to_slice(&mut h_buf);
                                    let _ = target_wh.write_all(&h_buf).await;
                                    if let Some(ref p) = payload {
                                        let _ = target_wh.write_all(p).await;
                                    }
                                    let _ = target_wh.write_all(&read_buf).await;
                                    let _ = tokio::io::copy(reader, &mut target_wh).await;
                                }
                            }
                        }
                        return;
                    }
                }

                if cmd == CMD_WASTE {
                    continue;
                }

                // ---- 全局控制帧 ----
                if stream_id == 0 {
                    if cmd == CMD_WINDOW_UPDATE {
                        if let Some(p) = payload {
                            if p.len() >= 4 {
                                let delta = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as i32;
                                state.global_send_window.fetch_add(delta, Ordering::Relaxed);
                                let mut wakers = state.global_tx_wakers.lock().unwrap();
                                for w in wakers.drain(..) {
                                    w.wake();
                                }
                            }
                        }
                    } else if cmd == CMD_PING && (flags & FLAG_ACK == 0) {
                        let _ = prio_tx.send(Frame {
                            cmd: CMD_PING,
                            flags: FLAG_ACK,
                            length: 0,
                            stream_id: 0,
                            payload: None,
                        });
                    }
                    continue;
                }

                // ---- 数据与流分发 ----
                let is_syn = (flags & FLAG_SYN) != 0;
                let stream_opt = {
                    if is_syn {
                        if state.stream_count.load(Ordering::Relaxed) < config.max_stream_count {
                            let internal = Arc::new(StreamInternal::new(
                                stream_id,
                                prio_tx.clone(),
                                state.clone(),
                            ));
                            state.insert_stream(stream_id, internal.clone());
                            let _ = accept_tx.try_send(Stream {
                                internal: internal.clone(),
                            });
                            let _ = prio_tx.send(Frame {
                                cmd: CMD_CTRL,
                                flags: FLAG_ACK,
                                length: 0,
                                stream_id,
                                payload: None,
                            });
                            Some(internal)
                        } else {
                            let _ = prio_tx.send(Frame {
                                cmd: CMD_CTRL,
                                flags: FLAG_RST,
                                length: 0,
                                stream_id,
                                payload: None,
                            });
                            None
                        }
                    } else {
                        state.get_stream(stream_id)
                    }
                };

                if let Some(internal) = stream_opt {
                    if flags & FLAG_RST != 0 {
                        internal.handle_rst();
                        state.remove_stream(stream_id);
                        continue;
                    }
                    if flags & FLAG_FIN != 0 {
                        internal.handle_fin();
                    }

                    if cmd == CMD_DATA {
                        if let Some(p) = payload {
                            internal.push_data(p);
                        }
                    } else if cmd == CMD_WINDOW_UPDATE {
                        if let Some(p) = payload {
                            if p.len() >= 4 {
                                let delta = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as i32;
                                internal.add_send_window(delta);
                            }
                        }
                    }
                }
            } // end while

            if reader.read_buf(&mut read_buf).await.unwrap_or(0) == 0 {
                break; // Socket 关闭
            }
        }

        state.reset_all_streams();
    }
}
