use super::config::Config;
use super::frame::{
    Frame, CMD_CTRL, CMD_DATA, CMD_PING, CMD_WASTE, CMD_WINDOW_UPDATE, FLAG_ACK, FLAG_FIN,
    FLAG_RST, FLAG_SYN, HEADER_SIZE,
};
use super::stream::{Stream, StreamInternal};
use bytes::BytesMut;
use clashmap::ClashMap;
use sha2::{Digest, Sha256};
use std::io::{self};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex as AsyncMutex};

pub(crate) struct SessionState {
    pub streams: ClashMap<u32, Arc<StreamInternal>>,
    pub global_send_window: AtomicI32,
    pub stream_count: AtomicU32,
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            streams: ClashMap::new(),
            global_send_window: AtomicI32::new(10 * 1024 * 1024), // 10MB
            stream_count: AtomicU32::new(0),
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
        // clashmap 的 get 返回一个 Ref，我们需要 clone 出内部的 Arc
        self.streams
            .get(&stream_id)
            .map(|ref_kv| ref_kv.value().clone())
    }

    pub fn wake_all_tx(&self) {
        let streams_to_wake: Vec<Arc<StreamInternal>> = self
            .streams
            .iter()
            .map(|ref_kv| ref_kv.value().clone())
            .collect();

        for s in streams_to_wake {
            s.wake_tx();
        }
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
    data_tx: mpsc::UnboundedSender<Frame>,
    accept_rx: AsyncMutex<mpsc::Receiver<Stream>>,
}

impl Session {
    pub async fn new<T>(conn: T, config: Config) -> io::Result<Arc<Self>>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (prio_tx, prio_rx) = mpsc::unbounded_channel();
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::channel(128);

        // 跨协程传递 Fallback 通道的利器
        let (fallback_tx, fallback_rx) = mpsc::channel::<tokio::net::tcp::OwnedReadHalf>(1);

        let state = Arc::new(SessionState::new());

        let next_stream_id = if config.is_client { 1 } else { 2 };

        let session = Arc::new(Self {
            state: state.clone(),
            next_stream_id: AtomicU32::new(next_stream_id),
            prio_tx: prio_tx.clone(),
            data_tx: data_tx.clone(),
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

        let write_prio_rx = prio_rx;
        let write_data_rx = data_rx;
        tokio::spawn(async move {
            Self::write_loop(&mut wh, write_prio_rx, write_data_rx, fallback_rx).await;
        });

        let read_state = state.clone();
        let read_prio_tx = prio_tx.clone();
        let read_data_tx = data_tx.clone();
        tokio::spawn(async move {
            Self::read_loop(
                &mut rh,
                read_state,
                read_prio_tx,
                read_data_tx,
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
            self.data_tx.clone(),
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

    async fn write_loop<W>(
        writer: &mut W,
        mut prio_rx: mpsc::UnboundedReceiver<Frame>,
        mut data_rx: mpsc::UnboundedReceiver<Frame>,
        mut fallback_rx: mpsc::Receiver<tokio::net::tcp::OwnedReadHalf>,
    ) where
        W: AsyncWrite + Unpin,
    {
        let mut fallback_active = true;

        loop {
            let frame = tokio::select! {
                biased;
                opt_rh = fallback_rx.recv(), if fallback_active => {
                    if let Some(mut target_rh) = opt_rh {
                        let mut buf = [0u8; 8192];
                        loop {
                            match tokio::io::AsyncReadExt::read(&mut target_rh, &mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    if tokio::io::AsyncWriteExt::write_all(writer, &buf[..n]).await.is_err() {
                                        break;
                                    }
                                    if tokio::io::AsyncWriteExt::flush(writer).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        let _ = tokio::io::AsyncWriteExt::shutdown(writer).await;
                        return;
                    } else {
                        fallback_active = false;
                        continue;
                    }
                }
                Some(f) = prio_rx.recv() => f,
                Some(f) = data_rx.recv() => f,
                else => break,
            };

            let mut batched = 0;
            let mut current_frame = Some(frame);

            while let Some(f) = current_frame {
                let mut header_buf = BytesMut::with_capacity(HEADER_SIZE);
                f.encode_header(&mut header_buf);
                let header_bytes = header_buf.freeze();

                if let Some(payload) = f.payload {
                    let mut combined = BytesMut::with_capacity(header_bytes.len() + payload.len());
                    combined.extend_from_slice(&header_bytes);
                    combined.extend_from_slice(&payload);

                    if writer.write_all(&combined).await.is_err() {
                        return;
                    }
                } else {
                    if writer.write_all(&header_bytes).await.is_err() {
                        return;
                    }
                }

                batched += 1;
                if batched >= 64 {
                    break;
                }

                current_frame = match prio_rx.try_recv() {
                    Ok(f) => Some(f),
                    Err(_) => match data_rx.try_recv() {
                        Ok(f) => Some(f),
                        Err(_) => None,
                    },
                };
            }

            if writer.flush().await.is_err() {
                break;
            }
        }
    }

    async fn read_loop<R>(
        reader: &mut R,
        state: Arc<SessionState>,
        prio_tx: mpsc::UnboundedSender<Frame>,
        data_tx: mpsc::UnboundedSender<Frame>,
        accept_tx: mpsc::Sender<Stream>,
        config: Config,
        mut fallback_tx: Option<mpsc::Sender<tokio::net::tcp::OwnedReadHalf>>,
    ) where
        R: AsyncRead + Unpin,
    {
        let mut header_buf = [0u8; HEADER_SIZE];
        let mut auth_passed = !config.require_auth || config.is_client;

        loop {
            if reader.read_exact(&mut header_buf).await.is_err() {
                break;
            }

            let (cmd, flags, length, stream_id) = match Frame::decode_header(&header_buf) {
                Ok(h) => h,
                Err(_) => {
                    if let Some(tx) = fallback_tx.take() {
                        if !config.is_client && !config.fallback_target.is_empty() {
                            if let Ok(target_stream) =
                                tokio::net::TcpStream::connect(&config.fallback_target).await
                            {
                                let (target_rh, mut target_wh) = target_stream.into_split();
                                let _ = tx.try_send(target_rh);
                                let _ = target_wh.write_all(&header_buf).await;
                                let _ = tokio::io::copy(reader, &mut target_wh).await;
                                let _ = target_wh.shutdown().await;
                            }
                        }
                    }
                    break;
                }
            };

            let payload = if length > 0 {
                let mut p_buf = BytesMut::zeroed(length as usize);
                if reader.read_exact(&mut p_buf).await.is_err() {
                    break;
                }
                Some(p_buf.freeze())
            } else {
                None
            };

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
                            tracing::warn!("⚠️ [Security] 收到畸形首包，长度不足以进行哈希校验。");
                        }
                    }
                }

                if matched {
                    auth_passed = true;
                    continue;
                } else {
                    if let Some(tx) = fallback_tx.take() {
                        if !config.is_client && !config.fallback_target.is_empty() {
                            if let Ok(target_stream) =
                                tokio::net::TcpStream::connect(&config.fallback_target).await
                            {
                                let (target_rh, mut target_wh) = target_stream.into_split();
                                let _ = tx.try_send(target_rh);
                                let _ = target_wh.write_all(&header_buf).await;
                                if let Some(ref p) = payload {
                                    let _ = target_wh.write_all(p).await;
                                }
                                let _ = tokio::io::copy(reader, &mut target_wh).await;
                                let _ = target_wh.shutdown().await;
                            }
                        }
                    }
                    break;
                }
            }

            if cmd == CMD_WASTE {
                continue;
            }

            if stream_id == 0 {
                if cmd == CMD_WINDOW_UPDATE {
                    if let Some(p) = payload {
                        if p.len() >= 4 {
                            let delta = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as i32;
                            state.global_send_window.fetch_add(delta, Ordering::Relaxed);
                            // 优雅地无锁批量唤醒
                            state.wake_all_tx();
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

            let is_syn = (flags & FLAG_SYN) != 0;

            let stream_opt = {
                if is_syn {
                    if state.stream_count.load(Ordering::Relaxed) < config.max_stream_count {
                        let internal = Arc::new(StreamInternal::new(
                            stream_id,
                            prio_tx.clone(),
                            data_tx.clone(),
                            state.clone(),
                        ));
                        state.insert_stream(stream_id, internal.clone());

                        let stream = Stream {
                            internal: internal.clone(),
                        };
                        let _ = accept_tx.try_send(stream);
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
        }

        state.reset_all_streams();
    }
}
