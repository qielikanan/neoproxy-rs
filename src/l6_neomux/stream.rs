use super::frame::Frame;
use super::frame::{
    CMD_CTRL, CMD_DATA, CMD_WINDOW_UPDATE, FLAG_FIN, FLAG_RST, INITIAL_WINDOW_SIZE,
};
use super::session::SessionState;
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

pub(crate) struct StreamState {
    pub rx_queue: VecDeque<Bytes>,
    pub rx_offset: usize,

    // 高性能改进：有界本地写出缓冲，配合 Session 的 Pull 拉模式避免 OOM
    pub tx_queue: VecDeque<Frame>,

    pub rx_waker: Option<Waker>,
    pub tx_waker: Option<Waker>,

    pub send_window: i32,
    pub recv_window: i32,
    pub unacked_bytes: i32,

    pub read_closed: bool,
    pub write_closed: bool,
    pub reset: bool,
}

pub(crate) struct StreamInternal {
    pub id: u32,
    pub prio_tx: mpsc::UnboundedSender<Frame>,
    pub session_state: Arc<SessionState>,
    pub state: Mutex<StreamState>,
}

impl StreamInternal {
    pub fn new(
        id: u32,
        prio_tx: mpsc::UnboundedSender<Frame>,
        session_state: Arc<SessionState>,
    ) -> Self {
        Self {
            id,
            prio_tx,
            session_state,
            state: Mutex::new(StreamState {
                rx_queue: VecDeque::new(),
                rx_offset: 0,
                tx_queue: VecDeque::with_capacity(64),
                rx_waker: None,
                tx_waker: None,
                send_window: INITIAL_WINDOW_SIZE,
                recv_window: INITIAL_WINDOW_SIZE,
                unacked_bytes: 0,
                read_closed: false,
                write_closed: false,
                reset: false,
            }),
        }
    }

    pub fn wake_rx(&self, state: &mut StreamState) {
        if let Some(waker) = state.rx_waker.take() {
            waker.wake();
        }
    }

    pub fn handle_rst(&self) {
        let mut state = self.state.lock().unwrap();
        state.reset = true;
        self.wake_rx(&mut state);
        if let Some(waker) = state.tx_waker.take() {
            waker.wake();
        }
    }

    pub fn handle_fin(&self) {
        let mut state = self.state.lock().unwrap();
        state.read_closed = true;
        self.wake_rx(&mut state);
    }

    pub fn push_data(&self, data: Bytes) {
        let mut state = self.state.lock().unwrap();
        if state.reset || state.read_closed {
            return;
        }

        state.recv_window -= data.len() as i32;
        if state.rx_queue.len() > 8192 || state.recv_window < 0 {
            state.reset = true;
            let _ = self.prio_tx.send(Frame {
                cmd: CMD_CTRL,
                flags: FLAG_RST,
                length: 0,
                stream_id: self.id,
                payload: None,
            });
            self.session_state.remove_stream(self.id);
            self.wake_rx(&mut state);
            return;
        }

        state.rx_queue.push_back(data);
        self.wake_rx(&mut state);
    }

    pub fn add_send_window(&self, delta: i32) {
        let mut state = self.state.lock().unwrap();
        state.send_window += delta;
        if let Some(waker) = state.tx_waker.take() {
            waker.wake();
        }
    }

    pub fn send_window_update(&self, delta: u32) {
        let mut p = BytesMut::with_capacity(4);
        p.put_u32(delta);
        let _ = self.prio_tx.send(Frame {
            cmd: CMD_WINDOW_UPDATE,
            flags: 0,
            length: 4,
            stream_id: self.id,
            payload: Some(p.freeze()),
        });

        let mut gp = BytesMut::with_capacity(4);
        gp.put_u32(delta);
        let _ = self.prio_tx.send(Frame {
            cmd: CMD_WINDOW_UPDATE,
            flags: 0,
            length: 4,
            stream_id: 0,
            payload: Some(gp.freeze()),
        });
    }
}

pub struct Stream {
    pub(crate) internal: Arc<StreamInternal>,
}

impl AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.internal.state.lock().unwrap();

        if state.reset {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "stream reset",
            )));
        }

        let front_opt = state.rx_queue.front().cloned();

        if let Some(front) = front_opt {
            let available = front.len() - state.rx_offset;
            let to_read = std::cmp::min(available, buf.remaining());

            buf.put_slice(&front[state.rx_offset..state.rx_offset + to_read]);
            state.rx_offset += to_read;

            if state.rx_offset == front.len() {
                state.rx_queue.pop_front();
                state.rx_offset = 0;
            }

            state.recv_window += to_read as i32;
            state.unacked_bytes += to_read as i32;

            let mut delta_update = 0;
            if state.unacked_bytes >= INITIAL_WINDOW_SIZE / 2 {
                delta_update = state.unacked_bytes;
                state.unacked_bytes = 0;
            }

            drop(state); // 释放锁再发送窗口更新

            if delta_update > 0 {
                self.internal.send_window_update(delta_update as u32);
            }

            return Poll::Ready(Ok(()));
        }

        if state.read_closed {
            return Poll::Ready(Ok(()));
        }

        state.rx_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut state = self.internal.state.lock().unwrap();

        if state.reset {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "stream reset",
            )));
        }
        if state.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        // 严格的内存控制：如果缓冲区积压帧过多，强行阻塞该流写入，杜绝 OOM
        if state.tx_queue.len() >= 64 {
            state.tx_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let global_win = self
            .internal
            .session_state
            .global_send_window
            .load(Ordering::Acquire);

        if state.send_window <= 0 || global_win <= 0 {
            if global_win <= 0 {
                // 注册到精准唤醒队列，而非全部唤醒
                self.internal
                    .session_state
                    .global_tx_wakers
                    .lock()
                    .unwrap()
                    .push(cx.waker().clone());
            }
            state.tx_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let mut can_send = std::cmp::min(state.send_window, global_win) as usize;
        can_send = std::cmp::min(can_send, 65535);
        can_send = std::cmp::min(can_send, buf.len());

        state.send_window -= can_send as i32;
        self.internal
            .session_state
            .global_send_window
            .fetch_sub(can_send as i32, Ordering::Release);

        let payload = Bytes::copy_from_slice(&buf[..can_send]);

        // 推入本地队列，并使用轻量级 Notify 告知 Session 来提取
        state.tx_queue.push_back(Frame {
            cmd: CMD_DATA,
            flags: 0,
            length: can_send as u16,
            stream_id: self.internal.id,
            payload: Some(payload),
        });

        // 仅在释放内部锁后执行外部同步结构以防止潜在死锁
        drop(state);

        self.internal
            .session_state
            .ready_streams
            .lock()
            .unwrap()
            .push_back(self.internal.id);
        self.internal.session_state.write_notify.notify_one();

        Poll::Ready(Ok(can_send))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let mut state = self.internal.state.lock().unwrap();
        if !state.write_closed && !state.reset {
            state.write_closed = true;
            let _ = self.internal.prio_tx.send(Frame {
                cmd: CMD_CTRL,
                flags: FLAG_FIN,
                length: 0,
                stream_id: self.internal.id,
                payload: None,
            });
            self.internal.session_state.remove_stream(self.internal.id);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let mut state = self.internal.state.lock().unwrap();
        if !state.write_closed && !state.reset {
            state.reset = true;
            let _ = self.internal.prio_tx.send(Frame {
                cmd: CMD_CTRL,
                flags: FLAG_RST,
                length: 0,
                stream_id: self.internal.id,
                payload: None,
            });
            self.internal.session_state.remove_stream(self.internal.id);
        }
    }
}
