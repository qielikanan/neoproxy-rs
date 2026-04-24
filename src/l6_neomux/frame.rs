use bytes::{BufMut, Bytes, BytesMut};
use std::io;

pub const HEADER_SIZE: usize = 8;
pub const VERSION: u8 = 0x1;

// 命令码 (Cmd)
pub const CMD_DATA: u8 = 0x0;
pub const CMD_WINDOW_UPDATE: u8 = 0x1;
pub const CMD_PING: u8 = 0x2;
pub const CMD_GOAWAY: u8 = 0x3;
pub const CMD_WASTE: u8 = 0x4;
pub const CMD_CTRL: u8 = 0x5;

// 标志位 (Flags)
pub const FLAG_SYN: u8 = 0x01;
pub const FLAG_ACK: u8 = 0x02;
pub const FLAG_FIN: u8 = 0x04;
pub const FLAG_RST: u8 = 0x08;

pub const INITIAL_WINDOW_SIZE: i32 = 512 * 1024; // 512KB 窗口

#[derive(Debug, Clone)]
pub struct Frame {
    pub cmd: u8,
    pub flags: u8,
    pub length: u16,
    pub stream_id: u32,
    pub payload: Option<Bytes>, // 零拷贝载荷
}

impl Frame {
    /// 极速编码帧头，不发生内存分配，直接写入传入的 buffer
    pub fn encode_header(&self, buf: &mut BytesMut) {
        let ver_cmd = (VERSION << 4) | (self.cmd & 0x0F);
        buf.put_u8(ver_cmd);
        buf.put_u8(self.flags);
        buf.put_u16(self.length);
        buf.put_u32(self.stream_id);
    }

    pub fn encode_header_to_slice(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= HEADER_SIZE);
        let ver_cmd = (VERSION << 4) | (self.cmd & 0x0F);
        buf[0] = ver_cmd;
        buf[1] = self.flags;
        buf[2..4].copy_from_slice(&self.length.to_be_bytes());
        buf[4..8].copy_from_slice(&self.stream_id.to_be_bytes());
    }

    /// 解析 8 字节二进制头
    pub fn decode_header(header: &[u8]) -> io::Result<(u8, u8, u16, u32)> {
        if header.len() < HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "header too short",
            ));
        }
        let ver = header[0] >> 4;
        if ver != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid neomux version",
            ));
        }
        let cmd = header[0] & 0x0F;
        let flags = header[1];
        let length = u16::from_be_bytes([header[2], header[3]]);
        let stream_id = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

        Ok((cmd, flags, length, stream_id))
    }
}
