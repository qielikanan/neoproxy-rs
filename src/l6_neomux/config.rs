use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub is_client: bool,
    pub require_auth: bool, // TLS 模式下应为 true，启用首包鉴权
    pub password: String,
    pub fallback_target: String, // 鉴权失败时的回落目标 (如 127.0.0.1:80)
    pub keep_alive_interval: Duration,
    pub keep_alive_timeout: Duration,
    pub max_stream_count: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            is_client: true,
            require_auth: false,
            password: String::new(),
            fallback_target: String::new(),
            keep_alive_interval: Duration::from_secs(15),
            keep_alive_timeout: Duration::from_secs(30),
            max_stream_count: 256,
        }
    }
}
