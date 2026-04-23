// 声明我们要使用的子模块（如果你还没建对应的文件夹，可以先用 // 注释掉）
// pub mod l4_security;
// pub mod l5_shaper;
pub mod l6_neomux;
// pub mod l7_router;

#[tokio::main] // 启动 Tokio 异步运行时
async fn main() {
    println!("🚀 NeoProxy-RS (Rust 重写版) 正在启动...");

    // 我们一会儿会在这里调用配置解析和核心逻辑
}
