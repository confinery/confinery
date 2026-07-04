//! `confinery doctor` — report host isolation capabilities.

use confinery_sandbox::{detect, platform_sandbox};

pub fn run() -> anyhow::Result<i32> {
    let caps = detect();
    print!("{caps}");
    println!("  backend: {}", platform_sandbox().backend());
    Ok(0)
}
