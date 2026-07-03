//! Fuzzes `Profile::from_json_str` against arbitrary bytes. See
//! `profile_toml.rs` for why this matters: only `Ok`/clean `Err`, no panics.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = confinery_core::Profile::from_json_str(data);
});
