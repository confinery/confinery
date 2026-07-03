//! Fuzzes `Profile::from_toml_str` against arbitrary bytes.
//!
//! This parses operator- (and potentially agent-) supplied profile files
//! before any sandbox is set up; a panic here is a denial-of-service
//! against the launcher itself, not just a bad profile. The only
//! acceptable outcomes are `Ok` or a clean `Err` -- never a panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = confinery_core::Profile::from_toml_str(data);
});
