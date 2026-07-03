//! Fuzzes the hand-rolled `ByteSize`/`HumanDuration` parsers, which take
//! attacker-influenced strings (profile fields) through custom
//! character-by-character parsing logic rather than an existing crate.

#![no_main]

use confinery_core::units::{ByteSize, HumanDuration};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let _ = ByteSize::parse(data);
    let _ = HumanDuration::parse(data);
});
