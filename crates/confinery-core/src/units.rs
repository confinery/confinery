//! Human-friendly size and duration values used in profiles.
//!
//! Sizes accept `1024`, `64KiB`, `2GiB`, `512MB`; durations accept `30s`,
//! `10m`, `1h30m`. Both round-trip to a canonical string form so that
//! `confinery profile show` output stays stable and reproducible.

use std::fmt;
use std::time::Duration;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};

use crate::error::{CoreError, Result};

/// A byte quantity parsed from a human string such as `2GiB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub const fn bytes(&self) -> u64 {
        self.0
    }

    /// Parse a size string. Binary (`KiB`) and decimal (`KB`, `K`) units are
    /// both accepted; a bare number is interpreted as bytes.
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() {
            return Err(CoreError::invalid("size", "empty value"));
        }
        let split = s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len());
        let (num, unit) = s.split_at(split);
        let value: f64 = num
            .trim()
            .parse()
            .map_err(|_| CoreError::invalid("size", format!("invalid number in `{input}`")))?;
        if value < 0.0 {
            return Err(CoreError::invalid("size", "must not be negative"));
        }
        let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
            "" | "b" => 1,
            "k" | "kb" => 1_000,
            "kib" => 1 << 10,
            "m" | "mb" => 1_000_000,
            "mib" => 1 << 20,
            "g" | "gb" => 1_000_000_000,
            "gib" => 1 << 30,
            "t" | "tb" => 1_000_000_000_000,
            "tib" => 1u64 << 40,
            other => {
                return Err(CoreError::invalid(
                    "size",
                    format!("unknown unit `{other}`"),
                ))
            }
        };
        Ok(ByteSize((value * mult as f64) as u64))
    }

    /// Canonical human string using binary units when they divide evenly.
    pub fn human(&self) -> String {
        const UNITS: [(&str, u64); 4] = [
            ("GiB", 1 << 30),
            ("MiB", 1 << 20),
            ("KiB", 1 << 10),
            ("B", 1),
        ];
        for (name, size) in UNITS {
            if self.0 >= size && self.0 % size == 0 {
                return format!("{}{}", self.0 / size, name);
            }
        }
        format!("{}B", self.0)
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.human())
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.human())
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(ByteSizeVisitor)
    }
}

struct ByteSizeVisitor;

impl Visitor<'_> for ByteSizeVisitor {
    type Value = ByteSize;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a byte size such as `2GiB` or a raw byte count")
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<ByteSize, E> {
        Ok(ByteSize(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<ByteSize, E> {
        u64::try_from(v)
            .map(ByteSize)
            .map_err(|_| E::custom("size must not be negative"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<ByteSize, E> {
        ByteSize::parse(v).map_err(E::custom)
    }
}

/// A wall-clock duration parsed from a human string such as `10m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanDuration(pub Duration);

impl HumanDuration {
    pub const fn as_duration(&self) -> Duration {
        self.0
    }

    /// Parse a duration string built from `ms`, `s`, `m`, `h`, `d` segments.
    pub fn parse(input: &str) -> Result<Self> {
        let s = input.trim();
        if s.is_empty() {
            return Err(CoreError::invalid("duration", "empty value"));
        }
        // Bare number is seconds.
        if let Ok(secs) = s.parse::<u64>() {
            return Ok(HumanDuration(Duration::from_secs(secs)));
        }

        let mut total = Duration::ZERO;
        let mut number = String::new();
        let mut chars = s.chars().peekable();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() || c == '.' {
                number.push(c);
                chars.next();
                continue;
            }
            let mut unit = String::new();
            while let Some(&u) = chars.peek() {
                if u.is_ascii_alphabetic() {
                    unit.push(u.to_ascii_lowercase());
                    chars.next();
                } else {
                    break;
                }
            }
            let value: f64 = number
                .parse()
                .map_err(|_| CoreError::invalid("duration", format!("bad number in `{input}`")))?;
            number.clear();
            let seconds = match unit.as_str() {
                "ms" => value / 1000.0,
                "s" | "sec" => value,
                "m" | "min" => value * 60.0,
                "h" | "hr" => value * 3600.0,
                "d" => value * 86_400.0,
                other => {
                    return Err(CoreError::invalid(
                        "duration",
                        format!("unknown unit `{other}`"),
                    ))
                }
            };
            let segment = Duration::try_from_secs_f64(seconds).map_err(|_| {
                CoreError::invalid("duration", format!("`{input}` is out of range"))
            })?;
            total = total.checked_add(segment).ok_or_else(|| {
                CoreError::invalid("duration", format!("`{input}` is out of range"))
            })?;
        }
        if !number.is_empty() {
            return Err(CoreError::invalid(
                "duration",
                format!("missing unit after `{number}`"),
            ));
        }
        Ok(HumanDuration(total))
    }

    /// Canonical human string, e.g. `10m` or `1h30m`.
    pub fn human(&self) -> String {
        let mut secs = self.0.as_secs();
        if secs == 0 {
            return "0s".to_string();
        }
        let mut out = String::new();
        for (unit, size) in [("h", 3600u64), ("m", 60), ("s", 1)] {
            let n = secs / size;
            if n > 0 {
                out.push_str(&format!("{n}{unit}"));
                secs %= size;
            }
        }
        out
    }
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.human())
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.human())
    }
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        HumanDuration::parse(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_binary_and_decimal_sizes() {
        assert_eq!(ByteSize::parse("1024").unwrap().bytes(), 1024);
        assert_eq!(ByteSize::parse("2GiB").unwrap().bytes(), 2 << 30);
        assert_eq!(ByteSize::parse("512MiB").unwrap().bytes(), 512 << 20);
        assert_eq!(ByteSize::parse("1GB").unwrap().bytes(), 1_000_000_000);
        assert_eq!(ByteSize::parse("64 KiB").unwrap().bytes(), 64 << 10);
    }

    #[test]
    fn rejects_bad_sizes() {
        assert!(ByteSize::parse("").is_err());
        assert!(ByteSize::parse("abc").is_err());
        assert!(ByteSize::parse("10 QiB").is_err());
    }

    #[test]
    fn size_round_trips() {
        let s = ByteSize::parse("2GiB").unwrap();
        assert_eq!(s.human(), "2GiB");
    }

    #[test]
    fn parses_durations() {
        assert_eq!(
            HumanDuration::parse("30s").unwrap().as_duration().as_secs(),
            30
        );
        assert_eq!(
            HumanDuration::parse("10m").unwrap().as_duration().as_secs(),
            600
        );
        assert_eq!(
            HumanDuration::parse("1h30m")
                .unwrap()
                .as_duration()
                .as_secs(),
            5400
        );
        assert_eq!(
            HumanDuration::parse("90").unwrap().as_duration().as_secs(),
            90
        );
    }

    #[test]
    fn duration_round_trips() {
        let d = HumanDuration::parse("1h30m").unwrap();
        assert_eq!(d.human(), "1h30m");
    }

    #[test]
    fn rejects_bad_durations() {
        assert!(HumanDuration::parse("10x").is_err());
        assert!(HumanDuration::parse("10m5").is_err());
    }

    #[test]
    fn rejects_out_of_range_durations_instead_of_panicking() {
        // Found by fuzzing (fuzz/fuzz_targets/units.rs): a numeric segment
        // large enough that `Duration::from_secs_f64` would panic on
        // overflow. Must return a clean error instead.
        assert!(HumanDuration::parse("1e400s").is_err());
        assert!(HumanDuration::parse(&format!("{}d", "9".repeat(30))).is_err());
    }
}
