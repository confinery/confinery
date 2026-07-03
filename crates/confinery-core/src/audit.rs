//! Structured audit trail for sandbox lifecycle and policy decisions.
//!
//! Records are written as newline-delimited JSON (JSONL), one event per line,
//! each stamped with an RFC 3339 UTC timestamp.

use std::io::Write;
use std::path::Path;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// A single audit event.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A sandbox is about to start.
    SandboxStart {
        id: String,
        profile: String,
        command: Vec<String>,
    },
    /// A security layer was applied successfully.
    LayerApplied {
        id: String,
        layer: String,
        detail: String,
    },
    /// A security layer was skipped (unsupported or disabled).
    LayerSkipped {
        id: String,
        layer: String,
        reason: String,
    },
    /// A policy decision denied an action.
    Violation {
        id: String,
        kind: String,
        detail: String,
    },
    /// The sandboxed process finished.
    SandboxExit {
        id: String,
        code: Option<i32>,
        signal: Option<i32>,
        duration_ms: u128,
    },
}

#[derive(Serialize)]
struct Record<'a> {
    ts: String,
    #[serde(flatten)]
    event: &'a AuditEvent,
}

/// Writes audit events to a sink, or discards them when disabled.
pub struct Auditor {
    writer: Option<Box<dyn Write + Send>>,
}

impl Auditor {
    /// An auditor that discards every event.
    pub fn disabled() -> Self {
        Auditor { writer: None }
    }

    /// Write events to an arbitrary sink.
    pub fn to_writer(writer: Box<dyn Write + Send>) -> Self {
        Auditor {
            writer: Some(writer),
        }
    }

    /// Append events to a file, creating it if needed.
    pub fn to_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Auditor::to_writer(Box::new(file)))
    }

    pub fn is_enabled(&self) -> bool {
        self.writer.is_some()
    }

    /// Record an event. Serialization failures are surfaced through tracing but
    /// never interrupt the sandbox.
    pub fn record(&mut self, event: AuditEvent) {
        let Some(writer) = self.writer.as_mut() else {
            return;
        };
        let record = Record {
            ts: now_rfc3339(),
            event: &event,
        };
        match serde_json::to_vec(&record) {
            Ok(mut line) => {
                line.push(b'\n');
                if let Err(err) = writer.write_all(&line).and_then(|_| writer.flush()) {
                    tracing::warn!(%err, "failed to write audit record");
                }
            }
            Err(err) => tracing::warn!(%err, "failed to serialize audit record"),
        }
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_jsonl_records() {
        let buf: Vec<u8> = Vec::new();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(buf));
        let writer = SharedBuf(shared.clone());
        let mut auditor = Auditor::to_writer(Box::new(writer));
        auditor.record(AuditEvent::SandboxStart {
            id: "abc".into(),
            profile: "default".into(),
            command: vec!["echo".into(), "hi".into()],
        });
        let out = String::from_utf8(shared.lock().unwrap().clone()).unwrap();
        assert!(out.contains("\"event\":\"sandbox_start\""));
        assert!(out.contains("\"ts\":"));
        assert!(out.ends_with('\n'));
    }

    struct SharedBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for SharedBuf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
