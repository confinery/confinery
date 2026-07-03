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
    ///
    /// Audit records include the full command line of every sandboxed run,
    /// which commonly carries secrets (API keys, tokens passed as flags).
    /// The file is created with `0600` permissions on Unix so it isn't
    /// world- or group-readable by default the way a bare `open()` (subject
    /// to the process umask, typically `0644`) would leave it.
    pub fn to_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        // `mode()` only takes effect when the file is newly created; tighten
        // it explicitly too, in case an audit file from before this fix (or
        // written by something else) is being appended to.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(err) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
                // Not fatal to the run -- the audit log is a best-effort
                // sink -- but worth surfacing since it means an existing
                // audit file may be more widely readable than intended.
                tracing::warn!(%err, "failed to restrict audit log file permissions to 0600");
            }
        }
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

    #[cfg(unix)]
    #[test]
    fn audit_file_is_created_with_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let _auditor = Auditor::to_file(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "audit log should not be group- or world-readable (command lines can carry secrets)"
        );
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
