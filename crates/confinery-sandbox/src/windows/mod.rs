//! Windows sandbox backend.
//!
//! Uses a Job Object to bound memory and active process count and to guarantee
//! the whole process tree is terminated together (`KILL_ON_JOB_CLOSE`), plus UI
//! restrictions to cut the process off from the interactive desktop, clipboard,
//! and global atoms. Environment filtering matches the other backends.
//!
//! Filesystem and network confinement are not yet enforced here; those require
//! an AppContainer, Windows Sandbox, or a WSL2 container and are reported as
//! skipped so the operator is never misled about the boundary.

use std::os::windows::io::AsRawHandle;
use std::process::Command;
use std::time::{Duration, Instant};

use confinery_core::audit::{AuditEvent, Auditor};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_TIMEOUT};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};

use crate::error::{Result, SandboxError};
use crate::report::{LayerOutcome, SandboxReport};
use crate::spec::SandboxSpec;
use crate::Sandbox;

/// The Windows sandbox engine.
pub struct WindowsSandbox;

impl WindowsSandbox {
    pub fn new() -> Self {
        WindowsSandbox
    }
}

impl Sandbox for WindowsSandbox {
    fn backend(&self) -> &'static str {
        "windows-jobobject"
    }

    fn run(&self, spec: &SandboxSpec, auditor: &mut Auditor) -> Result<SandboxReport> {
        let program = spec.program()?.to_string();
        spec.check_tool_allowed()?;

        auditor.record(AuditEvent::SandboxStart {
            id: spec.id.clone(),
            profile: spec.profile.name.clone(),
            command: spec.command.clone(),
        });

        let profile = &spec.profile;
        let mut layers = Vec::new();

        // Build the job object with resource and UI limits.
        let job = JobObject::create(
            profile.resources.memory.map(|m| m.bytes()),
            profile.resources.pids,
        )?;
        record(
            auditor,
            &spec.id,
            &mut layers,
            "job_object",
            true,
            "memory, active-process, kill-on-close",
        );
        record(
            auditor,
            &spec.id,
            &mut layers,
            "ui_restrictions",
            true,
            "desktop, clipboard, global atoms blocked",
        );
        record(
            auditor,
            &spec.id,
            &mut layers,
            "environment",
            true,
            "filtered",
        );
        record(
            auditor,
            &spec.id,
            &mut layers,
            "filesystem",
            false,
            "not enforced on Windows job backend; use WSL2 or Windows Sandbox",
        );
        record(
            auditor,
            &spec.id,
            &mut layers,
            "network",
            false,
            "not enforced on Windows job backend",
        );

        if spec.dry_run {
            return Ok(SandboxReport {
                id: spec.id.clone(),
                exit_code: None,
                signal: None,
                duration: Duration::ZERO,
                layers,
                dry_run: true,
            });
        }

        let mut cmd = Command::new(&program);
        cmd.args(&spec.command[1..]);
        if let Some(dir) = &spec.workdir {
            cmd.current_dir(dir);
        }
        crate::common::apply_env(&mut cmd, &profile.env);

        let start = Instant::now();
        let mut child = cmd.spawn().map_err(|source| SandboxError::Spawn {
            command: program.clone(),
            source,
        })?;

        let process = HANDLE(child.as_raw_handle());
        job.assign(process)?;

        let timeout = profile.resources.timeout.map(|d| d.as_duration());
        let ms = timeout
            .map(|d| d.as_millis().min(u128::from(u32::MAX)) as u32)
            .unwrap_or(INFINITE);
        let waited = unsafe { WaitForSingleObject(process, ms) };
        let timed_out = waited == WAIT_TIMEOUT;
        if timed_out {
            job.terminate(137);
        }

        let status = child.wait().map_err(SandboxError::Io)?;
        let duration = start.elapsed();
        let exit_code = status.code();

        if timed_out {
            auditor.record(AuditEvent::Violation {
                id: spec.id.clone(),
                kind: "timeout".into(),
                detail: "job terminated after timeout".into(),
            });
        }
        auditor.record(AuditEvent::SandboxExit {
            id: spec.id.clone(),
            code: exit_code,
            signal: None,
            duration_ms: duration.as_millis(),
        });

        if timed_out {
            return Err(SandboxError::Timeout {
                timeout: timeout
                    .map(|_| "configured".to_string())
                    .unwrap_or_default(),
            });
        }

        Ok(SandboxReport {
            id: spec.id.clone(),
            exit_code,
            signal: None,
            duration,
            layers,
            dry_run: false,
        })
    }
}

/// RAII wrapper around a Windows Job Object.
struct JobObject {
    handle: HANDLE,
}

impl JobObject {
    fn create(memory: Option<u64>, pids: Option<u32>) -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|e| SandboxError::layer("job_object", format!("create failed: {e}")))?;
        let job = JobObject { handle };

        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let mut flags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        if let Some(mem) = memory {
            flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            limits.JobMemoryLimit = mem as usize;
        }
        if let Some(pids) = pids {
            flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = pids;
        }
        limits.BasicLimitInformation.LimitFlags = flags;

        unsafe {
            SetInformationJobObject(
                job.handle,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(|e| SandboxError::layer("job_object", format!("set limits failed: {e}")))?;

        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        };
        unsafe {
            SetInformationJobObject(
                job.handle,
                JobObjectBasicUIRestrictions,
                &ui as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        }
        .map_err(|e| SandboxError::layer("job_object", format!("set ui limits failed: {e}")))?;

        Ok(job)
    }

    fn assign(&self, process: HANDLE) -> Result<()> {
        unsafe { AssignProcessToJobObject(self.handle, process) }
            .map_err(|e| SandboxError::layer("job_object", format!("assign failed: {e}")))
    }

    fn terminate(&self, code: u32) {
        let _ = unsafe { TerminateJobObject(self.handle, code) };
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

#[allow(clippy::too_many_arguments)]
fn record(
    auditor: &mut Auditor,
    id: &str,
    layers: &mut Vec<LayerOutcome>,
    layer: &str,
    applied: bool,
    detail: &str,
) {
    if applied {
        auditor.record(AuditEvent::LayerApplied {
            id: id.to_string(),
            layer: layer.to_string(),
            detail: detail.to_string(),
        });
        layers.push(LayerOutcome::applied(layer, detail));
    } else {
        auditor.record(AuditEvent::LayerSkipped {
            id: id.to_string(),
            layer: layer.to_string(),
            reason: detail.to_string(),
        });
        layers.push(LayerOutcome::skipped(layer, detail));
    }
}
