# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's [private vulnerability reporting](https://github.com/confinery/confinery/security/advisories/new) rather than opening a public issue.

Include what you can: affected version, platform and kernel, a profile and command that reproduce it, and what boundary was crossed. We aim to acknowledge reports within a few days.

## Scope

In scope: any way to escape a layer Confinery claims to enforce for a given profile — reading a masked path, reaching the network under `mode = "none"`, regaining a dropped capability, bypassing the seccomp filter, or exceeding a resource limit that was applied.

Out of scope: kernel vulnerabilities themselves, and behaviour on hosts where `confinery doctor` already reports a layer as unavailable. Confinery is defence in depth, not a hypervisor; running fully hostile native code still warrants a VM.

## What Confinery guarantees

Confinery fails closed. When a layer cannot be applied it is recorded in the run report and audit trail, never silently dropped. If you rely on a specific boundary, check `confinery doctor` and the run report on your target host.
