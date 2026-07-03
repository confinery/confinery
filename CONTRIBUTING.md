# Contributing

Thanks for helping improve Confinery. This is a security tool, so correctness and clear boundaries matter more than features.

## Getting set up

```
cargo build --workspace
cargo test --workspace
```

Before opening a pull request:

```
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

CI runs these on Linux and Windows and will not merge on a failure.

## Ground rules

- **Fail closed.** If a layer cannot be applied, report it — never weaken a default to make something work.
- **Keep the split.** Policy and validation live in `confinery-core` with no OS calls; platform code lives in `confinery-sandbox`. See [docs/architecture.md](docs/architecture.md).
- **Test what you add.** Unit tests for policy and compilation, integration tests (`crates/confinery-cli/tests`) for behaviour. Isolation tests must degrade gracefully on hosts that lack a feature.
- **Least privilege stays the default.** New profile fields need a least-privilege default and a `policy::validate` check.
- **Docs are terse and honest.** Describe what a layer actually enforces and its limits.

## Changes that need discussion first

Open an issue before: adding a new platform backend, changing profile schema or defaults, or relaxing any default boundary. These affect the security posture and deserve review before code.

## Commits and PRs

Keep commits focused with a clear message. Describe what changed and why, and note any security implications. Link the issue you are addressing.

By contributing you agree your work is licensed under Apache-2.0.
