# Changelog

## v1.1.1 - 2026-05-18

### Added
- `--debug` flag for `pseudo` and `pseudopod` CLIs to enable trace-level logging (PR #17)
- Architecture gating to seccomp filters (PR #17)

### Changed
- Seccomp filters now terminate the child process if the kernel-reported seccomp architecture doesn’t match the build’s native architecture (PR #17)

### Fixed
- Corrected virtid handling of `setresuid(-1, uid, -1)` / `setresgid(-1, gid, -1)` by accepting both 32-bit and 64-bit `-1` representations (PR #12)
- Proper ordering of tracer parent callbacks after the initial child stop is observed, ensuring correct ordering with `pseudo_fork` semantics (PR #17)
- `pseudo_run()` now returns the traced program’s exit status instead of always returning `0` (PR #17)
- Potential crash when unprivileged mapping is attempted with an empty ID map entry list (PR #17)
- `update_pmi_fd()` environment variable return value check (PR #17)
- aarch64 syscall emulation now uses `NT_ARM_SYSTEM_CALL` to read/write the traced syscall number, fixing root emulation paths that previously leaked through (PR #16)
- `trace.json` seccomp profile updated to include `SCMP_ARCH_PPC64LE` (PR #17)
- Typo fix in `docs/architecture.md` (PR #17)

### Build
- Improved build compatibility with Clang and musl (Alpine) and added `docs/alpine.df` recipe (PR #13)
- Stricter internal compiler warning handling and Alpine recipe typo fixes (PR #15)

### Documentation
- Updated `README.md` build instructions (PR #14)
