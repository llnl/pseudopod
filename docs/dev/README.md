# `libpseudo` Developer API

This directory documents the developer-facing API implemented in
`src/libpseudo` and exported from `include/pseudo`.

The public API is split across four headers:

- [`pseudo/pseudo.h`](../../include/pseudo/pseudo.h) for
  - configuration,
  - callback registration, and
  - the top-level runtime entry point
- [`pseudo/seccomp.h`](../../include/pseudo/seccomp.h) for
  - shared seccomp filter builders and installation helpers
- [`pseudo/syscall.h`](../../include/pseudo/syscall.h) for
  - tracee register, and
  - memory patching helpers
- [`pseudo/log.h`](../../include/pseudo/log.h) for
  - logging and fatal error handling

Further reading (recommended order):

- [`libpseudo-runtime.md`](./libpseudo-runtime.md) for
  - configuration,
  - callback phases,
  - ownership rules,
  - and `pseudo_run()`
- [`seccomp.md`](./seccomp.md) for
  - filter selection,
  - installation, and
  - how the built-in filter sets are derived
- [`syscall.md`](./syscall.md) for
  - `syscall_ctx_t`,
  - register access, and
  - tracee memory writes
- [`logging.md`](./logging.md) for log levels, stderr output, and `die()`
