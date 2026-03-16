# Seccomp API

`pseudo/seccomp.h` exposes helpers for installing shared seccomp filter
programs into the child process created by `libpseudo`.

## Public Functions

```c
const seccomp_fprog* get_filter_trace(void);
const seccomp_fprog* get_filter_fakechown(void);
const seccomp_fprog* get_filter_fakeroot(void);

void set_no_new_privs(void);
void install_filter(const seccomp_fprog* fprog);
```

`seccomp_fprog` is an alias of `struct sock_fprog`.

## Filter Builders

The three `get_filter_*()` functions return pointers to process-global cached
filters. Each filter is built lazily on first use and then reused.

Current implications:

- callers must treat the returned programs as immutable shared objects
- the implementation caches them in static storage
- allocation failure during first construction terminates through `die()`

## Built-in Filter Sets

The filter builders use `src/libpseudo/nr_map.c` and
`src/libpseudo/internal/nr_map.h` to derive the syscall numbers to match for
each supported ABI.

### `get_filter_trace()`

Builds a filter over every syscall flagged with `PSEUDO_SCF_TRACE`.

Currently that set is the identity-management family used by the virtual-ID path:

- `setuid`
- `setgid`
- `getuid`
- `getgid`
- `geteuid`
- `getegid`
- `setreuid`
- `setregid`
- `setresuid`
- `setresgid`
- `getresuid`
- `getresgid`

Matching syscalls return `SECCOMP_RET_TRACE`, which produces
`PTRACE_EVENT_SECCOMP` stops for the tracer.

### `get_filter_fakechown()`

Builds a filter over every syscall flagged with `PSEUDO_SCF_FAKECHOWN`:

- `chown`
- `lchown`
- `setgroups`
- `fchown`
- `fchownat`

Matching syscalls return `SECCOMP_RET_ERRNO | 0`, which makes the kernel
report success without performing the real syscall.

### `get_filter_fakeroot()`

Builds a filter using the same syscall match set as `get_filter_trace()`, but
returns `SECCOMP_RET_ERRNO | 0` instead of trapping to the tracer. This keeps
the syscall list aligned with trace mode while turning intercepted calls into
fake success.

## Installation Helpers

### `void set_no_new_privs(void)`

Calls `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`. Failure is fatal.

`child_exec()` calls this automatically before installing any configured
filters.

### `void install_filter(const seccomp_fprog* fprog)`

Installs one filter program into the current process.

Current behavior:

- a `NULL` pointer is ignored
- it prefers the `seccomp()` syscall when `SYS_seccomp` is available
- it falls back to `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, fprog)`
- installation failure is fatal

## Using Filters from `pseudo_config_child_t`

`pseudo_config_child_t.filters` is interpreted as a null-terminated array:

```C
const seccomp_fprog* filters[] = {
    get_filter_trace(),
    get_filter_fakechown(),
    NULL,
};
cfg.cfg_child.filters = filters;
```

The runtime installs filters in array order inside the child, after child
callbacks run and before `execvpe()`.

## ABI Coverage

Filter generation is ABI-aware. The syscall map currently carries numbers for:

- `SYSCALL_ABI_X86_64`
- `SYSCALL_ABI_X86_I386`
- `SYSCALL_ABI_AARCH64`
- `SYSCALL_ABI_ARM`
- `SYSCALL_ABI_PPC64LE`
- `SYSCALL_ABI_S390X`

If a syscall has no valid number for a given ABI, that ABI simply omits the
match instruction for that syscall.
