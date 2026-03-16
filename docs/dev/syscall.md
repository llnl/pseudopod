# Syscall and Tracee Access API

`pseudo/syscall.h` provides two groups of helpers:

- register snapshot/readback through `syscall_ctx_t`
- direct writes into the tracee address space

These helpers are intended for use from syscall callbacks and tracer-side
modules that are operating on a stopped tracee.

## Core Types

### `syscall_abi_t`

`syscall_abi_t` names the ABI whose register calling convention is being used:

- `SYSCALL_ABI_UNKNOWN`
- `SYSCALL_ABI_X86_64`
- `SYSCALL_ABI_X86_I386`
- `SYSCALL_ABI_AARCH64`
- `SYSCALL_ABI_ARM`
- `SYSCALL_ABI_PPC64LE`
- `SYSCALL_ABI_S390X`

This enum serves two roles today:

- it records the ABI in `syscall_ctx_t`
- it indexes the syscall-number tables used by seccomp filter generation

The enum is broader than the currently implemented `ptrace` register backends.

### `syscall_ctx_t`

```C
typedef struct {
    uint64_t args[6];
    uint64_t no;
    uint64_t ret;
    syscall_abi_t abi;
} syscall_ctx_t;
```

Field meaning:

- `args[0..5]` are the first six syscall arguments in ABI order
- `no` is the syscall number
- `ret` is the current return-value register
- `abi` records which ABI decoder populated the struct

`handle_syscall()` reads this struct before running syscall callbacks, then
writes it back after the callbacks return.

## Register Access

### `int syscall_get_regs(pid_t pid, syscall_ctx_t* out)`

Reads the stopped tracee register state into `out`.

### `int syscall_set_regs(pid_t pid, const syscall_ctx_t* in)`

Writes `in` back into the stopped tracee register state.

Current implementation notes:

- these calls return `0` on success and `-1` on `ptrace` failure
- the tracee must already be in a `ptrace` stop
- the implementation is compiled per host architecture

Implemented register mappings today:

| Host build target | `args[]` source | `no` source | `ret` source |
| --- | --- | --- | --- |
| x86_64 | `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` | `orig_rax` | `rax` |
| aarch64 | `x0`..`x5` | `x8` | `x0` |
| ppc64le | `gpr[3]`..`gpr[8]` | `gpr[0]` | `gpr[3]` |

If the library is built on an unsupported architecture, `src/libpseudo/syscall.c`
currently fails compilation with `#error "Unsupported architecture"`.

## Tracee Memory Writes

### `int write_u32_to_child(pid_t pid, uint64_t addr, uint32_t value)`

Writes four bytes into the tracee at `addr`.

Current strategy:

1. try `process_vm_writev()`
2. if that fails, read one machine word with `PTRACE_PEEKDATA`
3. replace the low 32 bits
4. write the result back with `PTRACE_POKEDATA`

Constraints of the fallback path:

- it assumes little-endian layout
- it assumes the low 32 bits returned by `PTRACE_PEEKDATA` correspond to the
  target address

### `int write_u64_to_child(pid_t pid, uint64_t addr, uint64_t value)`

Writes eight bytes into the tracee at `addr`.

Current strategy:

1. try `process_vm_writev()`
2. if that fails, require 8-byte alignment and use `PTRACE_POKEDATA`

If the fallback sees an unaligned address, it returns `-1` and sets
`errno = EINVAL`.

## Guidance for Callback Authors

- Modify the `syscall_ctx_t` passed into a syscall callback rather than calling
  `syscall_set_regs()` directly from the callback unless you need a custom
  write timing.
- Treat `ret` carefully on syscall-entry stops. The runtime always round-trips
  the register file, so any changes you make will be written back even if the
  syscall has not executed yet.
- Prefer the typed helpers in this header over raw `ptrace` register code so
  ABI differences stay localized.
