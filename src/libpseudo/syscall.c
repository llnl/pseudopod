// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pseudo/syscall.h>
#include <pseudo/log.h>

#include <sys/ptrace.h>
#include <sys/uio.h>
#include <errno.h>
#include <stdio.h>

int write_u32_to_child(pid_t pid, uint64_t addr, uint32_t value) {
    // attempt process_vm_writev
    struct iovec local = {.iov_base = &value, .iov_len = sizeof(value)};
    struct iovec remote = {.iov_base = (void *)(uintptr_t)addr, .iov_len = sizeof(value)};
    ssize_t nw = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (nw == (ssize_t)sizeof(value)) { return 0; }

    // attempt fallback via ptrace PEEK/POKE (word-aligned read-modify-write)
    pseudo_log_debug("process_vm_writev failed. Falling back to PTRACE_POKE");
    errno = 0;
    uint64_t word = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)addr, NULL);
    if (word == (uint64_t)-1 && errno != 0) {
        return -1;
    }

    // replace low 32 bits, assuming little-endian and that writing exactly 4 bytes is intended
    uint64_t newword = (word & 0xffffffff00000000ull) | ((uint64_t)value & 0xffffffffull);
    if (ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)addr, (void *)newword) == -1) {
        return -1;
    }
    return 0;
}

int write_u64_to_child(pid_t pid, uint64_t addr, uint64_t value) {
    struct iovec local = {.iov_base = &value, .iov_len = sizeof(value)};
    struct iovec remote = {.iov_base = (void *)(uintptr_t)addr, .iov_len = sizeof(value)};
    ssize_t nw = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (nw == (ssize_t)sizeof(value)) return 0;

    // attempt fallback via ptrace PEEK/POKE (word-aligned read-modify-write)
    pseudo_log_debug("process_vm_writev failed. Falling back to PTRACE_POKE");
    if (addr % sizeof(uint64_t) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)addr, (void *)value) == -1) {
        return -1;
    }
    return 0;
}

#if defined(__x86_64__)
#include <sys/user.h>

int syscall_get_regs(pid_t pid, syscall_ctx_t *out) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) return -1;
    out->args[0]  = regs.rdi;
    out->args[1]  = regs.rsi;
    out->args[2]  = regs.rdx;
    out->args[3]  = regs.r10;
    out->args[4]  = regs.r8;
    out->args[5]  = regs.r9;
    out->no       = regs.orig_rax;
    out->ret      = regs.rax; // <-- Return value is in rax
    return 0;
}

int syscall_set_regs(pid_t pid, const syscall_ctx_t *in) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) return -1;
    regs.rdi      = in->args[0];
    regs.rsi      = in->args[1];
    regs.rdx      = in->args[2];
    regs.r10      = in->args[3];
    regs.r8       = in->args[4];
    regs.r9       = in->args[5];
    regs.orig_rax = in->no;
    regs.rax      = in->ret; // <-- Set return value
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) return -1;
    return 0;
}

#elif defined(__aarch64__)
#include <asm/ptrace.h>
#include <limits.h>

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif

/*
 * Read the active arm64 syscall number from the kernel's dedicated
 * syscall-number regset.
 *
 * On arm64, the syscall number is passed in x8 at syscall entry, but
 * ptrace/seccomp syscall rewriting is controlled through
 * NT_ARM_SYSTEM_CALL rather than by editing x8 in NT_PRSTATUS. Reading
 * this regset gives us the syscall number the kernel will actually use[1].
 *
 * Returns 0 on success and -1 on ptrace failure.
 *
 *   [1] arm64 original reasoning for NT_ARM_SYSTEM_CALL:
 *   https://lkml.iu.edu/hypermail/linux/kernel/1411.2/01094.html
 */
static int arm64_get_syscallno(pid_t pid, int *syscallno) {
    struct iovec iov = { .iov_base = syscallno, .iov_len = sizeof(*syscallno) };
    return ptrace(PTRACE_GETREGSET, pid, (void*)NT_ARM_SYSTEM_CALL, &iov);
}

/*
 * Write the active arm64 syscall number through NT_ARM_SYSTEM_CALL.
 *
 * This is required for syscall rewriting and syscall skipping on arm64.
 * In particular, setting the syscall number to a negative value tells the
 * kernel to skip the syscall, which is how pseudopod emulates successful
 * setuid/setgid-style calls without allowing them to reach the real kernel.
 *
 * Returns 0 on success and -1 on ptrace failure.
 */
static int arm64_set_syscallno(pid_t pid, int syscallno) {
    struct iovec iov = { .iov_base = &syscallno, .iov_len = sizeof(syscallno) };
    return ptrace(PTRACE_SETREGSET, pid, (void*)NT_ARM_SYSTEM_CALL, &iov);
}

/*
 * Convert pseudopod's syscall context number into the signed int format
 * expected by the arm64 NT_ARM_SYSTEM_CALL regset.
 *
 * Real arm64 syscall numbers fit in a positive int. Pseudopod uses -1,
 * stored through the unsigned syscall context field, as the sentinel for
 * "skip this syscall." Values outside the positive int range are therefore
 * treated as that skip sentinel.
 */
static int arm64_ctx_syscallno(uint64_t no) {
    if (no > INT_MAX) return -1;
    return (int)no;
}

int syscall_get_regs(pid_t pid, syscall_ctx_t *out) {
    struct user_pt_regs regs;
    int syscallno;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == -1) return -1;
    if (arm64_get_syscallno(pid, &syscallno) == -1) return -1;
    for (int i = 0; i < 6; ++i) out->args[i] = regs.regs[i]; // x0-x5
    out->no = (uint64_t)(int64_t)syscallno;
    out->ret = regs.regs[0];        // x0 is return value
    return 0;
}

int syscall_set_regs(pid_t pid, const syscall_ctx_t *in) {
    struct user_pt_regs regs;
    int syscallno = arm64_ctx_syscallno(in->no);
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == -1) return -1;
    if (arm64_set_syscallno(pid, syscallno) == -1) return -1;
    for (int i = 0; i < 6; ++i) regs.regs[i] = in->args[i]; // x0-x5
    if (syscallno < 0) regs.regs[0] = in->ret;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) == -1) return -1;
    return 0;
}

#elif defined(__powerpc64__)
#include <asm/ptrace.h>

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

int syscall_get_regs(pid_t pid, syscall_ctx_t *out) {
    struct pt_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == -1) return -1;
    out->args[0] = regs.gpr[3];
    out->args[1] = regs.gpr[4];
    out->args[2] = regs.gpr[5];
    out->args[3] = regs.gpr[6];
    out->args[4] = regs.gpr[7];
    out->args[5] = regs.gpr[8];
    out->no = regs.gpr[0];         // orig_gpr3
    out->ret = regs.gpr[3];        // r3 is return value
    return 0;
}

int syscall_set_regs(pid_t pid, const syscall_ctx_t *in) {
    struct pt_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == -1) return -1;
    regs.gpr[3] = in->args[0];
    regs.gpr[4] = in->args[1];
    regs.gpr[5] = in->args[2];
    regs.gpr[6] = in->args[3];
    regs.gpr[7] = in->args[4];
    regs.gpr[8] = in->args[5];
    regs.gpr[0] = in->no;         // orig_gpr3
    regs.gpr[3] = in->ret;        // r3 is return value
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) == -1) return -1;
    return 0;
}

#else
#error "Unsupported architecture"
#endif
