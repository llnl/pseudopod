// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#include <pseudo/syscall.h>
#include "internal/log.h"

#define _GNU_SOURCE
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
    DEBUG(stderr, "process_vm_writev failed. Falling back to PTRACE_POKE\n");
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
    DEBUG(stderr, "process_vm_writev failed. Falling back to PTRACE_POKE\n");
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

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

int syscall_get_regs(pid_t pid, syscall_ctx_t *out) {
    struct user_pt_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == -1) return -1;
    for (int i = 0; i < 6; ++i) out->args[i] = regs.regs[i]; // x0-x5
    out->no = regs.regs[8];         // x8 is syscall number
    out->ret = regs.regs[0];        // x0 is return value
    return 0;
}

int syscall_set_regs(pid_t pid, const syscall_ctx_t *in) {
    struct user_pt_regs regs;
    struct iovec iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) == -1) return -1;
    for (int i = 0; i < 6; ++i) regs.regs[i] = in->args[i]; // x0-x5
    regs.regs[8] = in->no;         // x8 is syscall number
    regs.regs[0] = in->ret;        // x0 is return value
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
