// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#define _GNU_SOURCE
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stddef.h>
#include "pseudo/seccomp.h"
#include "internal/log.h"

static struct sock_filter seccomp_filter_trace[] = {
    // Load arch
    BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),

    // Load syscall number
    BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    // x86_64 - ACT_TRACE
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setuid,    12, 0), // -> trace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setgid,    11, 0), // -> trace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getuid,    10, 0), // -> trace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getgid,     9, 0), // -> trace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_geteuid,    8, 0), // -> trace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getegid,    7, 0), // -> trace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setreuid,   6, 0), // -> trace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setregid,   5, 0), // -> trace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setresuid,  4, 0), // -> trace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setresgid,  3, 0), // -> trace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getresuid,  2, 0), // -> trace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getresgid,  1, 0), // -> trace

    // default allow
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    // trace
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE)
};


static struct sock_filter seccomp_filter_fakechown[] = {
    // Load arch
    BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),

    // Load syscall numbers
    BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    // x86_64 - ACT_ERRNO

#if !defined(__aarch64__) // undefined on aarch64
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_chown,     5, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_lchown,    4, 0), // -> fake
#endif
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setgroups, 3, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchown,    2, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fchownat,  1, 0), // -> fake

    // default allow
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    // fake success
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0)
};

static struct sock_filter seccomp_filter_fakeroot[] = {
    // Load arch
    BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),

    // Load syscall number
    BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    // x86_64 - ACT_ERRNO
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setuid,    12, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setgid,    11, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getuid,    10, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getgid,     9, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_geteuid,    8, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getegid,    7, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setreuid,   6, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setregid,   5, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setresuid,  4, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setresgid,  3, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getresuid,  2, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getresgid,  1, 0), // -> fake

    // default allow
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    // fake success
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0)
};

static struct sock_fprog seccomp_prog_trace = {
    .len = (unsigned short)(sizeof(seccomp_filter_trace)/sizeof(seccomp_filter_trace[0])),
    .filter = seccomp_filter_trace
};

static struct sock_fprog seccomp_prog_fakeroot = {
    .len = (unsigned short)(sizeof(seccomp_filter_fakeroot)/sizeof(seccomp_filter_fakeroot[0])),
    .filter = seccomp_filter_fakeroot
};

static struct sock_fprog seccomp_prog_fakechown = {
    .len = (unsigned short)(sizeof(seccomp_filter_fakechown)/sizeof(seccomp_filter_fakechown[0])),
    .filter = seccomp_filter_fakechown
};

void set_no_new_privs() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) die("prctl NO_NEW_PRIVS");
}

const seccomp_fprog* get_filter_trace() { return &seccomp_prog_trace; }
const seccomp_fprog* get_filter_fakechown() { return &seccomp_prog_fakechown; }
const seccomp_fprog* get_filter_fakeroot() { return &seccomp_prog_fakeroot; }

void install_filter(const seccomp_fprog* fprog) {
    if (!fprog) { return; }

    // Prefer seccomp() syscall if available, otherwise prctl(PR_SET_SECCOMP).
#ifdef SYS_seccomp
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, fprog) == -1) {
        die("seccomp(SECCOMP_SET_MODE_FILTER)");
    }
#else
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, fprog) == -1) {
        die("prctl(PR_SET_SECCOMP)");
    }
#endif
}

