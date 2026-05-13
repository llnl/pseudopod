// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#define _GNU_SOURCE
#include "seccomp.h"

static struct sock_filter seccomp_filter_fakeroot[] = {
    // Load arch
    BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),

    // Load syscall number
    BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    // x86_64 - ACT_ERRNO
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setuid,    14, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setgid,    13, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getuid,    12, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getgid,    11, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_geteuid,   10, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getegid,    9, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setreuid,   8, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setregid,   7, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setresuid,  6, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setresgid,  5, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getresuid,  4, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getresgid,  3, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setfsuid,   2, 0), // -> fake
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setfsgid,   1, 0), // -> fake

    // default allow
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    // fake success
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 0)
};

static struct sock_fprog seccomp_prog_fakeroot = {
    .len = (unsigned short)(sizeof(seccomp_filter_fakeroot)/sizeof(seccomp_filter_fakeroot[0])),
    .filter = seccomp_filter_fakeroot
};

/**
 * Get the fakeroot seccomp filter.
 * This filter intercepts uid/gid-related syscalls and fakes success.
 * @return Pointer to static seccomp filter program
 */
const seccomp_fprog* get_filter_fakeroot(void) {
    return &seccomp_prog_fakeroot;
}