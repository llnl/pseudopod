// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod
// Contributors. See top-level LICENSE and COPYRIGHT files for dates and
// other details.

// SPDX-License-Identifier: (Apache-2.0)

#define _GNU_SOURCE
#include "seccomp.h"

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

static struct sock_fprog seccomp_prog_fakechown = {
    .len = (unsigned short)(sizeof(seccomp_filter_fakechown)/sizeof(seccomp_filter_fakechown[0])),
    .filter = seccomp_filter_fakechown
};

/**
 * Get the fakechown seccomp filter.
 * This filter intercepts chown-related syscalls and fakes success.
 * @return Pointer to static seccomp filter program
 */
const seccomp_fprog* get_filter_fakechown(void) {
    return &seccomp_prog_fakechown;
}