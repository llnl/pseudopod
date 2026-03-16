// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod
// Contributors. See top-level LICENSE and COPYRIGHT files for dates and other
// details.

// SPDX-License-Identifier: (Apache-2.0)

#define _GNU_SOURCE
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "pseudo/seccomp.h"
#include <libpseudo/internal/nr_map.h>
#include <pseudo/log.h>

/** Create a BPF filter from a flagged subset of shared syscall descriptors.
    @param flag_mask        syscall(s) filter
    @param match_action     seccomp action returned for matching syscalls.
    @return                 BPF program matching the selected syscalls. */
static struct sock_fprog make_filter(uint32_t flag_mask,
                                     uint32_t match_action)
{
    size_t per_arch_overhead = 4; // ld arch, jeq arch, ld nr, ja allow
    size_t total_len = 0;

    for (size_t arch = 0; arch < pseudo_arch_info_count; arch++) {
        total_len += per_arch_overhead;
        total_len += get_syscall_abi_count(flag_mask,
                                           pseudo_arch_info[arch].abi);
    }

    total_len += 2; // RET allow, RET match

    struct sock_filter* prog = calloc(total_len, sizeof(*prog));
    if (!prog) {
        die("calloc failed for seccomp filter");
    }

    size_t idx = 0;
    size_t idx_allow = total_len - 2;
    size_t idx_match = total_len - 1;

    for (size_t arch = 0; arch < pseudo_arch_info_count; arch++) {
        syscall_abi_t abi = pseudo_arch_info[arch].abi;
        size_t arch_match_count = get_syscall_abi_count(flag_mask, abi);
        size_t idx_next_arch = idx + 4 + arch_match_count;

        prog[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                                   offsetof(struct seccomp_data, arch));

        uint8_t jf_next_arch = (uint8_t)(idx_next_arch - idx - 1);
        prog[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                   pseudo_arch_info[arch].audit_arch,
                                                   0,
                                                   jf_next_arch);

        prog[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                                   offsetof(struct seccomp_data, nr));

        for (size_t ri = 0; ri < pseudo_syscall_info_count; ri++) {
            const pseudo_syscall_info_t* info = &pseudo_syscall_info[ri];
            int nr;

            if (!(info->flags & flag_mask)) {
                continue;
            }

            nr = info->nr[abi];
            if (nr == PSEUDO_SYSCALL_NR_NONE) {
                continue;
            }

            uint8_t jt_match = (uint8_t)(idx_match - idx - 1);
            prog[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                       (uint32_t)nr,
                                                       jt_match,
                                                       0);
        }

        uint32_t ja_allow = (uint32_t)(idx_allow - idx - 1);
        prog[idx++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JA,
                                                   ja_allow,
                                                   0,
                                                   0);
    }

    prog[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    prog[idx++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, match_action);

    if (idx != total_len) {
        die("make_filter: instruction count mismatch");
    }

    struct sock_fprog out = {
        .len = (unsigned short)total_len,
        .filter = prog,
    };
    return out;
}

static struct sock_fprog seccomp_prog_fakeroot = { 0 };

static const seccomp_fprog* get_or_make_fakeroot_filter(void) {
    if (!seccomp_prog_fakeroot.filter) {
        /* Note: we preserve the original fakeroot filter behavior here: use the
           same syscall match set as trace mode, but return fake success via
           SECCOMP_RET_ERRNO|0 rather than trapping to the tracer.
         */
        seccomp_prog_fakeroot = make_filter(PSEUDO_SCF_TRACE,
                                            SECCOMP_RET_ERRNO | 0);
    }
    return &seccomp_prog_fakeroot;
}

static struct sock_fprog seccomp_prog_trace = { 0 };
static struct sock_fprog seccomp_prog_fakechown = { 0 };

static const seccomp_fprog* get_or_make_trace_filter(void) {
    if (!seccomp_prog_trace.filter) {
        seccomp_prog_trace = make_filter(PSEUDO_SCF_TRACE,SECCOMP_RET_TRACE);
    }
    return &seccomp_prog_trace;
}

static const seccomp_fprog* get_or_make_fakechown_filter(void) {
    if (!seccomp_prog_fakechown.filter) {
        seccomp_prog_fakechown = make_filter(PSEUDO_SCF_FAKECHOWN,
                                             SECCOMP_RET_ERRNO | 0);
    }
    return &seccomp_prog_fakechown;
}

void set_no_new_privs() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) die("prctl NO_NEW_PRIVS");
}

const seccomp_fprog* get_filter_trace()     { return get_or_make_trace_filter(); }
const seccomp_fprog* get_filter_fakechown() { return get_or_make_fakechown_filter(); }
const seccomp_fprog* get_filter_fakeroot()  { return get_or_make_fakeroot_filter(); }

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
