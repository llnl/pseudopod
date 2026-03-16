// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod
// Contributors. See top-level LICENSE and COPYRIGHT files for dates and other
// details.
//
// SPDX-License-Identifier: (Apache-2.0)

#include <libpseudo/internal/nr_map.h>

#include <linux/audit.h>

/* Some Linux distros omit the following AUDIT_ARCH_* definitions from the
   kernel UAPI headers. */
#ifndef AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_AARCH64 0xC00000B7
#endif

#ifndef AUDIT_ARCH_ARM
#define AUDIT_ARCH_ARM 0x40000028
#endif

#define NR_MAP(x86_64, x86_i386, aarch64, arm, ppc64le, s390x) \
    { \
        [SYSCALL_ABI_UNKNOWN] = PSEUDO_SYSCALL_NR_NONE, \
        [SYSCALL_ABI_X86_64] = (x86_64), \
        [SYSCALL_ABI_X86_I386] = (x86_i386), \
        [SYSCALL_ABI_AARCH64] = (aarch64), \
        [SYSCALL_ABI_ARM] = (arm), \
        [SYSCALL_ABI_PPC64LE] = (ppc64le), \
        [SYSCALL_ABI_S390X] = (s390x), \
    }

// map supported syscall abi to kernal audit arch values
const pseudo_arch_info_t pseudo_arch_info[] = {
    { .abi = SYSCALL_ABI_AARCH64,  .audit_arch = AUDIT_ARCH_AARCH64 },
    { .abi = SYSCALL_ABI_ARM,      .audit_arch = AUDIT_ARCH_ARM },
    { .abi = SYSCALL_ABI_X86_I386, .audit_arch = AUDIT_ARCH_I386 },
    { .abi = SYSCALL_ABI_PPC64LE,  .audit_arch = AUDIT_ARCH_PPC64LE },
    { .abi = SYSCALL_ABI_S390X,    .audit_arch = AUDIT_ARCH_S390X },
    { .abi = SYSCALL_ABI_X86_64,   .audit_arch = AUDIT_ARCH_X86_64 },
};

const size_t pseudo_arch_info_count =
    sizeof(pseudo_arch_info) / sizeof(pseudo_arch_info[0]);

const pseudo_syscall_info_t pseudo_syscall_info[] = {
    {
        .id = PSEUDO_SC_SETUID,
        .name = "setuid",
        .flags = PSEUDO_SCF_TRACE | PSEUDO_SCF_VIRTID,
        .nr = NR_MAP(105, 213, 146, 213, 23, 213),
    },
    {
        .id = PSEUDO_SC_SETGID,
        .name = "setgid",
        .flags = PSEUDO_SCF_TRACE | PSEUDO_SCF_VIRTID,
        .nr = NR_MAP(106, 214, 144, 214, 46, 214),
    },
    {
        .id = PSEUDO_SC_GETUID,
        .name = "getuid",
        .flags = PSEUDO_SCF_TRACE | PSEUDO_SCF_VIRTID,
        .nr = NR_MAP(102, 199, 174, 199, 24, 199),
    },
    {
        .id = PSEUDO_SC_GETGID,
        .name = "getgid",
        .flags = PSEUDO_SCF_TRACE | PSEUDO_SCF_VIRTID,
        .nr = NR_MAP(104, 200, 176, 200, 47, 200),
    },
    {
        .id = PSEUDO_SC_GETEUID,
        .name = "geteuid",
        .flags = PSEUDO_SCF_TRACE | PSEUDO_SCF_VIRTID,
        .nr = NR_MAP(107, 201, 175, 201, 49, 201),
    },
    {
        .id = PSEUDO_SC_GETEGID,
        .name = "getegid",
        .flags = PSEUDO_SCF_TRACE | PSEUDO_SCF_VIRTID,
        .nr = NR_MAP(108, 202, 177, 202, 50, 202),
    },
    {
        .id = PSEUDO_SC_SETREUID,
        .name = "setreuid",
        .flags = PSEUDO_SCF_TRACE | PSEUDO_SCF_VIRTID,
        .nr = NR_MAP(113, 203, 145, 203, 70, 203),
    },
    {
        .id = PSEUDO_SC_SETREGID,
        .name = "setregid",
        .flags = PSEUDO_SCF_TRACE | PSEUDO_SCF_VIRTID,
        .nr = NR_MAP(114, 204, 143, 204, 71, 204),
    },
    {
        .id = PSEUDO_SC_SETRESUID,
        .name = "setresuid",
        .flags = PSEUDO_SCF_TRACE | PSEUDO_SCF_VIRTID,
        .nr = NR_MAP(117, 208, 147, 208, 164, 208),
    },
    {
        .id = PSEUDO_SC_SETRESGID,
        .name = "setresgid",
        .flags = PSEUDO_SCF_TRACE | PSEUDO_SCF_VIRTID,
        .nr = NR_MAP(119, 210, 149, 210, 169, 210),
    },
    {
        .id = PSEUDO_SC_GETRESUID,
        .name = "getresuid",
        .flags = PSEUDO_SCF_TRACE | PSEUDO_SCF_VIRTID,
        .nr = NR_MAP(118, 209, 148, 209, 165, 209),
    },
    {
        .id = PSEUDO_SC_GETRESGID,
        .name = "getresgid",
        .flags = PSEUDO_SCF_TRACE | PSEUDO_SCF_VIRTID,
        .nr = NR_MAP(120, 211, 150, 211, 170, 211),
    },
    {
        .id = PSEUDO_SC_CHOWN,
        .name = "chown",
        .flags = PSEUDO_SCF_FAKECHOWN,
        .nr = NR_MAP(92, 212, PSEUDO_SYSCALL_NR_NONE, 212, 181, 212),
    },
    {
        .id = PSEUDO_SC_LCHOWN,
        .name = "lchown",
        .flags = PSEUDO_SCF_FAKECHOWN,
        .nr = NR_MAP(94, 198, PSEUDO_SYSCALL_NR_NONE, 198, 16, 198),
    },
    {
        .id = PSEUDO_SC_SETGROUPS,
        .name = "setgroups",
        .flags = PSEUDO_SCF_FAKECHOWN,
        .nr = NR_MAP(116, 206, 159, 206, 81, 206),
    },
    {
        .id = PSEUDO_SC_FCHOWN,
        .name = "fchown",
        .flags = PSEUDO_SCF_FAKECHOWN,
        .nr = NR_MAP(93, 207, 55, 207, 95, 207),
    },
    {
        .id = PSEUDO_SC_FCHOWNAT,
        .name = "fchownat",
        .flags = PSEUDO_SCF_FAKECHOWN,
        .nr = NR_MAP(260, 298, 54, 325, 289, 291),
    },
};

const size_t pseudo_syscall_info_count =
    sizeof(pseudo_syscall_info) / sizeof(pseudo_syscall_info[0]);

const pseudo_syscall_info_t* get_syscall_by_nr(syscall_abi_t abi,
                                               uint64_t nr)
{
    if (abi <= SYSCALL_ABI_UNKNOWN || abi >= SYSCALL_ABI_COUNT) {
        return NULL;
    }

    for (size_t i = 0; i < pseudo_syscall_info_count; i++) {
        int info_nr = pseudo_syscall_info[i].nr[abi];
        if (info_nr != PSEUDO_SYSCALL_NR_NONE && nr == (uint64_t) info_nr) {
            return &pseudo_syscall_info[i];
        }
    }

    return NULL;
}

size_t get_syscall_abi_count(uint32_t flag_mask, syscall_abi_t abi)
{
    size_t count = 0;

    if (abi <= SYSCALL_ABI_UNKNOWN || abi >= SYSCALL_ABI_COUNT) {
        return 0;
    }

    for (size_t i = 0; i < pseudo_syscall_info_count; i++) {
        if (!(pseudo_syscall_info[i].flags & flag_mask)) {
            continue;
        }
        if (pseudo_syscall_info[i].nr[abi] != PSEUDO_SYSCALL_NR_NONE) {
            count++;
        }
    }

    return count;
}
