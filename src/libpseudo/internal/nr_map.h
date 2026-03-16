// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod
// Contributors. See top-level LICENSE and COPYRIGHT files for dates and other
// details.

// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_INTERNAL_NR_MAP_H
#define LIBPSEUDO_INTERNAL_NR_MAP_H

#include <stddef.h>
#include <stdint.h>
#include <pseudo/syscall.h>

#define PSEUDO_SYSCALL_NR_NONE (-1)

typedef enum {
    PSEUDO_SC_NONE = 0,
    PSEUDO_SC_SETUID,
    PSEUDO_SC_SETGID,
    PSEUDO_SC_GETUID,
    PSEUDO_SC_GETGID,
    PSEUDO_SC_GETEUID,
    PSEUDO_SC_GETEGID,
    PSEUDO_SC_SETREUID,
    PSEUDO_SC_SETREGID,
    PSEUDO_SC_SETRESUID,
    PSEUDO_SC_SETRESGID,
    PSEUDO_SC_GETRESUID,
    PSEUDO_SC_GETRESGID,
    PSEUDO_SC_CHOWN,
    PSEUDO_SC_LCHOWN,
    PSEUDO_SC_SETGROUPS,
    PSEUDO_SC_FCHOWN,
    PSEUDO_SC_FCHOWNAT,
} pseudo_syscall_id_t;

enum pseudo_syscall_flags {
    PSEUDO_SCF_TRACE     = 1u << 0,
    PSEUDO_SCF_FAKECHOWN = 1u << 1,
    PSEUDO_SCF_VIRTID    = 1u << 2,
};

typedef struct {
    syscall_abi_t abi;
    uint32_t audit_arch;
} pseudo_arch_info_t;

typedef struct {
    pseudo_syscall_id_t id;
    const char* name;
    uint32_t flags;
    int nr[SYSCALL_ABI_COUNT];
} pseudo_syscall_info_t;

extern const pseudo_arch_info_t pseudo_arch_info[];
extern const size_t pseudo_arch_info_count;

extern const pseudo_syscall_info_t pseudo_syscall_info[];
extern const size_t pseudo_syscall_info_count;

const pseudo_syscall_info_t* get_syscall_by_nr(syscall_abi_t abi,
                                               uint64_t nr);
size_t get_syscall_abi_count(uint32_t flag_mask, syscall_abi_t abi);

#endif
