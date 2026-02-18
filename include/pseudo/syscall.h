// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_ARCH_H
#define LIBPSEUDO_ARCH_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <inttypes.h>
#include <sys/types.h>

typedef struct {
    uint64_t args[6];
    uint64_t no;
    uint64_t ret;
} syscall_ctx_t;

int write_u32_to_child(pid_t pid, uint64_t addr, uint32_t value);
int write_u64_to_child(pid_t pid, uint64_t addr, uint64_t value);

int syscall_get_regs(pid_t pid, syscall_ctx_t *out);
int syscall_set_regs(pid_t pid, const syscall_ctx_t *in);

#endif
