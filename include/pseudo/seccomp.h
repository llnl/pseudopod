// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef PSEUDO_SECCOMP_H
#define PSEUDO_SECCOMP_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stddef.h>

typedef struct sock_fprog seccomp_fprog;
const seccomp_fprog* get_filter_trace();
const seccomp_fprog* get_filter_fakechown();
const seccomp_fprog* get_filter_fakeroot();

void set_no_new_privs();

void install_filter(const seccomp_fprog* fprog);
#endif
