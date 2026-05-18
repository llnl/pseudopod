// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod
// Contributors. See top-level LICENSE and COPYRIGHT files for dates and
// other details.

// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_SECCOMP_HANDLER_H
#define LIBPSEUDO_SECCOMP_HANDLER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pseudo/pseudo.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stddef.h>

#if defined(__aarch64__)
  #define AUDIT_ARCH_NATIVE AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
  #define AUDIT_ARCH_NATIVE AUDIT_ARCH_X86_64
#elif defined(__i386__) || defined(__x86__)
  #define AUDIT_ARCH_NATIVE AUDIT_ARCH_I386
#elif (defined(__powerpc64__) || defined(__ppc64__)) \
  && ((defined(__LITTLE_ENDIAN__) || defined(__BYTE_ORDER__)) \
  && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
  #define AUDIT_ARCH_NATIVE AUDIT_ARCH_PPC64LE
#else
  #error "Unsupported architecture"
#endif

typedef struct sock_fprog seccomp_fprog;

// Filter getters; return pointers to static filter definitions
const seccomp_fprog* get_filter_trace(void);
const seccomp_fprog* get_filter_fakechown(void);
const seccomp_fprog* get_filter_fakeroot(void);

// Handler attachment API (similar to virtid_attach_handlers)
typedef struct {
    pseudo_cb_t child;
} seccomp_callbacks_t;

/**
 * Create callback bundle for seccomp filter installation.
 * @param filters NULL-terminated array of seccomp_fprog pointers
 * @return Callback structure to be attached to config
 */
seccomp_callbacks_t seccomp_callbacks(const seccomp_fprog* const* filters);

/**
 * Convenience function to attach seccomp handlers to config.
 * This is equivalent to:
 *   seccomp_callbacks_t cbs = seccomp_callbacks(filters);
 *   pseudo_cb_adds(&cfg->cfg_child.cbs, &cbs.child);
 * 
 * @param cfg The pseudo configuration
 * @param filters NULL-terminated array of seccomp_fprog pointers
 */
void seccomp_attach_handlers(pseudo_config_t* cfg, const seccomp_fprog* const* filters);

// Utility functions
void set_no_new_privs(void);
void install_filter(const seccomp_fprog* fprog);

#endif // LIBPSEUDO_SECCOMP_HANDLER_H