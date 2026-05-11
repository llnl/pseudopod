// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod
// Contributors. See top-level LICENSE and COPYRIGHT files for dates and
// other details.

// SPDX-License-Identifier: (Apache-2.0)

#define _GNU_SOURCE
#include "seccomp.h"
#include <pseudo/pseudo.h>
#include <pseudo/log.h>
#include <stdlib.h>
#include <string.h>

// Handler state passed to callback
typedef struct {
    const seccomp_fprog* const* filters;
} seccomp_handler_state_t;

/**
 * Child callback - installs filters before exec.
 * This callback is invoked in the child process to install seccomp filters.
 * @param cb_args Callback arguments containing filter array
 * @return 0 on success
 */
static int seccomp_child_cb(void* cb_args) {
    seccomp_handler_state_t* state = (seccomp_handler_state_t*)cb_args;

    if (!state || !state->filters) {
        pseudo_log_trace("seccomp_handler: no filters to install");
        return 0;
    }

    pseudo_log_trace("seccomp_handler: installing filters");
    set_no_new_privs();

    for (int i = 0; state->filters[i] != NULL; i++) {
        pseudo_log_trace("seccomp_handler: install filter #%d", i);
        install_filter(state->filters[i]);
    }

    pseudo_log_trace("seccomp_handler: filters installed successfully");
    return 0;
}

/**
 * Create callback bundle for seccomp filter installation.
 * @param filters NULL-terminated array of seccomp_fprog pointers
 * @return Callback structure to be attached to config
 */
seccomp_callbacks_t seccomp_callbacks(const seccomp_fprog* const* filters) {
    seccomp_callbacks_t out;
    memset(&out, 0, sizeof(out));

    if (!filters) {
        pseudo_log_warn("seccomp_callbacks: NULL filters array provided");
        return out;
    }

    // Allocate state for the handler
    seccomp_handler_state_t* state = (seccomp_handler_state_t*)malloc(sizeof(seccomp_handler_state_t));
    if (!state) {
        pseudo_die("seccomp_callbacks: failed to allocate handler state");
    }

    state->filters = filters;

    out.child.cb = (void*)seccomp_child_cb;
    out.child.cbargs = (void*)state;

    return out;
}

/**
 * Convenience function to attach seccomp handlers to config.
 * This is equivalent to:
 *   seccomp_callbacks_t cbs = seccomp_callbacks(filters);
 *   pseudo_cb_adds(&cfg->cfg_child.cbs, &cbs.child);
 * 
 * @param cfg The pseudo configuration
 * @param filters NULL-terminated array of seccomp_fprog pointers
 */
void seccomp_attach_handlers(pseudo_config_t* cfg, const seccomp_fprog* const* filters) {
    if (!cfg) {
        pseudo_log_error("seccomp_attach_handlers: NULL config provided");
        return;
    }

    seccomp_callbacks_t cbs = seccomp_callbacks(filters);
    pseudo_cb_adds(&cfg->cfg_child.cbs, &cbs.child);
    pseudo_log_debug("seccomp_attach_handlers: handlers attached");
}

/**
 * Set the no_new_privs flag for the current process.
 * This prevents gaining additional privileges through execve.
 * Required before installing seccomp filters.
 */
void set_no_new_privs(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        pseudo_die("prctl NO_NEW_PRIVS");
    }
}

/**
 * Install a seccomp filter.
 * Uses seccomp() syscall if available, otherwise falls back to prctl.
 * @param fprog The seccomp filter program to install
 */
void install_filter(const seccomp_fprog* fprog) {
    if (!fprog) {
        pseudo_log_warn("install_filter: NULL filter provided");
        return;
    }

    // Prefer seccomp() syscall if available, otherwise prctl(PR_SET_SECCOMP).
#ifdef SYS_seccomp
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, fprog) == -1) {
        pseudo_die("seccomp(SECCOMP_SET_MODE_FILTER)");
    }
#else
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, fprog) == -1) {
        pseudo_die("prctl(PR_SET_SECCOMP)");
    }
#endif
}