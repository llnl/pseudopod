// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#define _GNU_SOURCE
#include "internal/emulation.h"
#include <pseudo/log.h>
#include <pseudo/pseudo.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sched.h>

void pseudo_init_config(pseudo_config_t* cfg) {
    memset(cfg, 0, sizeof(pseudo_config_t));
    pseudo_cb_init(&cfg->cfg_syscall.cbs);
    pseudo_cb_init(&cfg->cfg_parent.cbs);
    pseudo_cb_init(&cfg->cfg_child.cbs);
    pseudo_cb_init(&cfg->cfg_tracer.cbs);
}

void pseudo_free_config(pseudo_config_t* cfg) {
    pseudo_cb_free(&cfg->cfg_syscall.cbs);
    pseudo_cb_free(&cfg->cfg_parent.cbs);
    pseudo_cb_free(&cfg->cfg_child.cbs);
    pseudo_cb_free(&cfg->cfg_tracer.cbs);
    memset(cfg, 0, sizeof(pseudo_config_t));
}

static void parent_exec_callbacks(pid_t child, const pseudo_config_parent_t* cfg) {
    pseudo_log_trace("parent_exec_callbacks: executing parent callbacks");
    for (int i = 0; i < cfg->cbs.len; i++) {
        pseudo_log_trace("parent_exec_callbacks: executing parent callback %d", i);
        void* cb_args = cfg->cbs.callbacks[i].cbargs;
        parent_cb_func_t* cb = (parent_cb_func_t*) cfg->cbs.callbacks[i].cb;
        if (cb(child, cb_args)) {
            pseudo_die("parent_exec_callbacks: post-clone callback returned nonzero");
        }
    }
    pseudo_log_trace("parent_exec_callbacks: parent callbacks succeded");
}

static void child_exec_callbacks(const pseudo_config_child_t* cfg) {
    pseudo_log_trace("child_exec_callbacks: executing callbacks");
    for (int i = 0; i < cfg->cbs.len; i++) {
        pseudo_log_debug("child_exec_callbacks: executing callback %d", i);
        void* cb_args = cfg->cbs.callbacks[i].cbargs;
        child_cb_func_t* cb = (child_cb_func_t*) cfg->cbs.callbacks[i].cb;
        if (cb(cb_args)) {
            pseudo_die("child_exec_callbacks: pre-exec callback returned nonzero");
        }
    }
    pseudo_log_trace("child_exec_callbacks: callbacks succeded");
}

static int child_exec(const pseudo_config_child_t* cfg) {
    pseudo_log_trace("child_exec: entrypoint");
    // continue to execvp target after parent sets up our environment

    char** envp = environ;
    if (cfg->child_envp) {
        envp = cfg->child_envp;
    }

    pseudo_log_debug("child_exec: exec");
    execvpe(cfg->child_argv[0], cfg->child_argv, envp);
    pseudo_die("execvp returned");
    return EXIT_FAILURE;
}

int pseudo_run(const pseudo_config_t* pseudo_cfg) {
    pseudo_log_debug("pseudo_run: start");

    pid_t child = pseudo_fork(pseudo_cfg);
    if (child == -1) {
        pseudo_die("fork");
    }
    pseudo_log_debug("pseudo_run: fork succeeded");

    if (child > 0) {
        // parent
        pseudo_log_debug("pseudo_run: handling events");
        pseudo_fork_wait(child, pseudo_cfg);
    } else if (child == 0) {
        // child
        pseudo_log_debug("pseudo_run: child_exec");
        child_exec(&pseudo_cfg->cfg_child); // does not return
    }
   return 0;
}

int pseudo_fork(const pseudo_config_t* pseudo_cfg) {
    pseudo_log_trace("pseudo_fork: entrypoint");

    pid_t child = -1;
    if ((child = fork()) == -1) {
        pseudo_log_perror(PSEUDO_LOGLEVEL_WARN, "fork");
    }
    
    if (child == 0) {
        if (unshare(pseudo_cfg->cfg_child.clone_flags) != 0) {
            pseudo_log_perror(PSEUDO_LOGLEVEL_ERROR, "unshare");
            pseudo_die("unshare failed");
        }

        pseudo_log_trace("pseudo_fork: child: raising SIGSTOP");
        raise(SIGSTOP);
        pseudo_log_trace("pseudo_fork: child: resuming from initial stop");

        // Execute child callbacks
        child_exec_callbacks(&pseudo_cfg->cfg_child);
    } else {
        pseudo_log_trace("pseudo_fork: parent: child pid is %d", child);

        // Execute parent callbacks (user-attached modules, e.g., virtid)
        parent_exec_callbacks(child, &pseudo_cfg->cfg_parent);
    }

    return child;
}

int pseudo_fork_wait(int child, const pseudo_config_t* pseudo_cfg) {
    pseudo_log_debug("pseudo_fork_wait: entering event loop");
    // Always run the tracing/event loop. If no handlers are attached,
    // it acts as a passthrough runner.
    int rv = handle_events(child, pseudo_cfg);
    pseudo_log_debug("pseudo_fork_wait: child exited with code: %d", rv);

    return rv;
}