// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <signal.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include <pseudo/pseudo.h>
#include <pseudo/log.h>
#include <handlers/idtrack.h>
#include <pseudo/syscall.h>

static inline int handle_syscall(const pseudo_config_syscall_t* cfg, pid_t pid) {
    syscall_ctx_t sc_args;
    if (syscall_get_regs(pid, &sc_args) == -1) return -1;

    pseudo_log_trace("handle_syscall: executing callbacks");
    for (int i = 0; i < cfg->cbs.len; i++) {
        pseudo_log_debug("handle_syscall: executing callback %d", i);
        void* cb_args = cfg->cbs.callbacks[i].cbargs;
        syscall_cb_func_t* cb = (syscall_cb_func_t*) cfg->cbs.callbacks[i].cb;
        if (cb(pid, &sc_args, cb_args)) {
            pseudo_die("handle_syscall: syscall callback returned nonzero");
        }
    }
    pseudo_log_trace("handle_syscall: callbacks succeded");

    if (syscall_set_regs(pid, &sc_args) == -1) return -1;
    return 0;
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

static const int PTRACE_OPTS=PTRACE_O_TRACEFORK
                        | PTRACE_O_TRACEVFORK
                        | PTRACE_O_TRACECLONE
                        | PTRACE_O_TRACEEXEC
                        | PTRACE_O_TRACEEXIT
                        | PTRACE_O_TRACESECCOMP
                        | PTRACE_O_EXITKILL;

static inline void set_ptrace_opts(pid_t pid) {
    pseudo_log_trace("set_ptrace_opts: target=%d", pid);
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_OPTS) == -1) {
        if (errno != ESRCH) {
            pseudo_log_debug("set_ptrace_opts: set options %d: %s", pid, strerror(errno));
            pseudo_die("PTRACE_SETOPTIONS");
        }
    }
}

static inline void continue_tracee(pid_t pid, int sig) {
    pseudo_log_trace("continue_tracee: target=%d sig=%d", pid, sig);
    if (ptrace(PTRACE_CONT, pid, 0, (void*)(long)sig) == -1) {
        if (errno != ESRCH) pseudo_log_debug("continue_tracee: cont %d: %s", pid, strerror(errno));
    }
}

static inline void attach_child(pid_t newpid) {
    pseudo_log_trace("attach_child: PTRACE_ATTACH: %d", newpid);
    // try to fallback to ATTACH
    if (ptrace(PTRACE_ATTACH, newpid, 0, 0) == -1) {
        pseudo_log_debug("attach_child: attach %d failed: %s", newpid, strerror(errno));
        return;
    }
    int st;
    if (waitpid(newpid, &st, __WALL) == -1 && errno != ECHILD) {
        pseudo_log_debug("attach_child: waitpid %d failed: %s", newpid, strerror(errno));
    }
    set_ptrace_opts(newpid);
}

static inline void seize_child(pid_t newpid) {
    if (ptrace(PTRACE_SEIZE, newpid, 0, PTRACE_OPTS) == -1) {
        if (errno == ESRCH || errno == EPERM) {
            pseudo_log_warn("seize_child: PTRACE_SEIZE failed on PID: %d : %s", newpid, strerror(errno));
            // likely exited already or not attachable
            return;
        }
        attach_child(newpid);
    } else {
        pseudo_log_trace("seize_child: PTRACE_SEIZE: %d", newpid);
    }
}

// wait for initial child to SIGSTOP and attach
static void attach_initial_child(pid_t child, const pseudo_config_t* cfg) {
    // children should automatically inherit this process as a ptracer
    seize_child(child);

    int status = 0;
    for (;;) {
        pid_t pid = waitpid(child, &status, __WALL);
        if (pid == -1) {
            if (errno == EINTR) { continue; }
            pseudo_log_perror(PSEUDO_LOGLEVEL_ERROR, "attach_initial_child: waitpid");
            pseudo_die("attach_initial_child: initial waitpid failed");
        }
        break;
    }

    if (WIFSTOPPED(status)) {
        // Execute parent callbacks (user-attached modules, e.g., virtid)
        parent_exec_callbacks(child, &cfg->cfg_parent);
        continue_tracee(child, 0);
    } else if (WIFEXITED(status)) {
        pseudo_log_error("attach_initial_child: child exited with status %d", WEXITSTATUS(status));
        pseudo_die("attach_initial_child failed");
    } else {
        pseudo_die("attach_initial_child: invalid child state");
    }
}

int handle_events(pid_t child, const pseudo_config_t* cfg) {
    int status = 0;
    int last_return = -1;
    
    attach_initial_child(child, cfg);
    
    for (;;) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid == -1) {
            if (errno == EINTR) { continue; }
            if (errno == ECHILD) { break; }
            pseudo_die("waitpid loop");
        }
        pseudo_log_trace("handle_events: caught pid %d", pid);

        pseudo_log_trace("handle_events: executing callbacks");
        for (int i = 0; i < cfg->cfg_tracer.cbs.len; i++) {
            pseudo_log_trace("handle_events: executing callback %d", i);
            void* cb_args = cfg->cfg_tracer.cbs.callbacks[i].cbargs;
            tracer_cb_func_t* cb = (tracer_cb_func_t*) cfg->cfg_tracer.cbs.callbacks[i].cb;
            if (cb(pid, status, cb_args)) {
                pseudo_die("handle_events: tracer callback returned nonzero");
            }
        }
        pseudo_log_trace("handle_events: callbacks succeded");

        if (WIFEXITED(status)) {
            last_return = WEXITSTATUS(status);
            pseudo_log_trace("handle_events: pid %d: exited", pid);
            continue;
        }
        if (WIFSIGNALED(status)) {
            pseudo_log_trace("handle_events: pid %d: signaled", pid);
            continue;
        }
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            pseudo_log_trace("handle_events: pid %d: stopped: signal=%d", pid, sig);
            unsigned event = 0;
            if (sig == SIGTRAP) {
                event = (unsigned)((status >> 16) & 0xffff);
                pseudo_log_trace("handle_events: pid %d: SIGTRAP event=%d", pid, sig, event);
                switch (event) {
                    case PTRACE_EVENT_SECCOMP:
                     pseudo_log_debug("handle_events: caught syscall");
                    if (handle_syscall(&cfg->cfg_syscall, pid) == -1) {
                        pseudo_log_perror(PSEUDO_LOGLEVEL_WARN, "handle_syscall");
                    }
                    // fallthrough
                default:
                    // eat unknown SIGTRAP events
                    continue_tracee(pid, 0);
                    continue;
                }
            }

            int fwd_sig = 0;
            if (sig != SIGTRAP && sig != SIGSTOP) { fwd_sig = sig; }
            pseudo_log_trace("handle_events: resume child %d", pid);
            continue_tracee(pid, fwd_sig);
        }
    }
    return last_return;
}
