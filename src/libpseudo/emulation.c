// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#define _GNU_SOURCE
#include <pseudo/log.h>
#include <handlers/idtrack.h>
#include <pseudo/syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/ptrace.h>
#include <signal.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int handle_syscall(pseudo_config_syscall_t* cfg, pid_t pid) {
    syscall_ctx_t sc_args;
    syscall_get_regs(pid, &sc_args);

    log_trace("handle_syscall: executing callbacks");
    for (int i = 0; i < cfg->cbs.len; i++) {
        log_debug("handle_syscall: executing callback %d", i);
        void* cb_args = cfg->cbs.callbacks[i].cbargs;
        syscall_cb_func_t* cb = (syscall_cb_func_t*) cfg->cbs.callbacks[i].cb;
        if (cb(pid, &sc_args, cb_args)) {
            die("handle_syscall: syscall callback returned nonzero");
        }
    }
    log_trace("handle_syscall: callbacks succeded");

    syscall_set_regs(pid, &sc_args);
    return 0;
}

static const int PTRACE_OPTS=PTRACE_O_TRACEFORK
                        | PTRACE_O_TRACEVFORK
                        | PTRACE_O_TRACECLONE
                        | PTRACE_O_TRACEEXEC
                        | PTRACE_O_TRACEEXIT
                        | PTRACE_O_TRACESECCOMP
                        | PTRACE_O_EXITKILL;

static void set_ptrace_opts(pid_t pid) {
    log_trace("set_ptrace_opts: target=%d", pid);
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_OPTS) == -1) {
        if (errno != ESRCH) {
            log_debug("set_ptrace_opts: set options %d: %s", pid, strerror(errno));
            die("PTRACE_SETOPTIONS");
        }
    }
}

static void continue_tracee(pid_t pid, int sig) {
    log_trace("continue_tracee: target=%d sig=%d", pid, sig);
    if (ptrace(PTRACE_CONT, pid, 0, (void*)(long)sig) == -1) {
        if (errno != ESRCH) log_debug("continue_tracee: cont %d: %s", pid, strerror(errno));
    }
}

static void attach_child(pid_t newpid) {
    log_trace("attach_child: PTRACE_ATTACH: %d", newpid);
    // try to fallback to ATTACH
    if (ptrace(PTRACE_ATTACH, newpid, 0, 0) == -1) {
        log_debug("attach_child: attach %d failed: %s", newpid, strerror(errno));
        return;
    }
    int st;
    if (waitpid(newpid, &st, __WALL) == -1 && errno != ECHILD) {
        log_debug("attach_child: waitpid %d failed: %s", newpid, strerror(errno));
    }
    set_ptrace_opts(newpid);
}

static void seize_child(pid_t newpid) {
    if (ptrace(PTRACE_SEIZE, newpid, 0, PTRACE_OPTS) == -1) {
        if (errno == ESRCH || errno == EPERM) {
            log_warn("seize_child: PTRACE_SEIZE failed on PID: %d : %s", newpid, strerror(errno));
            // likely exited already or not attachable
            return;
        }
        attach_child(newpid);
    } else {
        log_trace("seize_child: PTRACE_SEIZE: %d", newpid);
    }
}

struct exec_args {
    const pseudo_config_child_t* params;
    int virt_enabled;
};

static int child_exec(void *v_args) {
    log_trace("child_exec: entrypoint");
    const pseudo_config_child_t* cfg = (const pseudo_config_child_t*) v_args;
    // continue to execvp target after parent sets up our environment
    log_trace("child_exec: raising SIGSTOP");
    raise(SIGSTOP);
    log_trace("child_exec: resuming from initial stop");

    log_trace("child_exec: executing callbacks");
    for (int i = 0; i < cfg->cbs.len; i++) {
        log_debug("child_exec: executing callback %d", i);
        void* cb_args = cfg->cbs.callbacks[i].cbargs;
        child_cb_func_t* cb = (child_cb_func_t*) cfg->cbs.callbacks[i].cb;
        if (cb(cb_args)) {
            die("child_exec: pre-exec callback returned nonzero");
        }
    }
    log_trace("child_exec: callbacks succeded");

    char** envp = environ;
    if (cfg->child_envp) {
        envp = cfg->child_envp;
    }

    if (cfg->filters) {
        log_trace("child_exec: installing seccomp filters");
        set_no_new_privs();
        for (int i = 0;; i++) {
            const seccomp_fprog* fprog = cfg->filters[i];
            if (cfg->filters[i]) {
                log_trace("child_exec: install filter #%d", i);
                install_filter(fprog);
            } else {
                break;
            }
        }
        log_trace("child_exec: seccomp done");
    }

    log_debug("child_exec: exec");
    execvpe(cfg->child_argv[0], cfg->child_argv, envp);
    die("execvp returned");
    return EXIT_FAILURE;
}

int do_clone(const pseudo_config_child_t* cfg) {
    pid_t child = -1;
    long pgsz = sysconf(_SC_PAGESIZE);
    if (pgsz == -1) {
        log_perror(LOG_WARN, "sysconf");
        pgsz = 4096;
        log_warn("Setting pagesize to default (%d)", pgsz);
    }

    long stack_size = pgsz * 8;
    char* stack = (char*)mmap(0, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (stack == MAP_FAILED) {
        die("mmap");
    }
    char* stack_top = &stack[stack_size];
    if ((child = clone(child_exec, (void*)stack_top, SIGCHLD | cfg->clone_flags, (void*) cfg)) == -1) {
        log_perror(LOG_WARN, "clone");
    }
    return child;
}

int handle_events(pid_t child, pseudo_config_t* cfg) {
    int status = 0;
    // attach to initial child while it's in SIGSTOP
    // children should be attached and traced automatically if we use SEIZE
    seize_child(child);
    continue_tracee(child, 0);

    for (;;) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid == -1) {
            if (errno == EINTR) { continue; }
            if (errno == ECHILD) { break; }
            die("waitpid loop");
        }

        log_trace("handle_events: executing callbacks");
        for (int i = 0; i < cfg->cfg_tracer.cbs.len; i++) {
            log_trace("handle_events: executing callback %d", i);
            void* cb_args = cfg->cfg_tracer.cbs.callbacks[i].cbargs;
            tracer_cb_func_t* cb = (tracer_cb_func_t*) cfg->cfg_tracer.cbs.callbacks[i].cb;
            if (cb(pid, status, cb_args)) {
                die("handle_events: tracer callback returned nonzero");
            }
        }
        log_trace("handle_events: callbacks succeded");

        if (WIFEXITED(status)) {
            continue;
        }
        if (WIFSIGNALED(status)) {
            continue;
        }
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            unsigned event = 0;
            if (sig == SIGTRAP) {
                event = (unsigned)((status >> 16) & 0xffff);
                if (event == PTRACE_EVENT_SECCOMP) {
                    log_debug("handle_events: caught syscall");
                    if (handle_syscall(&cfg->cfg_syscall, pid) == -1) {
                        log_perror(LOG_WARN, "handle_syscall");
                    }
                    continue_tracee(pid, 0);
                    continue;
                }
            }

            int fwd_sig = 0;
            if (sig != SIGTRAP && sig != SIGSTOP) { fwd_sig = sig; }
            log_trace("handle_events: resume child %d", pid);
            continue_tracee(pid, fwd_sig);
        }
    }
    return EXIT_SUCCESS;
}
