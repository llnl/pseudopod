// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#define _GNU_SOURCE
#include "internal/containers.h"
#include "internal/log.h"
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

    for (int i = 0; i < cfg->cbs.len; i++) {
        DEBUG(stderr, "handle_syscall: executing callback %d\n", i);
        void* cb_args = cfg->cbs.callbacks[i].cbargs;
        syscall_cb_func_t* cb = (syscall_cb_func_t*) cfg->cbs.callbacks[i].cb;
        if (cb(pid, &sc_args, cb_args)) {
            die("handle_syscall: syscall callback returned nonzero");
        }
    }

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
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_OPTS) == -1) {
        if (errno != ESRCH) {
            DEBUG(stderr, "set_ptrace_opts: set options %d: %s\n", pid, strerror(errno));
            die("PTRACE_SETOPTIONS");
        }
    }
}

static void continue_tracee(pid_t pid, int sig) {
    if (ptrace(PTRACE_CONT, pid, 0, (void*)(long)sig) == -1) {
        if (errno != ESRCH) DEBUG(stderr, "continue_tracee: cont %d: %s\n", pid, strerror(errno));
    }
}

static void attach_child(pid_t newpid) {
    DEBUG(stderr, "attach_child: PTRACE_ATTACH: %d\n", newpid);
    // try to fallback to ATTACH
    if (ptrace(PTRACE_ATTACH, newpid, 0, 0) == -1) {
        DEBUG(stderr, "attach_child: attach %d failed: %s\n", newpid, strerror(errno));
        return;
    }
    int st;
    if (waitpid(newpid, &st, __WALL) == -1 && errno != ECHILD) {
        DEBUG(stderr, "attach_child: waitpid %d failed: %s\n", newpid, strerror(errno));
    }
    set_ptrace_opts(newpid);
}

#ifndef USE_RECURSIVE_ATTACH
static void seize_child(pid_t newpid) {
    if (ptrace(PTRACE_SEIZE, newpid, 0, PTRACE_OPTS) == -1) {
        if (errno == ESRCH || errno == EPERM) {
            DEBUG(stderr, "seize_child: PTRACE_SEIZE failed on PID: %d : %s\n", newpid, strerror(errno));
            // likely exited already or not attachable
            return;
        }
        attach_child(newpid);
    } else {
        DEBUG(stderr, "seize_child: PTRACE_SEIZE: %d\n", newpid);
    }
}
#endif

struct exec_args {
    const pseudo_config_child_t* params;
    int virt_enabled;
};

static int child_exec(void *v_args) {
    const pseudo_config_child_t* cfg = (const pseudo_config_child_t*) v_args;
    // continue to execvp target after parent sets up our environment
    raise(SIGSTOP);

    DEBUG(stderr, "child_exec: resuming from initial stop\n");
    for (int i = 0; i < cfg->cbs.len; i++) {
        DEBUG(stderr, "child_exec: executing callback %d\n", i);
        void* cb_args = cfg->cbs.callbacks[i].cbargs;
        child_cb_func_t* cb = (child_cb_func_t*) cfg->cbs.callbacks[i].cb;
        if (cb(cb_args)) {
            die("child_exec: pre-exec callback returned nonzero");
        }
    }
    DEBUG(stderr, "child_exec: callbacks succeded\n");

    char** envp = environ;
    if (cfg->child_envp) {
        envp = cfg->child_envp;
    }

    if (cfg->filters) {
        DEBUG(stderr, "child_exec: installing seccomp filters\n");
        set_no_new_privs();
        for (int i = 0;; i++) {
            const seccomp_fprog* fprog = cfg->filters[i];
            if (cfg->filters[i]) {
                DEBUG(stderr, "child_exec: install filter #%d\n", i);
                install_filter(fprog);
            } else {
                break;
            }
        }
        DEBUG(stderr, "child_exec: seccomp done\n");
    }

    DEBUG(stderr, "child_exec: exec\n");
    execvpe(cfg->child_argv[0], cfg->child_argv, envp);
    perror("execvp");
    _exit(127);
}

int do_clone(const pseudo_config_child_t* cfg) {
    pid_t child = -1;
    long pgsz = sysconf(_SC_PAGESIZE);
    if (pgsz == -1) {
        perror("sysconf");
        pgsz = 4096;
    }

    long stack_size = pgsz * 8;
    char* stack = (char*)mmap(0, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (stack == MAP_FAILED) {
        die("mmap");
    }
    char* stack_top = &stack[stack_size];
    if ((child = clone(child_exec, (void*)stack_top, SIGCHLD | cfg->clone_flags, (void*) cfg)) == -1) {
        perror("clone");
        return child;
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

        for (int i = 0; i < cfg->cfg_tracer.cbs.len; i++) {
            DEBUG(stderr, "handle_events: executing callback %d\n", i);
            void* cb_args = cfg->cfg_tracer.cbs.callbacks[i].cbargs;
            tracer_cb_func_t* cb = (tracer_cb_func_t*) cfg->cfg_tracer.cbs.callbacks[i].cb;
            if (cb(pid, status, cb_args)) {
                die("handle_events: tracer callback returned nonzero");
            }
        }

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
                    DEBUG(stderr, "handle_events: caught syscall\n");
                    if (handle_syscall(&cfg->cfg_syscall, pid) == -1) {
                        perror("handle_syscall");
                    }
                    continue_tracee(pid, 0);
                    continue;
                }
            }

            int fwd_sig = 0;
            if (sig != SIGTRAP && sig != SIGSTOP) { fwd_sig = sig; }
            DEBUG(stderr, "handle_events: resume child %d\n", pid);
            continue_tracee(pid, fwd_sig);
        }
    }
    return EXIT_SUCCESS;
}
