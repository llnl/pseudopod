// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#include "libpseudo/internal/id_t.h"
#include "libpseudo/internal/log.h"
#include "handlers/virtid.h"
#include <pseudo/pseudo.h>
#include <pseudo/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define ID_UNCHANGED 0xFFFFFFFF
#define ID_MAX 0xFFFFFFFF

virtid_callbacks_t virtid_callbacks(idtrack_t* id_states)
{
    virtid_callbacks_t out;
    memset(&out, 0, sizeof(out));

    /* parent: seed base + unshare to child */
    out.parent.cb     = (void*)virtid_parent_cb;
    out.parent.cbargs = (void*)id_states;

    /* tracer: fork/clone unshare + exit cleanup */
    out.tracer.cb     = (void*)handle_trace_events;
    out.tracer.cbargs = (void*)id_states;

    /* syscall: uid/gid virtualization */
    out.syscall.cb     = (void*)handle_uid_syscalls;
    out.syscall.cbargs = (void*)id_states;

    return out;
}

static int virtid_parent_cb(pid_t child, void* cb_args)
{
    idtrack_t* id_states = (idtrack_t*)cb_args;
    pid_t parent = getpid();

    id_state_t* base = get_id_state(id_states, parent);
    if (!base) {
        die("virtid: Failed to get base ID state.");
    }

    /* Seed from tracker-owned base_id */
    memcpy(base, &id_states->base_id, sizeof(*base));

    /* Give child its own copy of the parent’s state */
    unshare_id_state(id_states, parent, child);
    return 0;
}

// Private

static inline void handle_setid(syscall_ctx_t* sc, id_state_t* idstate, int isgid) {
    sc->no = -1;
    uint64_t newv = sc->args[0];
    if (newv > ID_MAX) {
        sc->ret = (unsigned long long)-EINVAL;
        return;
    }
    if (idstate->id[0].effective == 0) {
      idstate->id[isgid].real = idstate->id[isgid].saved = (uint32_t)newv;
    }
    idstate->id[isgid].effective = (uint32_t)newv;
    sc->ret = 0;
}

static inline void handle_setreid(syscall_ctx_t* sc, ids_t* id) {
    sc->no = -1;
    uint64_t new_real      = sc->args[0];
    uint64_t new_effective = sc->args[1];

    if (new_effective != ID_UNCHANGED) {
        if (new_effective > ID_MAX) {
            sc->ret = (unsigned long long)-EINVAL;
            return;
        }
        id->effective = (uint32_t)new_effective;
        if (id->effective != id->real) id->saved = id->effective;
    }
    if (new_real != ID_UNCHANGED) {
        if (new_real > ID_MAX) {
            sc->ret = (unsigned long long)-EINVAL;
            return;
        }
        id->real = (uint32_t)new_real;
        id->saved = id->effective;
    }
    sc->ret = 0;
}

static inline void handle_setresid(syscall_ctx_t* sc, ids_t* id) {
    sc->no = -1;
    uint64_t new_real      = sc->args[0];
    uint64_t new_effective = sc->args[1];
    uint64_t new_saved     = sc->args[2];

    if (new_real      > ID_MAX ||
        new_effective > ID_MAX ||
        new_saved     > ID_MAX) {
        sc->ret = (unsigned long long)-EINVAL;
        return;
    }

    if (new_real      != ID_UNCHANGED) id->real      = (uint32_t)new_real;
    if (new_effective != ID_UNCHANGED) id->effective = (uint32_t)new_effective;
    if (new_saved     != ID_UNCHANGED) id->saved     = (uint32_t)new_saved;
    sc->ret = 0;
}

static inline void handle_getresid(pid_t pid, syscall_ctx_t* sc, ids_t* id) {
    int err = 0;
    if (!sc->args[0] || !sc->args[1] || !sc->args[2]) {
        err = EFAULT;
    } else {
        if (write_u32_to_child(pid, sc->args[0], id->real)  == -1)     err = EFAULT;
        if (write_u32_to_child(pid, sc->args[1], id->effective) == -1) err = EFAULT;
        if (write_u32_to_child(pid, sc->args[2], id->saved) == -1)     err = EFAULT;
    }
    sc->no = -1;
    sc->ret = err ? (unsigned long long)-err : 0;
}

int handle_uid_syscalls(pid_t pid, syscall_ctx_t* sc, void* v_args) {
    idtrack_t* id_states = (idtrack_t*) v_args;
    id_state_t *id_state = get_id_state(id_states, pid);
    switch (sc->no) {
      case __NR_setuid:
        DEBUG(stderr, "setuid: %lu\n", (unsigned long)sc->args[0]);
        handle_setid(sc, id_state, 0);
        break;
      case __NR_setreuid:
        DEBUG(stderr, "setreuid: %lu %lu\n", (unsigned long)sc->args[0], (unsigned long)sc->args[1]);
        handle_setreid(sc, &id_state->id[0]);
        break;
      case __NR_setresuid:
        DEBUG(stderr, "setresuid: %lu %lu %lu\n", (unsigned long)sc->args[0], (unsigned long)sc->args[1], (unsigned long)sc->args[2]);
        handle_setresid(sc, &id_state->id[0]);
        break;
      case __NR_setgid:
        DEBUG(stderr, "setgid: %lu\n", (unsigned long)sc->args[0]);
        handle_setid(sc, id_state, 1);
        break;
      case __NR_setregid:
        DEBUG(stderr, "setregid: %lu %lu\n", (unsigned long)sc->args[0], (unsigned long)sc->args[1]);
        handle_setreid(sc, &id_state->id[1]);
        break;
      case __NR_setresgid:
        DEBUG(stderr, "setresgid: %lu %lu %lu\n", (unsigned long)sc->args[0], (unsigned long)sc->args[1], (unsigned long)sc->args[2]);
        handle_setresid(sc, &id_state->id[1]);
        break;
      case __NR_getuid:
        DEBUG(stderr, "getuid: %lu\n", (unsigned long)id_state->id[0].real);
        sc->ret = id_state->id[0].real;
        sc->no = -1;
        break;
      case __NR_geteuid:
        DEBUG(stderr, "geteuid: %lu\n", (unsigned long)id_state->id[0].effective);
        sc->ret = id_state->id[0].effective;
        sc->no = -1;
        break;
      case __NR_getgid:
        DEBUG(stderr, "getgid: %lu\n", (unsigned long)id_state->id[1].real);
        sc->ret = id_state->id[1].real;
        sc->no = -1;
        break;
      case __NR_getegid:
        DEBUG(stderr, "getegid: %lu\n", (unsigned long)id_state->id[1].effective);
        sc->ret = id_state->id[1].effective;
        sc->no = -1;
        break;
      case __NR_getresuid: {
        DEBUG(stderr, "getresuid: %lu %lu %lu\n",
              (unsigned long)id_state->id[0].real,
              (unsigned long)id_state->id[0].effective,
              (unsigned long)id_state->id[0].saved);
        handle_getresid(pid, sc, &id_state->id[0]);
        break;
      }
      case __NR_getresgid: {
        DEBUG(stderr, "getresgid: %lu %lu %lu\n",
              (unsigned long)id_state->id[1].real,
              (unsigned long)id_state->id[1].effective,
              (unsigned long)id_state->id[1].saved);
        handle_getresid(pid, sc, &id_state->id[1]);
        break;
      }
      default:
        // ignore
        break;
    }
    return 0;
}

static int handle_trace_events(pid_t pid, int status, void* cb_args) {
    idtrack_t* id_states = (idtrack_t*)cb_args;
    if (WIFEXITED(status)) {
        erase_id_state(id_states, pid);
    }
    else if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        unsigned event = 0;
        if (sig == SIGTRAP) {
            event = (unsigned)((status >> 16) & 0xffff);
            if (event == PTRACE_EVENT_FORK ||
                event == PTRACE_EVENT_VFORK ||
                event == PTRACE_EVENT_CLONE) {
                unsigned long newpid = 0;
                if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &newpid) == -1) {
                    perror("PTRACE_GETEVENTMSG");
                } else {
                    DEBUG(stderr, "virtid_trace: unshare id state\n");
                    unshare_id_state(id_states, pid, newpid);
                }
            }
        }
    }
    return 0;
}
