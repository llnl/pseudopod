// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#include <handlers/idtrack.h>
#include <pseudo/log.h>
#include <handlers/virtid.h>
#include <unistd.h>
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

_idst_l2* idst_get_l2d(idtrack_t* idstates, pid_t pid) {
    int l1i = pid >> IDST_L1_BITS;
    _idst_l2 *l2d = idstates->l1[l1i];
    if (!l2d) {
        l2d = (_idst_l2*) malloc(sizeof(_idst_l2));
        if (!l2d) {
            die("idst_get_l2d: failed to allocate memory: ");
        }
        memset(l2d, 0, sizeof(_idst_l2));
        idstates->l1[l1i] = l2d;
    }
    return idstates->l1[l1i];
}

_idst_leaf* idst_get_leaf(idtrack_t* idstates, pid_t pid) {
    int l2i = pid & L2_MASK;
    _idst_l2 *l1d = idst_get_l2d(idstates, pid);
    return &l1d->l2[l2i];
}

id_state_t* get_id_state(idtrack_t* idstates, pid_t pid) {
    _idst_leaf *l2e = idst_get_leaf(idstates, pid);
    return &l2e->v;
}

id_state_t* unshare_id_state(idtrack_t* idstates, pid_t old_pid, pid_t new_pid) {
    id_state_t* r = get_id_state(idstates, old_pid);
    id_state_t* l = get_id_state(idstates, new_pid);
    memcpy(l, r, sizeof(id_state_t));
    return l;
}

void erase_id_state(idtrack_t* idstates, pid_t pid) {
    _idst_leaf *l2e = idst_get_leaf(idstates, pid);
    l2e->valid = 0;
    memset(&l2e->v, 0, sizeof(id_state_t));
}

// Callback manager

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
        log_trace("setuid: %lu", (unsigned long)sc->args[0]);
        handle_setid(sc, id_state, 0);
        break;
      case __NR_setreuid:
        log_trace("setreuid: %lu %lu", (unsigned long)sc->args[0], (unsigned long)sc->args[1]);
        handle_setreid(sc, &id_state->id[0]);
        break;
      case __NR_setresuid:
        log_trace("setresuid: %lu %lu %lu", (unsigned long)sc->args[0], (unsigned long)sc->args[1], (unsigned long)sc->args[2]);
        handle_setresid(sc, &id_state->id[0]);
        break;
      case __NR_setgid:
        log_trace("setgid: %lu", (unsigned long)sc->args[0]);
        handle_setid(sc, id_state, 1);
        break;
      case __NR_setregid:
        log_trace("setregid: %lu %lu", (unsigned long)sc->args[0], (unsigned long)sc->args[1]);
        handle_setreid(sc, &id_state->id[1]);
        break;
      case __NR_setresgid:
        log_trace("setresgid: %lu %lu %lu", (unsigned long)sc->args[0], (unsigned long)sc->args[1], (unsigned long)sc->args[2]);
        handle_setresid(sc, &id_state->id[1]);
        break;
      case __NR_getuid:
        log_trace("getuid: %lu", (unsigned long)id_state->id[0].real);
        sc->ret = id_state->id[0].real;
        sc->no = -1;
        break;
      case __NR_geteuid:
        log_trace("geteuid: %lu", (unsigned long)id_state->id[0].effective);
        sc->ret = id_state->id[0].effective;
        sc->no = -1;
        break;
      case __NR_getgid:
        log_trace("getgid: %lu", (unsigned long)id_state->id[1].real);
        sc->ret = id_state->id[1].real;
        sc->no = -1;
        break;
      case __NR_getegid:
        log_trace("getegid: %lu", (unsigned long)id_state->id[1].effective);
        sc->ret = id_state->id[1].effective;
        sc->no = -1;
        break;
      case __NR_getresuid: {
        log_trace("getresuid: %lu %lu %lu",
              (unsigned long)id_state->id[0].real,
              (unsigned long)id_state->id[0].effective,
              (unsigned long)id_state->id[0].saved);
        handle_getresid(pid, sc, &id_state->id[0]);
        break;
      }
      case __NR_getresgid: {
        log_trace("getresgid: %lu %lu %lu",
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
                    log_perror(LOG_ERROR, "PTRACE_GETEVENTMSG");
                } else {
                    log_debug("virtid_trace: unshare id state");
                    unshare_id_state(id_states, pid, newpid);
                }
            }
        }
    }
    return 0;
}

// Public

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

void virtid_attach_handlers(pseudo_config_t* cfg, idtrack_t* id_states) {
    virtid_callbacks_t v = virtid_callbacks(id_states);
    pseudo_cb_adds(&cfg->cfg_parent.cbs,  &v.parent);
    pseudo_cb_adds(&cfg->cfg_tracer.cbs,  &v.tracer);
    pseudo_cb_adds(&cfg->cfg_syscall.cbs, &v.syscall);
}
