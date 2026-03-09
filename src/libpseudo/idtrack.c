// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#define _GNU_SOURCE
#include "internal/id_t.h"
#include "internal/log.h"
#include <stdlib.h>
#include <string.h>

// ID state tracker

idtrack_t* idtrack_init() {
    idtrack_t* idt = (idtrack_t*) malloc(sizeof(idtrack_t));
    if (!idt) {
        die("get_id_tracker: failed to allocate memory: ");
    }
    memset(idt, 0, sizeof(idtrack_t));
    return idt;
}

void idtrack_free(idtrack_t* id_states) {
    for (int i = 0; i < IDST_L1_SZ; i++) {
        if (id_states->l1[i]) {
            free(&id_states->l1[i]);
            id_states->l1[i] = 0;
        }
    }
}

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

void _pseudo_cb_grow(pseudo_callbacks_t* cbs) {
    cbs->callbacks = (pseudo_cb_t*) reallocarray(cbs->callbacks, cbs->size+8, sizeof(pseudo_cb_t));
    if (!cbs->callbacks) {
        die("_pseudo_cb_grow: failed to allocate memory: ");
    }
    cbs->size += 8;
}

void pseudo_cb_init(pseudo_callbacks_t* cbs) {
    memset(cbs, 0, sizeof(pseudo_callbacks_t));
    _pseudo_cb_grow(cbs);
}

void pseudo_cb_free(pseudo_callbacks_t* cbs) {
    free(cbs->callbacks);
    cbs->len = 0;
    cbs->size = 0;
}

void pseudo_cb_adds(pseudo_callbacks_t* cbs, const pseudo_cb_t* pseudo_cb){
    while (cbs->len >= cbs->size) {
        _pseudo_cb_grow(cbs);
    }
    memcpy(&cbs->callbacks[cbs->len], pseudo_cb, sizeof(pseudo_cb_t));
    cbs->len += 1;
}

void pseudo_cb_add(pseudo_callbacks_t* cbs, void* cb, void* cb_args) {
    pseudo_cb_t mb = {cb, cb_args};
    pseudo_cb_adds(cbs, &mb);
}
