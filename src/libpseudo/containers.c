// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod
// Contributors. See top-level LICENSE and COPYRIGHT files for dates and
// other details.

// SPDX-License-Identifier: (Apache-2.0)

// This file Implements the ID‑state container and the callback manager used
// by the pseudo library.

#include "internal/containers.h"
#include <stdlib.h>
#include <string.h>


// ID‑state container (C implementation)

typedef struct {
    pid_t      pid;
    id_state_t state;
} id_state_entry_t;

typedef struct {
    id_state_entry_t *entries;
    size_t            len;
    size_t            capacity;
} id_state_container_c;

/* Helper: ensure that the container has at least `needed` slots. */
static int ensure_capacity(id_state_container_c *c, size_t needed)
{
    if (c->capacity >= needed) {
        return 0;
    }

    size_t new_cap = c->capacity ? c->capacity * 2 : 8;
    while (new_cap < needed) {
        new_cap *= 2;
    }

    id_state_entry_t *new_arr = realloc(c->entries,
                                        new_cap * sizeof(*new_arr));
    if (!new_arr) {
        return -1;
    }

    c->entries   = new_arr;
    c->capacity  = new_cap;
    return 0;
}

/* Linear search for an entry with the given PID. */
static id_state_entry_t *find_entry(id_state_container_c *c, pid_t pid)
{
    for (size_t i = 0; i < c->len; ++i) {
        if (c->entries[i].pid == pid) {
            return &c->entries[i];
        }
    }
    return NULL;
}

/* Retrieve (or lazily create) the state associated with `pid`. */
static id_state_t *container_get(id_state_container_c *c, pid_t pid)
{
    id_state_entry_t *e = find_entry(c, pid);
    if (e) {
        return &e->state;
    }

    /* Create a new entry. */
    if (ensure_capacity(c, c->len + 1) != 0) {
        return NULL;
    }

    e          = &c->entries[c->len];
    e->pid     = pid;
    memset(&e->state, 0, sizeof(e->state));
    c->len++;

    return &e->state;
}

/* Copy the state from `old_pid` to `new_pid`. */
static id_state_t *container_unshare(id_state_container_c *c,
                                     pid_t                old_pid,
                                     pid_t                new_pid)
{
    id_state_t *old_state = container_get(c, old_pid);
    if (!old_state) {
        return NULL;
    }

    id_state_t *new_state = container_get(c, new_pid);
    if (!new_state) {
        return NULL;
    }

    *new_state = *old_state;
    return new_state;
}

/* Remove the entry for `pid` from the container. */
static void container_invalidate(id_state_container_c *c, pid_t pid)
{
    for (size_t i = 0; i < c->len; ++i) {
        if (c->entries[i].pid == pid) {
            /* Swap with the last entry and shrink the array. */
            c->entries[i] = c->entries[c->len - 1];
            c->len--;
            return;
        }
    }
}


 // Callback manager (C implementation)

typedef struct {
    pseudo_cb_t        *array;
    size_t              len;
    size_t              capacity;
    pseudo_callbacks_t *managed;
} callback_manager_c;

static int cb_ensure_capacity(callback_manager_c *m, size_t needed)
{
    if (m->capacity >= needed) {
        return 0;
    }

    size_t new_cap = m->capacity ? m->capacity * 2 : 8;
    while (new_cap < needed) {
        new_cap *= 2;
    }

    pseudo_cb_t *new_arr = realloc(m->array, new_cap * sizeof(*new_arr));
    if (!new_arr) {
        return -1;
    }

    m->array    = new_arr;
    m->capacity = new_cap;
    return 0;
}

/* Keep the public `pseudo_callbacks_t` in sync with the manager. */
static int cb_update_managed(callback_manager_c *m)
{
    m->managed->callbacks = m->array;
    m->managed->len       = m->len;
    return 0;
}

/* Add a new callback to the manager. */
static int cb_add(callback_manager_c *m, const pseudo_cb_t *cb)
{
    if (cb_ensure_capacity(m, m->len + 1) != 0) {
        return -1;
    }

    m->array[m->len++] = *cb;
    return cb_update_managed(m);
}


// C API (extern "C" compatible)

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle for the ID‑state container */
struct id_state_container_t {
    void *impl;   /* points to id_state_container_c */
};

idtrack_t *get_id_tracker(void)
{
    idtrack_t *t = malloc(sizeof(*t));
    if (!t) {
        return NULL;
    }

    id_state_container_c *c = malloc(sizeof(*c));
    if (!c) {
        free(t);
        return NULL;
    }

    c->entries   = NULL;
    c->len       = 0;
    c->capacity  = 0;

    t->impl = c;
    return t;
}

void free_id_tracker(idtrack_t *id_states)
{
    if (!id_states) {
        return;
    }

    id_state_container_c *c = (id_state_container_c *)id_states->impl;
    free(c->entries);
    free(c);
    free(id_states);
}

id_state_t *get_id_state(idtrack_t *idstates, pid_t pid)
{
    if (!idstates) {
        return NULL;
    }

    id_state_container_c *c = (id_state_container_c *)idstates->impl;
    return container_get(c, pid);
}

id_state_t *unshare_id_state(idtrack_t *idstates,
                             pid_t       old_pid,
                             pid_t       new_pid)
{
    if (!idstates) {
        return NULL;
    }

    id_state_container_c *c = (id_state_container_c *)idstates->impl;
    return container_unshare(c, old_pid, new_pid);
}

void erase_id_state(idtrack_t *idstates, pid_t pid)
{
    if (!idstates) {
        return;
    }

    id_state_container_c *c = (id_state_container_c *)idstates->impl;
    container_invalidate(c, pid);
}

// Callback handling


void pseudo_cb_init(pseudo_callbacks_t *cbs)
{
    if (!cbs) {
        return;
    }

    callback_manager_c *mgr = malloc(sizeof(*mgr));
    if (!mgr) {
        return;   /* out of memory – leave `cbs` untouched */
    }

    mgr->array   = NULL;
    mgr->len     = 0;
    mgr->capacity = 0;
    mgr->managed = cbs;

    cbs->callbacks = NULL;
    cbs->len       = 0;
    cbs->_mgr      = mgr;
}

void pseudo_cb_free(pseudo_callbacks_t *cbs)
{
    if (!cbs) {
        return;
    }

    callback_manager_c *mgr = (callback_manager_c *)cbs->_mgr;
    if (mgr) {
        free(mgr->array);
        free(mgr);
    }

    cbs->callbacks = NULL;
    cbs->len       = 0;
    cbs->_mgr      = NULL;
}

int pseudo_cb_adds(pseudo_callbacks_t *cbs, const pseudo_cb_t *ps_cb)
{
    if (!cbs || !ps_cb) {
        return -1;
    }

    callback_manager_c *mgr = (callback_manager_c *)cbs->_mgr;
    if (!mgr) {
        return -1;
    }

    return cb_add(mgr, ps_cb);
}

int pseudo_cb_add(pseudo_callbacks_t *cbs, void *cb, void *cb_args)
{
    pseudo_cb_t tmp = { .cb = cb, .cbargs = cb_args };
    return pseudo_cb_adds(cbs, &tmp);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
