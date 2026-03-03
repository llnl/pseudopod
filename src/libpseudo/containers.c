// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod
// Contributors. See top-level LICENSE and COPYRIGHT files for dates and
// other details.
//
// SPDX-License-Identifier: (Apache-2.0)

/* This file Implements the ID‑state container and the callback manager used
   by the pseudo library. */

#include "internal/containers.h"
#include <stdlib.h>
#include <string.h>

#define DEFAULT_CAPACITY ((size_t)8)
#define GROWTH_FACTOR ((size_t)2)

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


/**
 * Ensure the container can hold at least @param needed entries.
 * Grows the internal array using GROWTH_FACTOR when required.
 *
 *  @param c        Pointer to the container.
 *  @param needed   Minimum number of slots needed.
 *  @return         0 on success, -1 on allocation failure.
 */
static int ensure_capacity(id_state_container_c *c, size_t needed)
{
    if (c->capacity >= needed) {
        return 0;
    }

    size_t new_cap = c->capacity ? c->capacity * GROWTH_FACTOR : DEFAULT_CAPACITY;
    while (new_cap < needed) {
        new_cap *= GROWTH_FACTOR;
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

/**
 * Find the entry in container @param c matching @param pid
 * pid.
 *
 *  @param c       Container to search.
 *  @param pid     Process identifier to locate.
 *  @return        Pointer to the entry, or NULL if not found.
 */
static id_state_entry_t *find_entry(id_state_container_c *c, pid_t pid)
{
    for (size_t i = 0; i < c->len; ++i) {
        if (c->entries[i].pid == pid) {
            return &c->entries[i];
        }
    }
    return NULL;
}

/**
 * Get the state for @param pid from container reference @param c, 
 * creating a new entry if missing.
 *
 *  @param c     Container reference.
 *  @param pid   Process identifier.
 *  @return      Pointer to the state, or NULL on error.
 */
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

/**
 * Duplicate the state from old_pid to a new entry for new_pid.
 * Creates the new entry if it does not exist.
 *
 *  @param c        Container reference.
 *  @param old_pid  Source pid.
 *  @param new_pid  Destination pid.
 *  @return         Pointer to new state, or NULL on error.
 */
static id_state_t *container_unshare(id_state_container_c *c,
                                     pid_t old_pid,
                                     pid_t new_pid)
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

/**
 * Invalidate (remove) the entry with the specified pid.
 * Swaps with the last entry for O(1) removal.
 *
 *  @param c    Container to modify.
 *  @param pid  Process identifier to erase.
 */
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

/**
 * Ensure the callback manager can hold at least `needed` callbacks.
 * Grows the internal array as needed.
 *
 *  @param m        Manager reference.
 *  @param needed   Minimum slots required.
 *  @return         0 on success, -1 on allocation failure.
 */
static int cb_ensure_capacity(callback_manager_c *m, size_t needed)
{
    if (m->capacity >= needed) {
        return 0;
    }

    size_t new_cap = m->capacity ? m->capacity * GROWTH_FACTOR : DEFAULT_CAPACITY;
    while (new_cap < needed) {
        new_cap *= GROWTH_FACTOR;
    }

    pseudo_cb_t *new_arr = realloc(m->array, new_cap * sizeof(*new_arr));
    if (!new_arr) {
        return -1;
    }

    m->array    = new_arr;
    m->capacity = new_cap;
    return 0;
}

/**
 * Synchronize the public pseudo_callbacks_t with manager state.
 *
 *  @param m    Manager whose state is reflected.
 *  @return     Always returns 0.
 */
static int cb_update_managed(callback_manager_c *m)
{
    m->managed->callbacks = m->array;
    m->managed->len       = m->len;
    return 0;
}

/**
 * Append a new callback to the manager's array.
 *
 *  @param m    Manager to receive the callback.
 *  @param cb   Callback to add.
 *  @return     0 on success, -1 on allocation failure.
 */
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
    void *impl;   // points to id_state_container_c
};

/**
 * Allocate and initialise a new idtrack_t handle.
 * Caller must free it with free_id_tracker.
 *
 *  @return New handle, or NULL on allocation failure.
 */
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

/**
 * Release all memory associated with an idtrack_t handle.
 * Safe to call with NULL.
 *
 *  @param id_states Tracker to free.
 */
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

/**
 * Retrieve (and lazily create) state for a pid.
 *
 *  @param idstates Tracker handle.
 *  @param pid      Process identifier.
 *  @return         Pointer to state, or NULL on error.
 */
id_state_t *get_id_state(idtrack_t *idstates, pid_t pid)
{
    if (!idstates) {
        return NULL;
    }

    id_state_container_c *c = (id_state_container_c *)idstates->impl;
    return container_get(c, pid);
}

/**
 * Duplicate state from old_pid to new_pid within the tracker.
 *
 *  @param idstates Tracker handle.
 *  @param old_pid  Source pid.
 *  @param new_pid  Destination pid.
 *  @return         Pointer to new state, or NULL on error.
 */
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

/**
 * Remove the entry for pid from the tracker.
 *
 *  @param idstates Tracker handle.
 *  @param pid      Process identifier to erase.
 */
void erase_id_state(idtrack_t *idstates, pid_t pid)
{
    if (!idstates) {
        return;
    }

    id_state_container_c *c = (id_state_container_c *)idstates->impl;
    container_invalidate(c, pid);
}


// Callback handling

/**
 * Initialise a pseudo_callbacks_t structure and manager.
 *
 *  @param cbs Callbacks structure to initialise.
 */
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

/**
 * Free resources associated with a pseudo_callbacks_t.
 *
 *  @param cbs Callbacks structure to free.
 */
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

/**
 * Add a pre‑constructed pseudo_cb_t to the manager.
 *
 *  @param cbs    Callbacks structure.
 *  @param ps_cb  Callback to add.
 *  @return       0 on success, -1 on failure.
 */
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

/**
 * Convenience wrapper to add a callback from raw pointers.
 *
 *  @param cbs      Callbacks structure.
 *  @param cb       Callback function pointer.
 *  @param cb_args  Argument pointer for callback.
 *  @return         0 on success, -1 on failure.
 */
int pseudo_cb_add(pseudo_callbacks_t *cbs, void *cb, void *cb_args)
{
    pseudo_cb_t tmp = { .cb = cb, .cbargs = cb_args };
    return pseudo_cb_adds(cbs, &tmp);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
