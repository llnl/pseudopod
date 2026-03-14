// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#define _GNU_SOURCE
#include <pseudo/pseudo.h>
#include <pseudo/log.h>
#include <stdlib.h>
#include <string.h>

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
