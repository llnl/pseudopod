// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_VIRTID_H
#define LIBPSEUDO_VIRTID_H
#include <pseudo/pseudo.h>
#include "internal/containers.h"

#define ID_UNCHANGED 0xFFFFFFFF

typedef struct virtid virtid_t;

typedef struct {
    pseudo_cb_t parent;  // parent_cb_func_t
    pseudo_cb_t tracer;  // tracer_cb_func_t
    pseudo_cb_t syscall; // syscall_cb_func_t
} virtid_callbacks_t;

// create && delete virtid context
virtid_t* virtid_init(const id_state_t* base_id); // base_id can be NULL (will use default)
void virtid_free(virtid_t* v);

// set/get base id
void virtid_set_id(virtid_t* v, const id_state_t* base_id);
const id_state_t* virtid_get_id(const virtid_t* v);

// return the callbacks for this virtid instance.
virtid_callbacks_t virtid_callbacks(virtid_t* v);

#endif // LIBPSEUDO_VIRTID_H
