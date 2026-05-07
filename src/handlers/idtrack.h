// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_IDTRACK_H
#define LIBPSEUDO_IDTRACK_H

#include <stdint.h>

#define IDST_L1_BITS 11
#define IDST_L2_BITS 11

#define IDST_L1_SZ (1 << IDST_L1_BITS)
#define IDST_L2_SZ (1 << IDST_L2_BITS)

#define L2_MASK (IDST_L2_SZ - 1)

// ID tracker types
typedef struct {
    uint32_t real, effective, saved;
} ids_t;

typedef struct {
    ids_t id[2]; // id[0]: user, id[1]: group
} id_state_t;

typedef struct {
    uint32_t valid;
    id_state_t v;
} _idst_leaf;

typedef struct {
    _idst_leaf l2[IDST_L2_SZ];
} _idst_l2;

 // client-owned state object that can be expanded later.
typedef struct idtrack {
    _idst_l2* l1[IDST_L1_SZ];
    id_state_t base_id;
    //fs_state_t fs_state;
} idtrack_t;

idtrack_t* idtrack_init(void);
void idtrack_set_base(idtrack_t* id_states, id_state_t base_id);
void idtrack_free(idtrack_t* id_states);

#endif