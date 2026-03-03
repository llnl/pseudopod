// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_CONTAINERS_H
#define LIBPSEUDO_CONTAINERS_H

#include <stdint.h>
#include <sys/types.h>
#include <pseudo/pseudo.h>

#define IDST_L1_BITS 11
#define IDST_L2_BITS 11

#define IDST_L1_SZ (1 << IDST_L1_BITS)
#define IDST_L2_SZ (1 << IDST_L2_BITS)

#define L2_MASK (IDST_L2_SZ - 1)

typedef struct {
    uint32_t valid;
    id_state_t v;
} _idst_leaf;

typedef struct {
    _idst_leaf l2 [1<<IDST_L2_BITS];
} _idst_l2;

typedef struct {
    _idst_l2 *l1[IDST_L1_SZ];
} _idst_l1;

typedef _idst_l1 idtrack_t;

idtrack_t* get_id_tracker();
void free_id_tracker(idtrack_t* id_states);

id_state_t* get_id_state(idtrack_t* idstates, pid_t pid);
id_state_t* unshare_id_state(idtrack_t* idstates, pid_t old_pid, pid_t new_pid);
void erase_id_state(idtrack_t* idstates, pid_t pid);

#endif
