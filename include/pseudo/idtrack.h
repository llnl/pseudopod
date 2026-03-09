// include/pseudo/idtrack.h
#ifndef LIBPSEUDO_IDTRACK_H
#define LIBPSEUDO_IDTRACK_H

#include <sys/types.h>
#include <stdint.h>
#include <pseudo/pseudo.h>   // id_state_t

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
    _idst_leaf l2[IDST_L2_SZ];
} _idst_l2;

 // Our client-owned state object that can grow later.
typedef struct idtrack {
    _idst_l2* l1[IDST_L1_SZ];
    id_state_t base_id;
    //fs_state_t fs_state;
} idtrack_t;

idtrack_t* idtrack_init(void);
void idtrack_free(idtrack_t* id_states);

#endif