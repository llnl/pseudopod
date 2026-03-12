// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#include "libpseudo/internal/log.h"
#include <handlers/idtrack.h>
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
            free(id_states->l1[i]);
            id_states->l1[i] = 0;
        }
    }
}

void idtrack_set_base(idtrack_t* id_states, id_state_t base_id) {
    if (!id_states) return;
    memcpy(&id_states->base_id, &base_id, sizeof(base_id));
}