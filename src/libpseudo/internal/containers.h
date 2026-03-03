// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_CONTAINERS_H
#define LIBPSEUDO_CONTAINERS_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <pseudo/pseudo.h>

/* Opaque container for PID‑specific id_state tracking */
typedef struct id_state_container_t idtrack_t;

/* Allocation / deallocation */
idtrack_t* get_id_tracker(void);
void free_id_tracker(idtrack_t* id_states);

/* ID state operations */
id_state_t* get_id_state(idtrack_t* idstates, pid_t pid);
id_state_t* unshare_id_state(idtrack_t* idstates, pid_t old_pid, pid_t new_pid);
void erase_id_state(idtrack_t* idstates, pid_t pid);

/* Callback manager operations */
void pseudo_cb_init(pseudo_callbacks_t* params);
void pseudo_cb_free(pseudo_callbacks_t* params);
int pseudo_cb_adds(pseudo_callbacks_t* params, const pseudo_cb_t* ps_cb);
int pseudo_cb_add(pseudo_callbacks_t* params, void* cb, void* cb_args);

#ifdef __cplusplus
}
#endif

#endif // LIBPSEUDO_CONTAINERS_H
