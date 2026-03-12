// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_VIRTID_H
#define LIBPSEUDO_VIRTID_H
#include <pseudo/pseudo.h>
#include <handlers/idtrack.h>

#define ID_UNCHANGED 0xFFFFFFFF

typedef struct {
    pseudo_cb_t parent;
    pseudo_cb_t tracer;
    pseudo_cb_t syscall;
} virtid_callbacks_t;

/*
  Return callback bundle. cbargs for each callback is id_states.
  Client attaches these to cfg.{parent,tracer,syscall}.cbs.*/
virtid_callbacks_t virtid_callbacks(idtrack_t* id_states);

/*
  Attach handlers to cfg. This is just a helper that calls virtid_callbacks and
  adds the callbacks to the config.*/
void virtid_attach_handlers(pseudo_config_t* cfg, idtrack_t* id_states);

// Previously declared internally at ./src/libpseudo/internal/
id_state_t* get_id_state(idtrack_t* idstates, pid_t pid);
id_state_t* unshare_id_state(idtrack_t* idstates, pid_t old_pid, pid_t new_pid);
void erase_id_state(idtrack_t* idstates, pid_t pid);
#endif
