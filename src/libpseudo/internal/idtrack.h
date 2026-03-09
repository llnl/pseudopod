// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_ID_T_H
#define LIBPSEUDO_ID_T_H

#include <sys/types.h>
#include <stdint.h>
#include <pseudo/pseudo.h>
#include <pseudo/idtrack.h>

// private

id_state_t* get_id_state(idtrack_t* idstates, pid_t pid);
id_state_t* unshare_id_state(idtrack_t* idstates, pid_t old_pid, pid_t new_pid);
void erase_id_state(idtrack_t* idstates, pid_t pid);

#endif