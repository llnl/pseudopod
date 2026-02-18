// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_EMULATION_H
#define LIBPSEUDO_EMULATION_H
#define _GNU_SOURCE
#include "containers.h"
#include <pseudo/pseudo.h>

int do_clone(const pseudo_config_child_t* cfg);
int handle_events(pid_t child, pseudo_config_t* cfg);

#endif // LIBPSEUDO_EMULATION_H
