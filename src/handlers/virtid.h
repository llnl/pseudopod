// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_VIRTSETID_H
#define LIBPSEUDO_VIRTSETID_H
#include <pseudo/pseudo.h>
#include "containers.h"

#define ID_UNCHANGED 0xFFFFFFFF

void virtid_attach_handlers(pseudo_config_t* cfg, idtrack_t* id_states);

#endif // LIBPSEUDO_VIRTSETID_H
