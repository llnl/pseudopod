// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#include "internal/log.h"
#include <error.h>
#include <stdlib.h>

void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}
