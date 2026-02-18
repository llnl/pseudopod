// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef PSEUDO_LOG_H
#define PSEUDO_LOG_H
#include <stdio.h>

#ifndef DEBUG_ENABLED
#define DEBUG_ENABLED 0
#endif

#define DEBUG(stream, fmt, ...) do { \
    if (DEBUG_ENABLED) fprintf(stream, "DEBUG: " fmt, ##__VA_ARGS__); \
} while(0)

#define WARN(fmt, ...) do { \
    fprintf(stderr, "WARN: " fmt, ##__VA_ARGS__); \
} while(0)

#define ERR(fmt, ...) do { \
    fprintf(stderr, "ERR: " fmt, ##__VA_ARGS__); \
} while(0)

void die(const char *msg);

#endif
