// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_LOG_H
#define LIBPSEUDO_LOG_H

typedef enum LogLevel {
    PSEUDO_LOGLEVEL_FATAL = 0,
    PSEUDO_LOGLEVEL_ERROR = 1,
    PSEUDO_LOGLEVEL_WARN  = 2,
    PSEUDO_LOGLEVEL_INFO  = 3,
    PSEUDO_LOGLEVEL_DEBUG = 4,
    PSEUDO_LOGLEVEL_TRACE = 5
} LogLevel;

int  pseudo_log_get_level(void);
void pseudo_log_set_level(int level);
void pseudo_log(int level, const char* fmt, ...);
void pseudo_log_perror(int level, const char* msg);

void pseudo_log_fatal(const char* fmt, ...);
void pseudo_log_error(const char* fmt, ...);
void pseudo_log_warn (const char* fmt, ...);
void pseudo_log_info (const char* fmt, ...);
void pseudo_log_debug(const char* fmt, ...);
void pseudo_log_trace(const char* fmt, ...);

// print errno and terminate
void pseudo_die(const char* msg);

#endif
