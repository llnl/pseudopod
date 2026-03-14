// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef PSEUDO_LOG_H
#define PSEUDO_LOG_H

typedef enum LogLevel {
    LOG_FATAL = 0,
    LOG_ERROR = 1,
    LOG_WARN  = 2,
    LOG_INFO  = 3,
    LOG_DEBUG = 4,
    LOG_TRACE = 5
} LogLevel;

int  pseudo_log_get_level(void);
void pseudo_log_set_level(int level);
void pseudo_log(int level, const char* fmt, ...);
void log_perror(int level, const char* msg);

void log_fatal(const char* fmt, ...);
void log_error(const char* fmt, ...);
void log_warn (const char* fmt, ...);
void log_info (const char* fmt, ...);
void log_debug(const char* fmt, ...);
void log_trace(const char* fmt, ...);

// print errno and terminate
void die(const char* msg);

#endif
