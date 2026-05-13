// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#include <pseudo/log.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

static int pseudo_log_level = PSEUDO_LOGLEVEL_WARN;

static const char* _level_name(int level) {
    switch (level) {
        case PSEUDO_LOGLEVEL_FATAL: return "FATAL";
        case PSEUDO_LOGLEVEL_ERROR: return "ERROR";
        case PSEUDO_LOGLEVEL_WARN:  return "WARN";
        case PSEUDO_LOGLEVEL_INFO:  return "INFO";
        case PSEUDO_LOGLEVEL_DEBUG: return "DEBUG";
        case PSEUDO_LOGLEVEL_TRACE: return "TRACE";
        default:        return "UNKNOWN";
    }
}

// returns size of timestamp
static int _get_timestamp(char* str, int maxlen) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    int l = snprintf(str, maxlen, "[%04d-%02d-%02d %02d:%02d:%02d]",
            tmv.tm_year + 1900,
            tmv.tm_mon + 1,
            tmv.tm_mday,
            tmv.tm_hour,
            tmv.tm_min,
            tmv.tm_sec);
    return l;
}

static int pseudo_log_clamp(int level) {
    if (level > 5) { return 5; }
    if (level < 0) { return 0; }
    return level;
}

int pseudo_log_get_level(void) {
    return pseudo_log_level;
}

void pseudo_log_set_level(int level) {
    if (level > 5) { level = 5; }
    if (level < 0) { level = 0; }
    pseudo_log_level = pseudo_log_clamp(level);
}

static void vlog(int level, const char* fmt, va_list ap) {
    if (level <= pseudo_log_level) {
        char timestamp[80];
        _get_timestamp(timestamp, 80);

        char logstr[1024];
        vsnprintf(logstr, 1024, fmt, ap);
        fprintf(stderr, "%s %s: %s\n", timestamp, _level_name(level), logstr);
    }
}

void pseudo_log(int level, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog(level, fmt, ap);
    va_end(ap);
}

void pseudo_log_fatal(const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog(PSEUDO_LOGLEVEL_FATAL, fmt, ap); va_end(ap); }
void pseudo_log_error(const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog(PSEUDO_LOGLEVEL_ERROR, fmt, ap); va_end(ap); }
void pseudo_log_warn (const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog(PSEUDO_LOGLEVEL_WARN,  fmt, ap); va_end(ap); }
void pseudo_log_info (const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog(PSEUDO_LOGLEVEL_INFO,  fmt, ap); va_end(ap); }
void pseudo_log_debug(const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog(PSEUDO_LOGLEVEL_DEBUG, fmt, ap); va_end(ap); }
void pseudo_log_trace(const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog(PSEUDO_LOGLEVEL_TRACE, fmt, ap); va_end(ap); }

void pseudo_log_perror(int level, const char* msg) {
    if (!msg) { msg = ""; }
    int e = errno;
    pseudo_log(level, "%s: %s (errno %d)", msg, strerror(e), e);
}

void pseudo_die(const char* msg) {
    pseudo_log_perror(PSEUDO_LOGLEVEL_FATAL, msg);
    exit(EXIT_FAILURE);
}
