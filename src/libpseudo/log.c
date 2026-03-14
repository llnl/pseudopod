// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#include <pseudo/log.h>
#include <error.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <threads.h>

// static mtx_t _mtx;
// static int _log_init = 0;

static int log_level = LOG_WARN;

static const char* _level_name(int level) {
    switch (level) {
        case LOG_FATAL: return "FATAL";
        case LOG_ERROR: return "ERROR";
        case LOG_WARN:  return "WARN";
        case LOG_INFO:  return "INFO";
        case LOG_DEBUG: return "DEBUG";
        case LOG_TRACE: return "TRACE";
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

static int log_clamp(int level) {
    if (level > 5) { return 5; }
    if (level < 0) { return 0; }
    return level;
}

int pseudo_log_get_level(void) {
    return log_level;
}

void pseudo_log_set_level(int level) {
    if (level > 5) { level = 5; }
    if (level < 0) { level = 0; }
    log_level = log_clamp(level);
}

void pseudo_log(int level, const char* fmt, ...) {
    if (level <= log_level) {
        char timestamp[80];
        _get_timestamp(timestamp, 80);

        // if (! _log_init) { mtx_init(&_mtx, mtx_plain); }
        // mtx_lock(&_mtx);
        va_list ap;
        va_start(ap, fmt);
        fprintf(stderr, "%s %s: ", timestamp, _level_name(level));
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
        va_end(ap);
        // mtx_unlock(&_mtx);
    }
}

void log_fatal(const char* fmt, ...) { va_list ap; va_start(ap, fmt); pseudo_log(LOG_FATAL, fmt, ap); va_end(ap); }
void log_error(const char* fmt, ...) { va_list ap; va_start(ap, fmt); pseudo_log(LOG_ERROR, fmt, ap); va_end(ap); }
void log_warn (const char* fmt, ...) { va_list ap; va_start(ap, fmt); pseudo_log(LOG_WARN,  fmt, ap); va_end(ap); }
void log_info (const char* fmt, ...) { va_list ap; va_start(ap, fmt); pseudo_log(LOG_INFO,  fmt, ap); va_end(ap); }
void log_debug(const char* fmt, ...) { va_list ap; va_start(ap, fmt); pseudo_log(LOG_DEBUG, fmt, ap); va_end(ap); }
void log_trace(const char* fmt, ...) { va_list ap; va_start(ap, fmt); pseudo_log(LOG_TRACE, fmt, ap); va_end(ap); }

void log_perror(int level, const char* msg) {
    if (!msg) { msg = ""; }
    int e = errno;
    pseudo_log(level, "%s: %s (errno %d)", msg, strerror(e), e);
}

void die(const char* msg) {
    log_perror(LOG_FATAL, msg);
    exit(EXIT_FAILURE);
}
