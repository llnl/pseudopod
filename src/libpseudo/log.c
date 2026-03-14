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

static void vlog(int level, const char* fmt, va_list ap) {
    if (level <= log_level) {
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

void log_fatal(const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog(LOG_FATAL, fmt, ap); va_end(ap); }
void log_error(const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog(LOG_ERROR, fmt, ap); va_end(ap); }
void log_warn (const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog(LOG_WARN,  fmt, ap); va_end(ap); }
void log_info (const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog(LOG_INFO,  fmt, ap); va_end(ap); }
void log_debug(const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog(LOG_DEBUG, fmt, ap); va_end(ap); }
void log_trace(const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog(LOG_TRACE, fmt, ap); va_end(ap); }

void log_perror(int level, const char* msg) {
    if (!msg) { msg = ""; }
    int e = errno;
    pseudo_log(level, "%s: %s (errno %d)", msg, strerror(e), e);
}

void die(const char* msg) {
    log_perror(LOG_FATAL, msg);
    exit(EXIT_FAILURE);
}
