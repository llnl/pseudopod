# Logging API

`pseudo/log.h` exposes a small stderr logger used throughout `libpseudo`.

## Log Levels

```c
typedef enum LogLevel {
    LOG_FATAL = 0,
    LOG_ERROR = 1,
    LOG_WARN  = 2,
    LOG_INFO  = 3,
    LOG_DEBUG = 4,
    LOG_TRACE = 5
} LogLevel;
```

The current default level is `LOG_WARN`.

## Public Functions

```C
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

void die(const char* msg);
```

## Behavior

### `pseudo_log_get_level()` and `pseudo_log_set_level()`

The logger keeps one process-global log level. `pseudo_log_set_level()` clamps
the supplied value into the inclusive range `[LOG_FATAL, LOG_TRACE]`.

### `pseudo_log()` and level-specific wrappers

Logs are written to `stderr` when `level <= current_level`.

Current message format:

```text
[YYYY-MM-DD HH:MM:SS] LEVEL: message
```

The wrappers such as `log_debug()` and `log_trace()` are thin convenience
front-ends over the same formatter.

### `log_perror()`

Captures the current `errno` and logs:

```text
<msg>: <strerror(errno)> (errno <n>)
```

If `msg` is `NULL`, it is treated as an empty string.

### `die()`

`die()` is the library's fatal error path:

- logs through `log_perror(LOG_FATAL, msg)`
- terminates the process with `exit(EXIT_FAILURE)`

This matters when using the rest of `libpseudo`: many internal failures do not
bubble up as error codes and instead terminate through `die()`.

## Practical Guidance

- Set the log level before `pseudo_run()` if you need to debug callback order
  or seccomp stops.
- Treat logging configuration as global process state; there is no per-runtime
  logger instance.
- Avoid relying on the exact timestamp format as a stable machine-readable API.
