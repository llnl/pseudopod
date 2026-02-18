// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#include "userns.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#ifdef USE_LIBCAP
#include <sys/capability.h>
#endif

#define GETPW_MAXBUF 32768

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

void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// privileged mode functions

int resolve_path(const char* cmd, int maxlen, char* cmd_path) {
    // try to resolve the full path using PATH
    int found = 0;
    const char *path_env = getenv("PATH");
    if (strchr(cmd, '/')) {
        snprintf(cmd_path, strlen(cmd_path), "%s", cmd);
    } else if (path_env) {
        char *saveptr, *token;
        char *path_copy = strdup(path_env);
        char* orig_path_copy = path_copy;
        for (token = strtok_r(path_copy, ":", &saveptr); token; token = strtok_r(NULL, ":", &saveptr)) {
            int path_len = strlen(token) + 1 + strlen(cmd) + 1;
            if (path_len > maxlen) {
                continue;
            }
            snprintf(cmd_path, path_len, "%s/%s", token, cmd);
            if (access(cmd_path, X_OK) == 0) {
                found = 1;
                break;
            }
        }
        free(orig_path_copy);
    }
    if (!found) {
        memset(cmd_path, 0, maxlen);
    }
    return found == 0; // return 0 for success
}

#ifdef USE_LIBCAP
// check capabilities on a binary
int check_cap(const char *path, cap_value_t cap) {
    cap_t caps = cap_get_file(path);
    if (!caps) {
        // if no capabilities, treat as not present
        return 0;
    }
    cap_flag_value_t value;
    int ret = cap_get_flag(caps, cap, CAP_EFFECTIVE, &value);
    cap_free(caps);
    if (ret == -1) {
        return 0;
    }
    return value == CAP_SET;
}
#endif

int get_subid_range(const char *filename, uid_t baseid, const char* name, subid_range_t *range) {
    char baseid_str[16];
    snprintf(baseid_str, 8, "%u", baseid);

    FILE *f = fopen(filename, "r");
    if (!f) {
        perror(filename);
        return -1;
    }

    range->baseid = baseid;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char user_field[64];
        unsigned long id, count;
        if (sscanf(line, "%63[^:]:%lu:%lu", user_field, &id, &count) == 3) {
            if (strcmp(user_field, name) == 0 || strcmp(user_field, baseid_str) == 0) {
                range->subid = id;
                range->count = count;
                found = 1;
                break;
            }
        }
    }
    fclose(f);

    if (!found) {
        DEBUG(stderr, "%s (id %s) not found in %s\n", name, baseid_str, filename);
        return -1;
    }
    return 0;
}

int exec_map_helper(char** argv) {
    if (DEBUG_ENABLED) {
        fprintf(stderr, "attempt to call %s ", argv[0]);
        char* arg = argv[1];
        for (int i = 1; arg; i++) {
            arg = argv[i];
            fprintf(stderr, "%s ", arg);
        }
        fprintf(stderr, "\n");
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    } else if (pid == 0) {
        // child
        execvp(argv[0], argv);
        perror("execvp");
        _exit(127);
    } else {
        // parent
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return -1;
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            return 0;
        } else {
            fprintf(stderr, "%s failed with status %d\n", argv[0], status);
            return -1;
        }
    }
    return 0;
}

// Run newuidmap or newgidmap
int run_map_helper(const char* map_cmd, pid_t target_pid, ns_config_t* config) {
    // Construct argv for newuidmap/newgidmap
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", target_pid);

    int allocd = 0, allocmax = 1024;
    char* alloc = (char*) malloc(allocmax);
    if (!alloc) { die("run_map_helper: malloc failed"); }

    // argv[0] + pid + 3xmappings + null
    int argc = 2 + config->num_entries * 3 + 1;
    char** argv = (char**) &alloc[allocd]; allocd += (sizeof(char*) * argc);

    int idx = 0;
    argv[idx++] = (char*)map_cmd;
    argv[idx++] = pid_str;
    for (int i = 0; i < config->num_entries; ++i) {
        char* to, *from, *len;
        to   = &alloc[allocd]; allocd += 16;
        from = &alloc[allocd]; allocd += 16;
        len  = &alloc[allocd]; allocd += 16;
        if (allocd > allocmax) { die("run_map_helper: alloc failed"); }
        snprintf(to,   16, "%u", config->entries[i].to);
        snprintf(from, 16, "%u", config->entries[i].from);
        snprintf(len,  16, "%u", config->entries[i].len);
        argv[idx++] = to; argv[idx++] = from; argv[idx++] = len;
    }
    argv[idx] = NULL;

    int ret = exec_map_helper(argv);
    free(alloc);
    return ret;
}

// unprivileged mode functions

int write_id_map(const char* path, const char* map, const ssize_t len) {
    int rv = 0;
    int fd = open(path, O_WRONLY);
    if (fd == -1) {
        perror("open");
        rv = -1;
    } else {
        if (write(fd, map, len) != len) {
            perror("write");
            rv = -1;
        }
        close(fd);
    }
    return rv;
}

int setup_child_idmap_unpriv(const char* idmap_file, const ns_config_t* nsconfig) {
    int rv = 0;
    char strbuf[64];

    if (nsconfig->num_entries > 1) {
        DEBUG(stderr, "Ignoring additional ID maps in unprivileged mode\n");
    } else if (nsconfig->num_entries == 0) {
        WARN("No ID maps specified\n");
    }

    ns_entry_t* nsentry = &nsconfig->entries[0];

    int len;
    len = snprintf(strbuf, 64, "%u %u %u", nsentry->to, nsentry->from, nsentry->len);
    if (write_id_map(idmap_file, strbuf, len)) {
        rv = -1;
    }
    return rv;
}

int setup_child_userns_unpriv(const pid_t child, const ns_config_t* uid_config, const ns_config_t* gid_config) {

    char pidbuf[16];
    char map_fn[32];
    snprintf(pidbuf, 16, "%d", child);

    snprintf(map_fn, 32, SETGROUPS_FILE, pidbuf);
    if (write_id_map(map_fn, "deny", 4)) {
        WARN("setgroups failed\n");
        return -1;
    }

    snprintf(map_fn, 32, UIDMAP_FILE, pidbuf);
    if (setup_child_idmap_unpriv(map_fn, uid_config)) {
        WARN("Write UID map failed\n");
        return -1;
    }

    snprintf(map_fn, 32, GIDMAP_FILE, pidbuf);
    if (setup_child_idmap_unpriv(map_fn, gid_config)) {
        WARN("Write GID map failed\n");
        return -1;
    }
    return 0;
}

// utility functions

int get_subid_config(subid_range_t *uid_range, subid_range_t *gid_range) {
    char* alloc = (char*) malloc(640);
    if (!alloc) {
        perror("malloc");
        die("get_subid_config: malloc failed");
    }
    char* newuidmap = &alloc[0], *newgidmap = &alloc[256];
    char* uname = &alloc[512], *gname = &alloc[512 + 64];

    int uid = getuid();
    int gid = getgid();

    struct passwd pwd, *pw_result;
    struct group grp, *gr_result;

    char* buf = (char*) malloc(GETPW_MAXBUF);
    getpwuid_r(uid, &pwd, buf, GETPW_MAXBUF, &pw_result);
    if (!pw_result) {
        DEBUG(stderr, "error finding uid %d in passwd\n", uid);
        free(buf);
        goto fail;
    }
    strncpy(uname, pw_result->pw_name, 64);

    getgrgid_r(gid, &grp, buf, GETPW_MAXBUF, &gr_result);
    if (!gr_result) {
        perror("getgrgid_r");
        DEBUG(stderr, "error finding gid %d in group\n", gid);
        free(buf);
        goto fail;
    }
    strncpy(gname, gr_result->gr_name, 64);
    free(buf);

    if (resolve_path("newuidmap", 256, newuidmap)) {
        DEBUG(stderr, "newuidmap binary not found\n");
        goto fail;
    }
    if (resolve_path("newgidmap", 256, newgidmap)) {
        DEBUG(stderr, "newgidmap binary not found\n");
        goto fail;
    }

#ifdef USE_LIBCAP
    if (!check_cap(newuidmap, CAP_SETUID)) {
        DEBUG(stderr, "%s not cap_setuid\n", newuidmap);
        goto fail;
    }

    if (!check_cap(newgidmap, CAP_SETGID)) {
        DEBUG(stderr, "%s not cap_setgid\n", newgidmap);
        goto fail;
    }
#endif

    if (get_subid_range("/etc/subuid", uid, uname, uid_range)) {
        DEBUG(stderr, "couldn't look up subuid range for %s\n", uname);
        goto fail;
    }

    if (get_subid_range("/etc/subgid", gid, gname, gid_range)) {
        DEBUG(stderr, "couldn't look up subgid range for %s\n", gname);
        goto fail;
    }

    free(alloc);
    return 0;

fail:
    free(alloc);
    return -1;
}

int cb_setup_userns_priv(pid_t child, void* v_cfg) {
    setup_userns_config_t* cfg = (setup_userns_config_t*) v_cfg;

    if (run_map_helper("newuidmap", child, &cfg->uid_config)) {
        WARN("newuidmap call failed\n");
        goto fallback;
    }

    if (run_map_helper("newgidmap", child, &cfg->gid_config)) {
        WARN("newgidmap call failed\n");
        goto fallback;
    }

    return 0;

fallback:
    return cb_setup_userns_unpriv(child, v_cfg);
}

int cb_setup_userns_unpriv(pid_t child, void* v_cfg) {
    setup_userns_config_t* cfg = (setup_userns_config_t*) v_cfg;
    if (setup_child_userns_unpriv(child, &cfg->uid_config, &cfg->gid_config)) {
        ERR("Unprivileged namespace setup failed\n");
        return -1;
    }
    return 0;
}

int cb_set_podman_envars(void* v_cfg) {
    cb_podman_envars_config_t* cfg = (cb_podman_envars_config_t*) v_cfg;
    char idbuf[16];
    setenv(USERNS_CONFIGURED, "done", 1);

    snprintf(idbuf, 16, "%d", cfg->uid);
    setenv(ENV_UID, idbuf, 1);

    snprintf(idbuf, 16, "%d", cfg->gid);
    setenv(ENV_GID, idbuf, 1);
    return 0;
}
