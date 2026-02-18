// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef PSEUDO_USERNS_H
#define PSEUDO_USERNS_H
#include <sys/types.h>
#include <inttypes.h>

#define USERNS_CONFIGURED "_CONTAINERS_USERNS_CONFIGURED"
#define ENV_UID "_CONTAINERS_ROOTLESS_UID"
#define ENV_GID "_CONTAINERS_ROOTLESS_GID"
#define SETGROUPS_FILE "/proc/%s/setgroups"
#define UIDMAP_FILE "/proc/%s/uid_map"
#define GIDMAP_FILE "/proc/%s/gid_map"

typedef struct {
    uint32_t to, from, len;
} ns_entry_t;

typedef struct {
    ns_entry_t* entries;
    int num_entries;
} ns_config_t;

typedef struct {
    uint32_t baseid;
    uint32_t subid;
    uint32_t count;
} subid_range_t;

// helper types for callbacks
typedef struct {
    uid_t uid;
    uid_t gid;
} cb_podman_envars_config_t;

typedef struct {
    ns_config_t uid_config;
    ns_config_t gid_config;
} setup_userns_config_t;

int setup_child_userns_unpriv(pid_t child, const ns_config_t* uid_config, const ns_config_t* gid_config);
int get_subid_range(const char *filename, uid_t id, const char* name, subid_range_t *range);
int get_subid_config(subid_range_t *uid_range, subid_range_t *gid_range);

// pseudo callback functions

// child callback
int cb_set_podman_envars(void*);               // takes cb_podman_envars_config_t*

// parent callback
int cb_setup_userns_unpriv(pid_t child, void*); // takes setup_userns_config_t*
int cb_setup_userns_priv(pid_t child, void*);   // privileged namespace setup

#endif
