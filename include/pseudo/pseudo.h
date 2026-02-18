// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_PSEUDO_H
#define LIBPSEUDO_PSEUDO_H

#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include <pseudo/seccomp.h>
#include <pseudo/syscall.h>
#include <sys/ptrace.h>

// ID tracker types
typedef struct {
    uint32_t real, effective, saved;
} ids_t;

typedef struct {
    ids_t id[2]; // id[0]: user, id[1]: group
} id_state_t;

// callback function signatures
typedef int (parent_cb_func_t)(pid_t child, void* cb_args);
typedef int (child_cb_func_t)(void* cb_args);
typedef int (tracer_cb_func_t)(pid_t child, int waitpid_status, void* cb_args);
typedef int (syscall_cb_func_t)(pid_t child, syscall_ctx_t* sc_args, void* cb_args);

typedef struct {
    void* cb;         // callback
    void* cbargs;     // extra arguments to callback
} pseudo_cb_t;

// opaque callback manager context
typedef void cb_manager_t;

// managed callback struct
typedef struct {
    pseudo_cb_t* callbacks;
    int len;
    cb_manager_t* _mgr;
} pseudo_callbacks_t;

// parameters for tracee
typedef struct {
    int clone_flags;  // extra flags to pass to CLONE
    char** child_argv;
    char** child_envp;
    const seccomp_fprog** filters;
    pseudo_callbacks_t cbs;
} pseudo_config_child_t;

// parameters for tracer
typedef struct {
    pseudo_callbacks_t cbs;
} pseudo_config_tracer_t;

// parameters for syscall handling
typedef struct {
    pseudo_callbacks_t cbs;
} pseudo_config_syscall_t;

// parameters for parent
typedef struct {
    pseudo_callbacks_t cbs;
    int virt_enabled;
    id_state_t base_id;
} pseudo_config_parent_t;

// top-level config
typedef struct {
    pseudo_config_child_t   cfg_child;
    pseudo_config_syscall_t cfg_syscall;
    pseudo_config_tracer_t  cfg_tracer;
    pseudo_config_parent_t  cfg_parent;
} pseudo_config_t;

void pseudo_init_config(pseudo_config_t* cfg);
void pseudo_free_config(pseudo_config_t* cfg);

void pseudo_cb_init(pseudo_callbacks_t* cbs);
void pseudo_cb_free(pseudo_callbacks_t* cbs);
// copies *sc_cb into cbs->callbacks - reallocs array!
int pseudo_cb_add(pseudo_callbacks_t* cbs, void* cb, void* cb_args);
int pseudo_cb_adds(pseudo_callbacks_t* cbs, const pseudo_cb_t* pseudo_cb);

int pseudo_run(pseudo_config_t* cfg);

#endif // LIBPSEUDO_PSEUDO_H
