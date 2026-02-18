// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#ifndef LIBPSEUDO_CONTAINERS_H
#define LIBPSEUDO_CONTAINERS_H

#include <stdint.h>
#include <sys/types.h>


#  ifdef __cplusplus
extern "C" {
#  endif

#include <pseudo/pseudo.h>

typedef struct id_state_container_t idtrack_t;

idtrack_t* get_id_tracker();
void free_id_tracker(idtrack_t* id_states);

id_state_t* get_id_state(idtrack_t* idstates, pid_t pid);
id_state_t* unshare_id_state(idtrack_t* idstates, pid_t old_pid, pid_t new_pid);
void erase_id_state(idtrack_t* idstates, pid_t pid);

void pseudo_cb_init(pseudo_callbacks_t* params);
void pseudo_cb_free(pseudo_callbacks_t* params);
// copies *sc_cb into params->callbacks - reallocs array!
int pseudo_cb_adds(pseudo_callbacks_t* params, const pseudo_cb_t* ps_cb);
int pseudo_cb_add(pseudo_callbacks_t* params, void* cb, void* cb_args);

#  ifdef __cplusplus
}
#include <map>
#include <list>

class IDStateContainer {
    std::map<pid_t, id_state_t> id_states;
public:
    id_state_t* get(pid_t pid);
    id_state_t* unshare(pid_t old_pid, pid_t new_pid);
    void invalidate(pid_t pid);
};

class CallbackManager {
    std::list<pseudo_cb_t> callbacks;
    pseudo_callbacks_t* managed;
    int update_managed();
public:
    CallbackManager(pseudo_callbacks_t* managed);
    int add_cb(const pseudo_cb_t* cb);
    ~CallbackManager() {
        if (this->managed->callbacks) { delete this->managed->callbacks; }

    }
};

#  endif

#endif
