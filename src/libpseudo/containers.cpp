// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#include "internal/containers.h"

id_state_t* IDStateContainer::get(pid_t pid) {
    return &this->id_states[pid];
}
id_state_t* IDStateContainer::unshare(pid_t old_pid, pid_t new_pid) {
    auto old_id = this->get(old_pid);
    this->id_states[new_pid] = *old_id;
    return this->get(new_pid);
}
void IDStateContainer::invalidate(pid_t pid) {
    this->id_states.erase(pid);
}

CallbackManager::CallbackManager(pseudo_callbacks_t* managed) : managed(managed) {
        this->managed->callbacks = 0;
        this->managed->len = 0;
        this->managed->_mgr = static_cast<cb_manager_t*>(this);
    }

int CallbackManager::update_managed() {
    if (this->managed->callbacks) {
        delete[] this->managed->callbacks;
    }
    this->managed->callbacks = new pseudo_cb_t[this->callbacks.size()];
    std::copy(this->callbacks.begin(), this->callbacks.end(), this->managed->callbacks);
    this->managed->len = this->callbacks.size();
    return 0;
}

int CallbackManager::add_cb(const pseudo_cb_t* cb) {
    this->callbacks.emplace_back(*cb);
    return this->update_managed();
}

// C API

extern "C" {

// idtrack_t
struct id_state_container_t {
    IDStateContainer impl;
};

idtrack_t* get_id_tracker() {
    idtrack_t* id_states = new idtrack_t;
    return id_states;
}

void free_id_tracker(idtrack_t* id_states) {
    delete id_states;
}

id_state_t* get_id_state(idtrack_t* idstates, pid_t pid) {
    return idstates->impl.get(pid);
}

id_state_t* unshare_id_state(idtrack_t* idstates, pid_t old_pid, pid_t new_pid) {
    return idstates->impl.unshare(old_pid, new_pid);
}

void erase_id_state(idtrack_t* idstates, pid_t pid) {
    idstates->impl.invalidate(pid);
}

void pseudo_cb_init(pseudo_callbacks_t* cbs) {
    new CallbackManager(cbs);
}

void pseudo_cb_free(pseudo_callbacks_t* cbs) {
    CallbackManager* cbm = static_cast<CallbackManager*>(cbs->_mgr);
    delete cbm;
}

int pseudo_cb_adds(pseudo_callbacks_t* cbs, const pseudo_cb_t* cb) {
    CallbackManager* cbm = static_cast<CallbackManager*>(cbs->_mgr);
    return cbm->add_cb(cb);
}

int pseudo_cb_add(pseudo_callbacks_t* cbs, void* cb, void* cb_args) {
    CallbackManager* cbm = static_cast<CallbackManager*>(cbs->_mgr);
    pseudo_cb_t cbt = {cb, cb_args};
    return cbm->add_cb(&cbt);
}

} // extern "C"
