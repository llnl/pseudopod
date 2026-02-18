// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#define _GNU_SOURCE
#include "internal/virtid.h"
#include "internal/emulation.h"
#include "internal/log.h"
#include <pseudo/pseudo.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

void pseudo_init_config(pseudo_config_t* cfg) {
    memset(cfg, 0, sizeof(pseudo_config_t));
    pseudo_cb_init(&cfg->cfg_syscall.cbs);
    pseudo_cb_init(&cfg->cfg_parent.cbs);
    pseudo_cb_init(&cfg->cfg_child.cbs);
    pseudo_cb_init(&cfg->cfg_tracer.cbs);
}

void pseudo_free_config(pseudo_config_t* cfg) {
    pseudo_cb_free(&cfg->cfg_syscall.cbs);
    pseudo_cb_free(&cfg->cfg_parent.cbs);
    pseudo_cb_free(&cfg->cfg_child.cbs);
    pseudo_cb_free(&cfg->cfg_tracer.cbs);
    memset(cfg, 0, sizeof(pseudo_config_t));
}

static void continue_child(pid_t child) {
    if (kill(child, SIGCONT)) {
        perror("kill");
    }
}

int pseudo_run(pseudo_config_t* pseudo_cfg) {
    DEBUG(stderr, "pseudo_run: start\n");

    pseudo_config_parent_t* cfg = &pseudo_cfg->cfg_parent;

    pid_t child = do_clone(&pseudo_cfg->cfg_child);
    if (child == -1) {
        die("clone");
    }

    DEBUG(stderr, "pseudo_run: clone succeded\n");

    for (int i = 0; i < cfg->cbs.len; i++) {
        DEBUG(stderr, "pseudo_run: executing callback %d\n", i);
        void* cb_args = cfg->cbs.callbacks[i].cbargs;
        parent_cb_func_t* cb = (parent_cb_func_t*) cfg->cbs.callbacks[i].cb;
        if (cb(child, cb_args)) {
            die("pseudo_run: post-clone callback returned nonzero");
        }
    }

    DEBUG(stderr, "pseudo_run: parent callback succeded\n");

    if (cfg->virt_enabled) {
        idtrack_t* id_states = get_id_tracker();
        virtid_attach_handlers(pseudo_cfg, id_states);
        unshare_id_state(id_states, getpid(), child);

        handle_events(child, pseudo_cfg);
    } else {
        int status;
        if (waitpid(child, &status, WUNTRACED) == -1) { die("waitpid initial"); }
        continue_child(child);
        DEBUG(stderr, "pseudo_run: waiting for child exit\n");
        waitpid(child, &status, 0);

    }
    DEBUG(stderr, "pseudo_run: done\n");

    return 0;
}
