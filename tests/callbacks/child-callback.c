// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <pseudo/pseudo.h>
#include <pseudo/log.h>

void* test(void* arg) {
    *((int*) arg) = 1;
    return 0;
}

int main(int argc, char *argv[]) {
    pseudo_config_t cfg;
    pseudo_init_config(&cfg);

    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        return 0;
    }

    int cb_success = 0;
    char* targv[] = {"/proc/self/exe", "--test", 0};
    cfg.cfg_child.child_argv = targv;
    pseudo_cb_add(&cfg.cfg_child.cbs, &test, (void*)&cb_success);

    //pseudo_log_set_level(PSEUDO_LOGLEVEL_TRACE);

    int pid = pseudo_fork(&cfg);
    int rc = -1;

    if (pid == 0) {
        if (cb_success != 1) {
            fprintf(stderr, "Failed! Child callback did not set test value\n");
            return -1;
        } else {
            execv(targv[0], targv);
        }
    } else {
        rc = pseudo_fork_wait(pid, &cfg);
    }

    return rc;
}