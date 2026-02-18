// Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod Contributors. See top-level LICENSE and COPYRIGHT files for dates and other details.
// SPDX-License-Identifier: (Apache-2.0)

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <pseudo/pseudo.h>

static int fakeroot = 0;
static int tracer = 1;

static struct option long_options[] = {
    {"uid",        required_argument, 0, 'u'},
    {"gid",        required_argument, 0, 'g'},
    {"fakeroot",   no_argument,       0, 'f'},
    {"no-tracer",  no_argument,       0, 's'},
    {"root",       no_argument,       0, 'r'},
    {"help",       no_argument,       0, 'h'},
    {0, 0, 0, 0}
};

static void usage(char *argv[]) {
    fprintf(stderr,
        "Usage: %s [OPTIONS] <target> [args...]\n"
        "Options:\n"
        "  -u <uid>, --uid=<num>  Set starting UID\n"
        "  -g <gid>, --gid=<num>  Set starting GID\n"
        "  -f, --fakeroot         Enable seccomp fakeroot (disables uid virtualization)\n"
        "  -s, --no-tracer        Disable seccomp tracer (attach it later to enable virtualization)\n"
        "  -r, --root             Set both UID and GID to root\n"
        "  -h, --help             Show this help message\n"
        "Notes:\n"
        "  If no user/group options are specified, current UID and GID are the default.\n"
        "  If no <target> is specified, the user's shell ($SHELL or /bin/sh) is run.\n"
        "  Parsing stops at the first non-option, or at \"--\".\n",
        argv[0]);
    exit(EXIT_FAILURE);
}

void opt_setid(uid_t* default_id, unsigned long value, char* type) {
    if (*default_id != (uid_t)-1) {
        fprintf(stderr, "WARN: %s already specified. Ignoring.\n", type);
    } else {
        *default_id = (uid_t)value;
    }
}

int main(int argc, char *argv[]) {
    int opt;
    int option_index = 0;

    uid_t default_uid = (uid_t)-1;
    gid_t default_gid = (gid_t)-1;

    int opt_id;
    char* inval;

    while ((opt = getopt_long(argc, argv, "+u:g:nfsrh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'u': // -u or --uid
                opt_id = strtoul(optarg, &inval, 10);
                if (*inval != 0) { fprintf(stderr, "Invalid UID: %s\n", inval); usage(argv); }
                opt_setid(&default_uid, opt_id, "uid");
                break;
            case 'g': // -g or --gid
                opt_id = strtoul(optarg, &inval, 10);
                if (*inval != 0) { fprintf(stderr, "Invalid GID: %s\n", inval); usage(argv); }
                opt_setid(&default_gid, opt_id, "gid");
                break;
            case 'f': // --fakeroot
                fakeroot = 1;
                break;
            case 's': // --no-tracer
                tracer = 0;
                break;
            case 'r': // --root
                opt_setid(&default_uid, 0, "uid");
                opt_setid(&default_gid, 0, "gid");
                break;
            case 'h': // -h or --help
            case '?':
            default:
                usage(argv);
                break;
        }
    }

    char** targv = &argv[optind];
    char* default_argv[] = {NULL, NULL};
    if (optind >= argc) {
        // no target specified, use user's shell
        char *shell = getenv("SHELL");
        if (!shell || !*shell) {
            shell = "/bin/sh";
        }
        default_argv[0] = shell;
        targv = default_argv;
    }

    // initialize starting IDs
    id_state_t base_id;
    if (default_uid == (uid_t)-1) { default_uid = getuid(); }
    if (default_gid == (gid_t)-1) { default_gid = getgid(); }
    base_id.id[0].real = base_id.id[0].effective = base_id.id[0].saved = default_uid;
    base_id.id[1].real = base_id.id[1].effective = base_id.id[1].saved = default_gid;

    const seccomp_fprog* filters[] = { get_filter_trace(), get_filter_fakechown(), NULL };
    if (fakeroot) {
        filters[0] = get_filter_fakeroot();
        filters[1] = get_filter_fakechown();
        filters[2] = NULL;
    }
    if (!tracer) {
        filters[0] = get_filter_fakechown();
        filters[1] = NULL;
    }

    pseudo_config_t cfg;
    pseudo_init_config(&cfg);

    cfg.cfg_child.child_argv    = targv;
    cfg.cfg_child.filters       = filters;
    cfg.cfg_parent.base_id      = base_id;
    cfg.cfg_parent.virt_enabled = !fakeroot;

    return pseudo_run(&cfg);
}

