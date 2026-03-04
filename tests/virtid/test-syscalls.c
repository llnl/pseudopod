#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <error.h>
#include <inttypes.h>
#include <sys/wait.h>

typedef struct {
    uid_t r, e, s;
} cred_t;


typedef struct {
    struct {
        int nr;
        uid_t arg1, arg2, arg3;
    } set;
    cred_t before;
    cred_t after;

} testcall_t;

typedef struct {
    testcall_t* chain;
    int len;
    int nr_getres;
    int nr_getr;
    int nr_gete;
} testcase_t;


// starting as id 0, do nothing
static testcall_t gid_test_nop[] = {
    {   .set = {__NR_setresgid, 0, 0, 0 },
        .before = {0, 0, 0},
        .after = {0, 0, 0}
    },
    {   .set = {__NR_setresgid, 0, -1, -1 },
        .before = {0, 0, 0},
        .after = {0, 0, 0}
    },
    {   .set = {__NR_setresgid, -1, 0, -1 },
        .before = {0, 0, 0},
        .after = {0, 0, 0}
    },
    {   .set = {__NR_setresgid, -1, -1, 0 },
        .before = {0, 0, 0},
        .after = {0, 0, 0}
    },
    {   .set = {__NR_setresgid, -1, -1, -1 },
        .before = {0, 0, 0},
        .after = {0, 0, 0},
    },
    {   .set = {__NR_setgid, 0, 0, 0 },
        .before = {0, 0, 0},
        .after = {0, 0, 0}
    },
    {   .set = {__NR_setregid, 0, 0, 0 },
        .before = {0, 0, 0},
        .after = {0, 0, 0}
    },
};

static testcall_t uid_test_nop[] = {
    {   .set = {__NR_setresuid, 0, 0, 0 },
        .before = {0, 0, 0},
        .after = {0, 0, 0}
    },
    {   .set = {__NR_setresuid, 0, -1, -1 },
        .before = {0, 0, 0},
        .after = {0, 0, 0}
    },
    {   .set = {__NR_setresuid, -1, 0, -1 },
        .before = {0, 0, 0},
        .after = {0, 0, 0}
    },
    {   .set = {__NR_setresuid, -1, -1, 0 },
        .before = {0, 0, 0},
        .after = {0, 0, 0}
    },
    {   .set = {__NR_setresuid, -1, -1, -1 },
        .before = {0, 0, 0},
        .after = {0, 0, 0},
    },
    {   .set = {__NR_setuid, 0, 0, 0 },
        .before = {0, 0, 0},
        .after = {0, 0, 0}
    },
    {   .set = {__NR_setreuid, 0, 0, 0 },
        .before = {0, 0, 0},
        .after = {0, 0, 0}
    },
};

static testcall_t gid_test_setre[] = {
    // test saved id
    {   .set = {__NR_setregid, 1, -1, 0 },
        .before = {0, 0, 0},
        .after = {1, 0, 0}
    },
    {   .set = {__NR_setregid, -1, 1, 0 },
        .before = {1, 0, 0},
        .after = {1, 1, 0}
    },
    {   .set = {__NR_setgid, 0, 0, 0 },
        .before = {1, 1, 0},
        .after = {0, 0, 0}
    },
    {   .set = {__NR_setregid, -1, 1, 0 },
        .before = {0, 0, 0},
        .after = {0, 1, 1}
    },
    {   .set = {__NR_setregid, -1, 0, 0 },
        .before = {0, 1, 1},
        .after = {0, 0, 1}
    },
    {   .set = {__NR_setgid, 1, 0, 0 },
        .before = {0, 0, 1},
        .after = {1, 1, 1}
    },
};

static testcall_t uid_test_setre[] = {
    // test saved id
    {   .set = {__NR_setreuid, 1, -1, 0 },
        .before = {0, 0, 0},
        .after = {1, 0, 0}
    },
    {   .set = {__NR_setreuid, -1, 1, 0 },
        .before = {1, 0, 0},
        .after = {1, 1, 0}
    },
    // unpriv->priv
    {   .set = {__NR_setuid, 0, 0, 0 },
        .before = {1, 1, 0},
        .after = {1, 0, 0}
    },
    // unpriv->unpriv
    {   .set = {__NR_setresuid, 0, 1, 2 },
        .before = {1, 0, 0},
        .after = {0, 1, 2}
    },
    {   .set = {__NR_setuid, 2, 0, 0 },
        .before = {0, 1, 2},
        .after = {0, 2, 2}
    },
    {   .set = {__NR_setresuid, 0, 0, 0 },
        .before = {0, 2, 2},
        .after = {0, 0, 0}
    },
    {   .set = {__NR_setresuid, 1, 0, 0 },
        .before = {0, 0, 0},
        .after = {1, 0, 0}
    },
    {   .set = {__NR_setreuid, 0, 1, 0 },
        .before = {1, 0, 0},
        .after = {0, 1, 1}
    },
    {   .set = {__NR_setreuid, -1, 0, 0 },
        .before = {0, 1, 1},
        .after = {0, 0, 1}
    },
    {   .set = {__NR_setresuid, 0, 0, 0 },
        .before = {0, 0, 1},
        .after = {0, 0, 0}
    },
    // priv->unpriv
    {   .set = {__NR_setuid, 1, 0, 0 },
        .before = {0, 0, 0},
        .after = {1, 1, 1}
    },
};

static testcall_t gid_test_setid_priv[] = {
    {   // GID: set effective unpriv
        .set = {__NR_setresgid, 0, 1, 2 },
        .before = {0, 0, 0},
        .after = {0, 1, 2}
    },
    {   // GID: test unpriv setuid e(1->2)
        .set = {__NR_setresgid, -1, 2, -1 },
        .before = {0, 1, 2},
        .after = {0, 2, 2}
    },
    {   // GID: reclaim privilege via rgid and reset
        .set = {__NR_setresgid, 0, 0, 0 },
        .before = {0, 2, 2},
        .after = {0, 0, 0}
    },
    {   // GID: set effective privileged
        .set = {__NR_setresgid, 1, 0, 2 },
        .before = {0, 0, 0},
        .after = {1, 0, 2}
    },
    {   // GID: test drop privlieges e(0->2)
        .set = {__NR_setgid, 2, 0, 0 },
        .before = {1, 0, 2},
        .after = {2, 2, 2}
    },
    {   // GID: reclaim privilege via euid and reset
        .set = {__NR_setresgid, 0, 0, 0 },
        .before = {2, 2, 2},
        .after = {0, 0, 0}
    }
};

static testcall_t uid_test_setid_priv[] = {
    {   // UID: set effective unpriv
        .set = {__NR_setresuid, 0, 1, 2 },
        .before = {0, 0, 0},
        .after = {0, 1, 2}
    },
    {   // UID: test unpriv setuid e(1->2)
        .set = {__NR_setuid, 2, 0, 0 },
        .before = {0, 1, 2},
        .after = {0, 2, 2}
    },
    {   // UID: reclaim privilege and reset
        .set = {__NR_setresuid, 0, 0, 0 },
        .before = {0, 2, 2},
        .after = {0, 0, 0}
    },
    {   // UID: set effective privileged
        .set = {__NR_setresuid, 1, 0, 2 },
        .before = {0, 0, 0},
        .after = {1, 0, 2}
    },
    {   // UID: test drop privlieges e(0->2)
        .set = {__NR_setuid, 2, 0, 0 },
        .before = {1, 0, 2},
        .after = {2, 2, 2}
    },
};

static testcase_t id_cases[] = {
    {gid_test_nop,        sizeof(gid_test_nop) / sizeof(testcall_t),        __NR_getresgid, __NR_getgid, __NR_getegid},
    {gid_test_setre,      sizeof(gid_test_setre) / sizeof(testcall_t),      __NR_getresgid, __NR_getgid, __NR_getegid},
    {gid_test_setid_priv, sizeof(gid_test_setid_priv) / sizeof(testcall_t), __NR_getresgid, __NR_getgid, __NR_getegid},
    {uid_test_nop,        sizeof(uid_test_nop) / sizeof(testcall_t),        __NR_getresuid, __NR_getuid, __NR_geteuid},
    {uid_test_setre,      sizeof(uid_test_setre) / sizeof(testcall_t),      __NR_getresuid, __NR_getuid, __NR_geteuid},
    {uid_test_setid_priv, sizeof(uid_test_setid_priv) / sizeof(testcall_t), __NR_getresuid, __NR_getuid, __NR_geteuid},
};

int test_id_call(const testcall_t* test, int nr_getres, int nr_getr, int nr_gete) {
    int r = 0;

    if (nr_getres) {
        cred_t obs = {0, 0, 0};
        syscall(nr_getres, &obs.r, &obs.e, &obs.s);
        if (obs.r != test->before.r) {
            printf("getres: initial real-id mismatch: %d (expected %d)\n", obs.r, test->before.r);
            return -1;
        }
        if (obs.e != test->before.e) {
            printf("getres: initial effective-id mismatch: %d (expected %d)\n", obs.e, test->before.e);
            return -1;
        }
        if (obs.s != test->before.s) {
            printf("getres: initial saved-id mismatch: %d (expected %d)\n", obs.s, test->before.s);
            return -1;
        }
    }


    if ((r = syscall(test->set.nr, test->set.arg1, test->set.arg2, test->set.arg3)) < 0) {
        perror("syscall");
        return -1;
    }

    if (nr_getres) {
        cred_t obs = {0, 0, 0};
        r = syscall(nr_getres, &obs.r, &obs.e, &obs.s);
        if (obs.r != test->after.r) {
            printf("getres: real-id mismatch: %d (expected %d)\n", obs.r, test->after.r);
            return -1;
        }
        if (obs.e != test->after.e) {
            printf("getres: effective-id mismatch: %d (expected %d)\n", obs.e, test->after.e);
            return -1;
        }
        if (obs.s != test->after.s) {
            printf("getres: saved-id mismatch: %d (expected %d)\n", obs.s, test->after.s);
            return -1;
        }
    }

    if (nr_getr) {
        cred_t obs = {0, 0, 0};
        obs.r = syscall(nr_getr);
        if (obs.r != test->after.r) {
            printf("getr: real-id mismatch: %d (expected %d)\n", obs.r, test->after.r);
            return -1;
        }
    }

    if (nr_gete) {
        cred_t obs = {0, 0, 0};
        obs.e = syscall(nr_gete);
        if (obs.e != test->after.e) {
            printf("gete: effective-id mismatch: %d (expected %d)\n", obs.e, test->after.e);
            return -1;
        }
    }
    return 0;
}

int test_chain(testcase_t* testcase) {
    for (int i = 0; i < testcase->len; i++) {
        if (test_id_call(&testcase->chain[i], testcase->nr_getres, testcase->nr_getr, testcase->nr_gete) != 0) {
            printf("Test chain failed: step %d\n", i);
            return -1;
        }
    }
    return 0;
}

int run_test(testcase_t* testcase) {
    int child = 0;
    int wstatus = 0;
    if ((child = fork()) == 0) {
        _exit(test_chain(testcase));
    } else {
        //parent
        do {
            if (wait(&wstatus) < 0) { return -254; }
            if (WIFEXITED(wstatus)) {
                return WEXITSTATUS(wstatus);
            } else if (WIFSIGNALED(wstatus)) {
                return -255;
            }
        } while(1);
    }
    return -1;
}

int main() {
    for (unsigned long i = 0; i < sizeof(id_cases) / sizeof(testcase_t); i++) {
        int r = 0;
        if ((r = run_test(&id_cases[i])) != 0) {
            fprintf(stderr, "Basic test %lu failed: %d\n", i, r);
            return -1;
        }
    }

    return 0;
}
