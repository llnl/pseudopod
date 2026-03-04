#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <error.h>
#include <string.h>
#include <inttypes.h>

int test_apt_sandbox_verify() {
    int apt_gid = 65534;
    int apt_uid = 42;

    if(syscall(__NR_setgroups, 1, &apt_gid) != 0) {
        return -1;
    }
    if(syscall(__NR_setresgid, apt_gid, apt_gid, apt_gid) != 0) {
        return -2;
    }
    if(syscall(__NR_setresuid, apt_uid, apt_uid, apt_uid) != 0) {
        return -3;
    }

    if(syscall(__NR_getgid) != apt_gid) {
        return -4;
    }
    if(syscall(__NR_getegid) != apt_gid) {
        return -5;
    }
    if(syscall(__NR_getuid) != apt_uid) {
        return -6;
    }
    if(syscall(__NR_geteuid) != apt_uid) {
        return -7;
    }

    int ruid = -1, euid = -1, suid = -1;
    if(syscall(__NR_getresuid, &ruid, &euid, &suid) != 0) {
        return -8;
    } else {
        if (suid != apt_uid) {
            return -9;
        }
    }
    int rgid = -1, egid = -1, sgid = -1;
    if(syscall(__NR_getresgid, &rgid, &egid, &sgid) != 0) {
        return -10;
    } else {
        if (sgid != apt_gid) {
            return -11;
        }
    }
    return 0;
}

int main() {
    int r = test_apt_sandbox_verify();
    if (r) {
        fprintf(stderr, "Apt test failed: %d\n", r);
    }
    return r;
}
