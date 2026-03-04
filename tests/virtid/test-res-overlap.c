#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <error.h>
#include <string.h>
#include <inttypes.h>

int test_res_overlap() {
    char id_buf[sizeof(uid_t) * 4];
    memset(id_buf, 0xAA, sizeof(id_buf));
    if(syscall(__NR_setresgid, 511, 511, 511) != 0) {
        return -1;
    }
    if(syscall(__NR_setresuid, 511, 511, 511) != 0) {
        return -2;
    }

    // assume uid_t/gid_t is 4 bytes
    uid_t* ruid = (uid_t*)&id_buf[0]; // [0-3]
    uid_t* euid = (uid_t*)&id_buf[2]; // [2-5]
    uid_t* suid = (uid_t*)&id_buf[4]; // [4-7]
    if(syscall(__NR_getresuid, &ruid, &euid, &suid) != 0) {
        return -3;
    } else {
        if (*ruid != 0) {
            return -4;
        }
        if (*euid != 0) {
            return -5;
        }
        if (*suid != 0) {
            return -6;
        }
    }
    memset(id_buf, 0xAA, sizeof(id_buf));
    gid_t* rgid = (gid_t*)&id_buf[2]; // [2-5] [0000_ff01_0000]
    gid_t* egid = (gid_t*)&id_buf[0]; // [0-3] [ff01_0000_0000]
    gid_t* sgid = (gid_t*)&id_buf[1]; // [1-4] [00ff_0100_0000]
                                      // final [ffff_0100_0000]
    // r/e/s gid is 0x000001ff
    if(syscall(__NR_getresgid, rgid, egid, sgid) != 0) {
        return -7;
    } else {
        if (*rgid != 0x00000001) {
            return -8;
        }
        if (*egid != 0x0001ffff) {
            return -9;
        }
        if (*sgid != 0x000001ff) {
            return -10;
        }
    }
    return 0;
}


int main() {
    int r = test_res_overlap();
    if (r) {
        fprintf(stderr, "resid overlapping test failed: %d\n", r);
    }
    return r;
}
