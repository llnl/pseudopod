#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <error.h>
#include <string.h>
#include <inttypes.h>

int test_res_unaligned() {
    char id_buf[sizeof(uid_t) * 16];
    memset(id_buf, 0xAA, sizeof(id_buf));
    if(syscall(__NR_setresgid, 511, 511, 511) != 0) {
        return -1;
    }
    if(syscall(__NR_setresuid, 511, 511, 511) != 0) {
        return -2;
    }

    // assume uid_t/gid_t is 4 bytes
    uid_t* ruid = (uid_t*)&id_buf[1];                                               // 0[1-4]
    uid_t* euid = (uid_t*)&id_buf[(void*)ruid - (void*)id_buf + sizeof(uid_t) + 1]; // 5[6-9]
    uid_t* suid = (uid_t*)&id_buf[(void*)euid - (void*)id_buf + sizeof(uid_t) + 1]; // 10[11-14]
    if(syscall(__NR_getresuid, ruid, euid, suid) != 0) {
        return -3;
    } else {
        if (*ruid != 511) {
            return -4;
        }
        if (*euid != 511) {
            return -5;
        }
        if (*suid != 511) {
            return -6;
        }
    }
    gid_t* rgid = (gid_t*)&id_buf[(void*)suid - (void*)id_buf + sizeof(uid_t) + 1]; // 15[16-19] - 8-aligned
    gid_t* egid = (gid_t*)&id_buf[(void*)rgid - (void*)id_buf + sizeof(gid_t) + 0]; // [20-23]   - 4-aligned
    gid_t* sgid = (gid_t*)&id_buf[(void*)egid - (void*)id_buf + sizeof(gid_t) + 3]; // 24-26[27-30]
    if(syscall(__NR_getresgid, rgid, egid, sgid) != 0) {
        return -7;
    } else {
        if (*rgid != 511) {
            return -8;
        }
        if (*egid != 511) {
            return -9;
        }
        if (*sgid != 511) {
            return -10;
        }
    }
    return 0;
}

int main() {
    int r = test_res_unaligned();
    if (r) {
        fprintf(stderr, "resid unaligned test failed: %d\n", r);
    }
    return r;
}
