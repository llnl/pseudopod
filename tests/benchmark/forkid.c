#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
  FANOUT = 8,
  DEPTH  = 6
};

static void die(const char *msg) {
  int e = errno;
  fprintf(stderr, "fatal: %s (errno=%d: %s)\n", msg, e, strerror(e));
  _exit(2);
}

static void leaf_check_uid(void) {
//     fprintf(stderr, "hello from %ld!\n", (long)getpid());
  uid_t ou = getuid();
  if (setuid(ou) != 0) {
    perror("setuid");
    _exit(1);
  }

  uid_t u = getuid();
  if (u != ou) {
    fprintf(stderr, "pid=%u: getuid() returned %u, expected %u\n", getpid(), u, ou);
    _exit(1);
  }

  _exit(0);
}

static void spawn_tree(int depth_remaining) {
  if (depth_remaining == 0) {
    leaf_check_uid();
  }

  pid_t kids[FANOUT];
  int i;

  for (i = 0; i < FANOUT; i++) {
    pid_t p = fork();
    if (p < 0) {
      die("fork failed");
    }
    if (p == 0) {
      spawn_tree(depth_remaining - 1);
      _exit(0);
    }
    kids[i] = p;
  }

  int status;
  int rc = 0;
  for (i = 0; i < FANOUT; i++) {
    pid_t w;
    do {
      w = waitpid(kids[i], &status, 0);
    } while (w < 0 && errno == EINTR);

    if (w < 0) {
      fprintf(stderr, "pid=%ld: waitpid failed for child %ld: %s\n",
              (long)getpid(), (long)kids[i], strerror(errno));
      rc = 1;
      continue;
    }

    if (WIFEXITED(status)) {
      int ec = WEXITSTATUS(status);
      if (ec != 0) rc = 1;
    } else if (WIFSIGNALED(status)) {
      fprintf(stderr, "pid=%ld: child %ld died by signal %d\n",
              (long)getpid(), (long)kids[i], WTERMSIG(status));
      rc = 1;
    } else {
      rc = 1;
    }
  }

  _exit(rc);
}

int main(void) {
  spawn_tree(DEPTH);
  return 0;
}
