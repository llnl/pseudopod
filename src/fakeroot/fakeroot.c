/* Copyright (c) Lawrence Livermore National Security, LLC and other Pseudopod
   Contributors. See top-level LICENSE and COPYRIGHT files for dates and other
   details.

   SPDX-License-Identifier: Apache-2.0 */

/* WARNING: At present, this file is merely Reid’s musings about APIs and is
   unlikely to even compile. In porticular, lots of this belongs elsewhere in
   libpseudo. */

/* GOAL: No callbacks needed for simple (i.e., fake success) mode. */

char usage[] = "\
Usage: fakeroot [OPTION...] [--] PROG [ARG ...]\n\
\n\
Run the executable PROG with zero or more arguments ARG in a root-emulated\n\
environment, similarly to Debian’s fakeroot(1) and a few others [1], using\n\
seccomp filters.\n\
\n\
System call groups to emulate:\n\
\n\
  -a, --all[=MODE]        all of the below\n\
  -f, --files[=MODE]      file ownership: chown(2), etc.\n\
  -m, --mknod[=MODE]      privileged uses of mknod(2) and mknodat(2)\n\
  -p, --processes[=MODE]  process user and group IDs: setresuid(2), etc.\n\
\n\
Other flags:\n\
\n\
  -g, --gid=GID   initial real, effective, and saved group ID (default 0)\n\
  -h, -?, --help  show this help message and exit\n\
  -u, --uid=UID   initial real, effective, and saved user ID (default 0)\n\
\n\
There are two root emulation modes (MODE above):\n\
\n\
  simple      Emulated system calls are intercepted and (fake) success is\n\
              returned to the wrapped process. That is, everything appears\n\
              to work but nothing actually happens, and no state is retained,\n\
              so even basic consistency checks will fail.\n\
\n\
              For example, with --files=simple, calling chown(2) on a file\n\
              will succeed, with no chown(2) call acually happening, but a\n\
              subsequent stat(2) is not intercepted and will return the\n\
              original, unchanged owner of the file.\n\
\n\
              This is the “zero-consistency” root emulation described in [2].\n\
\n\
  consistent  Emulated system calls are interecepted FIXME.\n\
\n\
              For example, with --files=consistent, calling chown(2) on a\n\
              file will succeed, with no chown(2) call acually happening, but\n\
              the desired new owner is recorded. Then, a subsequent stat(2)\n\
              is also intercepted, and the system call is actually made, but\n\
              the “struct stat” it returns is adjusted to reflect the owner\n\
              that the program tried to set with chown(2). That is, the\n\
              calling process sees a fake but consistent owner for the file.\n\
\n\
If not specified, MODE is consistent.\n\
\n\
[1]: https://manpages.debian.org/trixie/fakeroot/fakeroot.1.en.html\n\
[2]: https://doi.org/10.1109/SCW63240.2024.00023\n";

/* This example program is a fakeroot(1)-alike, providing root emulation but
   no containerization. It works similarly to Debian’s version [1] but has a different CLI.

   [1]: https://manpages.debian.org/trixie/fakeroot/fakeroot.1.en.html

*/

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "pseudo.h"


/** Types **/

typedef enum {
   PDO_EMU_NONE,       // not intercepted
   PDO_EMU_SIMPLE,     // fake success, no attempt at consistency
   PDO_EMU_CONSISTENT  // emulate consistently in userspace
} pdo_emulation_kind_t;

// Reasoning to provide the call back function and extra arguments separately:
// If there are no extra arguments, then the caller can just give a function
// argument without needing to package up a pseudo_cb_t.
typedef struct {
   long number;           // system call number, e.g. __NR_getrandom
   syscall_cb_func_t *f;  // callback function; if NULL then just return 0
   void *args;            // extra arguments to callback (FIXME: really needed?)
} pdo_syscall_disp_t;

// File metadata we care about.
typedef struct {
   // file identifiers
   dev_t dev;     // device containing file
   ino_t ino;     // inode of file
   char *path;    // path to file
   int fd;        // file descriptor or -1 if not open
   // metadata
   uid_t uid;     // owner
   gid_t gid;     // group
   mode_t type;   // type (only the type bits, i.e. st_mode & S_IFMT)
   dev_t rdev;    // device ID for file if S_IFBLK or S_IFCHR
} pdo_file_info_t;


/** Globals **/

// Classes of syscalls we can emulate.
static pdo_emulation_kind_t file_ids_emu = PDO_EMU_NONE;
static pdo_emulation_kind_t proc_ids_emu = PDO_EMU_NONE;
static pdo_emulation_kind_t mknod_emu = PDO_EMU_NONE;


// Actual lists of the system calls in each class.
//
// NOTE: This proposes that each callback deal with a single system call,
// which would eliminate big case statements e.g. the one in
// handle_uid_syscalls(). Possibly also the extra arguments? On the other hand
// maybe there is more boilerplace decoding and re-encoding things?
//
// NOTE: This also proposes a shorter prefix for public libpseudo objects, in
// order to conserve line space, specifically “pdo_” but there are certainly
// alternatives. Downside is that “pseudo_” is more clear.
//
// FIXME: These tables could be derived at compile time?

// File ID system calls we catch in either simple or consistent mode.
pdo_syscall_disp_t file_id_syscalls[] = {
   { SYS_chown,  pdo_hdl_chown  },  // FIXME: SYS_foo vs. __NR_foo?
   { SYS_fchown, pdo_hdl_fchown },
   { SYS_lchown, pdo_hdl_lchown },  // FIXME: not defined on aarch64, now what???
   // ... fchownat(2) etc.
   { 0 }
};
// FIle ID syscalls we only catch in consistent mode.
pdo_syscall_disp_t file_id_syscalls_consistent[] = {
   { SYS_stat,   pdo_hdl_stat,  },
   { SYS_rename, pdo_hdl_rename },
   // ...
   { 0 }
};

pdo_syscall_disp_t proc_id_syscalls[] = {
   { SYS_setuid,  pdo_hdl_setuid },
   { SYS_seteuid, pdo_hdl_seteuid },
   // ...
   { 0 }
};
pdo_syscall_disp_t proc_id_syscalls_consistent[] = {
   { SYS_getuid, pdo_hdl_getuid },
   { SYS_geteuid, pdo_hdl_geteuid },
   // ...
   { 0 }
};


static struct option lopts[] = {
   { "all",  optional_argument, NULL, 'a' },
   // ...
   { 0 }
};



/** Main **/

int main(int argc, char **argv)
{
   pseudo_config_t cfg;
   seccomp_fprog *filter;
   pid_t child_pid;

   while ((int opt = getopt_long(...)) != -1) {
      // ... parse command line options
   }

   pseudo_init_cfg(&cfg);

   // I expect this would actually live in libpseudo somewhere and this
   // program would call somethign like
   // “pdo_add_cfgs(pdo_get_file_ids_simple())”.
   switch (file_ids_emu) {
   case PDO_EMU_SIMPLE: {
      for (int i = 0; file_id_syscalls[i].number != 0; i++)
         pdo_add_fake_success(&cfg, file_id_syscalls[i].number);
   } break;
   case PDO_EMU_CONSISTENT: {
      for (int i = 0; file_id_syscalls[i].number != 0; i++)
         pdo_add_callback(&cfg, file_id_syscalls[i].number,
                                file_id_syscalls[i].f);
      for (int i = 0; file_id_syscalls_consistent[i].number != 0; i++)
         pdo_add_callback(&cfg, file_id_syscalls_consistent[i].number,
                                file_id_syscalls_consistent[i].f);
   } break;
   case PDO_EMU_NONE:
      break;
   }

   switch(proc_ids_emu) {
      // similarly
   }

   // mknod(2) and mknodat(2) are special because we need to examine their
   // arguments before deciding whether to emulate. Thus we have to add a BPF
   // fragment to the config rather than just a syscall to fake or callback.
   //
   // The two pdo_fragment_ functions here return the appropriate fragment.
   // They have to know the emulation mode to decide whether to
   // SECCOMP_RET_ERRNO or SECCOMP_RET_TRACE.
   if (mknod_emu != PDO_EMU_NONE) {
      pdo_add_fragment(&cfg, pdo_fragment_mknod(mknod_emu));
      pdo_add_fragment(&cfg, pdo_fragment_mknodat(mknodat_emu));
      if (mknod_emu == PDO_EMU_CONSISTENT) {
#if PDO_HAVE_SYSCALL(mknod)
         pdo_register_callback(SYS_mknod, pdo_hdl_mknod);
#endif
         pdo_register_callback(SYS_mknodat, pdo_hdl_mknodat);
   }

   /* This function compiles all the function emulation we added above into a
      BPF program. It also adds two things:

      1. Prepend fragment that validates architecture matches the build
         architecture.

      2. Add BPF code for the following. If any callbacks are installed for
         the process UID/GID stuff, we need to also emulate the UID/GID
         syscalls for any children that are spawned; that is, the descendant
         processes need to be added to the process state table. Ways to deal
         with this include:

         a. As part of the callbacks for the UID/GID syscalls, add the calling
            process to the state table on the first such call. The problem is
            that if the process is re-parented before such a syscall, e.g. if
            the wrapped process starts a grandchild-style daemon, then
            grandchild’s parent will be init(8) (or a subreaper), which may be
            outside the wrapped environment and thus not in the state table.
            That is, in the following sequence, we lose the grandchild’s
            corred UID/GID state. (FIXME: Are there other ways we could lose a
            process’ state?)

            1. Parent forks a child. Assume parent is in the state table so we
               know its fake IDs.

            2. Child forks a grandchild.

            3. Child exits and becomes a zombie. Child never made any UID/GID
               syscalls and therefore is not added to the state table.

            4. Parent reaps the child with wait(2) etc. and grandchild is
               re-parented to PID 1.

            5. Grandchild asks for its (e.g.) EUID with getuid(2). As part of
               adding it to the state table, we look for its parent process in
               the the table. Because it’s been re-parented, that parent PID
               is 1, which is not in the table, and we’re hosed.

         b. We can also intercept a few syscalls that are likely to appear
            soon after fork(2) or clone(2), for example set_tid_address(2),
            rt_sigprocmask(2), and execve(2). This reduces the race but does
            not eliminate it, because the child could still be re-parented
            first, and some clone(2) uses don’t make any of these early
            syscalls.

         c. Also intercept clone(2), fork(2), and vfork(2), letting the
            syscalls execute as usual but adding the calling process to the
            state table first. Thus, the child is added to the state table
            in Step a.1 above, and Step a.5 succeeds.

            We make two assumptions here:

            1. PID reuse won’t cause a false positive in the state table. We
               could either ignore the problem, assuming that it’s
               sufficiently unlikely for a recycled PID to also make its way
               into the state table and with different process UID/GID (and
               could we detect this case by intercepting _exit(2) etc. to mark
               the process exited?), or we could disambiguate by keying the
               state table on both PID and process start time (field 22 of
               /proc/$PID/stat).

            2. Indefinitely growing the state table doesn’t consume excessive
               memory.

         libpseudo does (a) and (c). */
   filter = pdo_compile_cfg(*cfg);

   child_pid = fork();
   if (child_pid == -1) {   // error
      // ugh ...
   } else if (child_pid) {  // parent
      pdo_handle_events(child_pid);
   } else {                 // child
      pdo_install_filter(filter);
      pdo_validate_filter();  // charliecloud does this with mknod(2)
      execv(argv[0], argv);   // our CLI removed already above
   }

   return 0;
}


/** Functions **/

/** stat(2) wrapper that adjusts results to reflect stored fake file IDs.

      @param[in] pid        Process ID of the process making the syscall.
                            Ignored for this wrapper because all wrapped
                            processes see the same files state.

      @param[in,out] sc     Context for the system call.

      @param[in,out] state  Fake ID table for known files.

      @returns @c PDO_EMU_OK on successful call and adjustment of @c stat(2),
      otherwise @c PDO_EMU_ERROR. Note that the (possibly-fake) result of @c
      stat(2) is returned in @p sc->ret; this function’s return value
      describes only whether something went wrong with the emulation. */
// example tag to allow deriving syscall table at compile time
// .pdo.syscall group:file_id_syscalls_consistent mode:consistent
pdo_emu_status_t pdo_hdl_stat(pid_t pid, syscall_ctx_t *sc, void *state)
{
   // Get the file data by path. This always succeeds. If the file is not yet
   // known, pdo_file_by_path() allocates a new file_meta_t, inserts it into
   // state, then returns it. Somehow it also keeps the file identifiers
   // consistent???
   pdo_file_info_t *f = pdo_file_by_path(sc->args[0], state);

   // This is the statbuf allocated by the caller.
   struct stat *st = sc->args[1];

   // Don’t use the C wrapper because that might do weird things.
   //
   // FIXME: Perhaps we should call fstatat(2) instead? Can we condense all
   // the stat(2) flavors into fstatat(2)? aarch64 doesn’t even have stat(2).
   sc->ret = syscall(SYS_stat, f->path);
   if (sc->ret == -1) {  // error
      if (errno == ENOSYS)
         // bad syscall number, so internal error
         return PDO_EMU_ERROR;
      // syscall failed but emulation succeeded
   } else {              // successful stat(2)
      st->st_uid = f->uid;
      st->st_gid = f->gid;
      st->st_mode &= f->type;
      st->st_rdev = f->rdev;
      // FIXME: maybe here is where we synchronize the file identifiers?
   }
   return PDO_EMU_OK;
}
