# pseudopod

Pseudopod is a utility that makes it easier to build and run **unprivileged containers** with Podman in Livermore Computing's HPC environment.

It provides a lightweight UID/GID emulation layer without requiring `subuid` and `subgid` allocations or privileged user namespaces.

## Overview

This repository contains these components:

| Component   | Description |
|-------------|-------------|
| `pseudopod` | User-facing CLI tool that sets up namespaces, tmpfs mounts, and environment variables for Podman and other tools. |
| `pseudo`    | Demonstrates a minimal implementation of `libpseudo`. Emulates UID and GID related syscalls using `seccomp` and `ptrace`. |
| `libpseudo` | The core library that implements the syscall emulation logic. |

## Why Pseudopod?

In HPC environments, it is often difficult or impossible to obtain `subuid` / `subgid` ranges.

Pseudopod makes it possible to run `podman build` and `podman run` as an unprivileged user without invasive changes to Dockerfiles or container OS configuration.

## Features

### UID/GID emulation

The primary feature of Pseudopod is UID/GID emulation:
- Emulates `set*id` and `get*id` family syscalls in userspace.
- Maintains a separate “virtual” credential state for each child process.
- Makes `getuid` after `setuid` return the expected value, without changing actual kernel credentials.

If `subuid` / `subgid` are enabled and available to the current user, Pseudopod will **prefer** to use them, as this avoids the overhead of syscall emulation.

### Modes of operation

Pseudopod supports several modes that control how user namespaces and emulation are configured:

- `auto`: Automatically use `subuid` if available, otherwise fall back to `virtual` mode.
- `subuid`: No emulation. Use a privileged user namespace with `subuid` ranges. This gives the lowest overhead when `subuid` is available.
- `virtual`: Enable UID/GID virtualization in an **unprivileged** user namespace with a single root mapping. This simulates a privileged namespace for the application, without needing real `subuid` mappings.

- `fakeroot`
  No virtualization of IDs. Installs a `seccomp` based fakeroot filter so that `setuid` and `getuid` always appear to return `0`. This is similar to classic `fakeroot`, and may be sufficient for many build workflows.

### `tmpfs` mount helper

Pseudopod sets up a mount namespace, and can mount `tmpfs` volumes on host paths before invoking the target program.

- By default, a `tmpfs` is mounted on top of `/run/user/`.
- This behavior can be disabled with a flag, or extended by specifying additional `tmpfs` mount points.

This is useful for keeping Podman state and container metadata off shared filesystems, and can improve performance and reduce filesystem load on HPC systems.

### Podman namespace setup helper

Pseudopod sets environment variables expected by rootless Podman, similar to `podman unshare`:

- `_CONTAINERS_USERNS_CONFIGURED`
- `_CONTAINERS_ROOTLESS_UID`
- `_CONTAINERS_ROOTLESS_GID`

This allows Podman to understand that it is already running inside an appropriately configured user namespace.

### MPI launch helper

When running MPI jobs with Podman under Pseudopod, file descriptor handling can be tricky. Pseudopod helps with this:

- If the `PMI_FD` environment variable is set, Pseudopod moves it to the lowest unused file descriptor and updates `PMI_FD` accordingly.
- Pseudopod also sets `PRESERVE_FDS` to a suitable `--preserve-fds=...` argument for `podman run`.

This simplifies launching MPI jobs under Podman by preserving the PMI file descriptor across the container boundary.

### Deferred `seccomp` filtering in `virtual` mode

Podman allows the user to specify a custom `seccomp` profile via:
```bash
--security-opt=seccomp=<profile.json>
```
When running in `virtual` mode:

- The `--trace=off` flag tells Pseudopod **not** to install its built in `seccomp` filter.
- When used with the Podman compatible `trace.json` provided in this repository, emulation is applied only to processes **inside** the container, not to Podman itself.

This separation reduces overhead on Podman and makes it easier to integrate Pseudopod into existing container workflows.
















## Features
The primary feature of Pseudopod is UID/GID emulation. However, if sub*ids are
enabled and available to the current user, Pseudopod will default to using them
in order to provide the lowest overhead. Additionally,

### Modes of operation
- `auto`: Automatically use `subuid` if available, otherwise fall back to
          `virtual` mode.
- `subuid`: No emulation. Use a privileged user namespace with `subuid`s.
- `virtual`: Emulation enabled. Use an unprivileged user namespace with a single
             root mapping. Simulates a privileged namespace.
- `fakeroot`: No emulation. `setuid` and `getuid` always return `0`.


### `tmpfs` mount helper
`pseudopod` also sets up a mount namespace, optionally mounting `tmpfs` volumes
to host paths before calling the target program. By default, a `tmpfs` is
mounted on top of `/run/user/`. This behavior can be disabled with a flag.

### Podman namespace setup helper
`pseudopod` will set the following environment variables, similar to
`podman unshare`:
- `_CONTAINERS_USERNS_CONFIGURED`
- `_CONTAINERS_ROOTLESS_UID`
- `_CONTAINERS_ROOTLESS_GID`

### MPI launch helper
If the `PMI_FD` environment variable is set, it is moved to the lowest unused
file descriptor and the variable updated with the new value. A `PRESERVE_FDS`
variable is provided, pre-populated with an appropriate `--preserve-fds=...`
command-line flag for `podman-run`. This feature simplifies launching MPI jobs
with Podman.


### Deferred `seccomp` filtering in `virtual` mode
Podman allows the user to specify a custom `seccomp` filter to attach to the
process running inside the container by specifying
`--security-opt=seccomp=<profile.json>`. When running in `virtual` mode, the
`--trace=off` flag tells `pseudopod` not to install its built-in seccomp filter.
When used with the podman-compatible `trace.json` supplied in this repository,
the emulation is applied only to the processes inside the container and not to
Podman itself.


## Background
While it is possible to build most containers without privileged namespaces, the
typical approaches involve direct user interventions such as:
- Injecting the `fakeroot` utility into the container and re-writing `RUN`
  stages to use it.
- Modifying the configuration files within the contained OS to remove user
  separation checks.

Attaching a `seccomp` filter that fakes the syscall return values for a set of
otherwise privileged operations (`seccomp fakeroot`) also works for most
containers. However, `apt` within Debian-based containers enforces strict
privilege checks and fails if a call to `getuid` after `setuid` does not return
the expected value. The more complex emulation provided by `libpseduo` allows
these types of check to pass.

## Requirements
- User namespaces supported and enabled (`sysctl user.max_user_namespaces` > 0)
- Linux kernel built with `seccomp` support

## Usage
```
Usage: ./pseudopod <subcommand> [OPTIONS] <target> [args...]
If no subcommand is provided, 'auto' is used.
If no <target> is provided, the user's shell ($SHELL or /bin/sh) is run.

Subcommands (minimal unambiguous prefixes accepted, case insensitive):
  auto        Auto-select based on subuid availability
  subuid      Use privileged user namespace, no virtualization
  virtual     Enable UID virtualization in an unprivileged user namespace
  fakeroot    Seccomp fakeroot emulation in an unprivileged user namespace (no virtualization)

Global options:
  -r, --mount-run=on|off      Mount tmpfs at /run/user  (default on)
  -t, --mount-tmpfs=<path>    Mount a tmpfs at the specified path. May be specified multiple times.
  -h, --help                  Show this help

virtual options:
  -v, --tracer=on|off         Install tracer seccomp profile (default on)
```

---

# pseudo
A tiny hypervisor layer for virtualizing UID and GID syscalls using seccomp and
ptrace. The virtualized process will see consistent return values for `get*id`
after a `set*id` call without actually changing their kernel credentials.

This program does NOT emulate permission checks. `setuid` calls will always work.

## Usage
```
Usage: ./pseudo [OPTIONS] <target> [args...]
Options:
  -u <uid>, --uid=<num>  Set starting UID
  -g <gid>, --gid=<num>  Set starting GID
  -f, --fakeroot         Enable seccomp fakeroot (disables uid virtualization)
  -s, --no-tracer        Disable seccomp tracer (attach it later to enable virtualization)
  -r, --root             Set both UID and GID to root
  -h, --help             Show this help message
Notes:
  If no user/group options are specified, current UID and GID are the default.
  If no <target> is specified, the user's shell ($SHELL or /bin/sh) is run.
  Parsing stops at the first non-option, or at "--".
```

---

# Performance

There is no overhead for unrelated syscalls and a low overhead for intercepted syscalls. `seccomp` enables the interception of only a subset of syscalls rather than processing all syscalls.

### Potential performance bottlenecks:
- The syscall emulation layer is currently single-threaded
- Increased latency for intercepted syscalls

### A real-world performance comparison
In this example, we build a linux kernel for `x86_64` entirely in tmpfs on a machine with 36 physical CPUs.

Baseline:
```
$ make distclean && cp ../config-4.18.0-553.69.1.1toss.t4.x86_64 .config && make olddefconfig && time make -j36
...
real    9m45.208s
user    246m11.685s
sys     37m29.323s
```

With `pseudo`:
```
$ make distclean && cp ../config-4.18.0-553.69.1.1toss.t4.x86_64 .config && make olddefconfig && time pseudo make -j36
...
real    10m3.590s
user    245m16.519s
sys     38m40.882s
```

---

# libpseudo
The core emulation is provided by `libpseudo` which handles running a target binary and recursively attaching a ptracer to its children. Client calls to `pseudo_run_child` do not return until all child processes have terminated.

A minimal usage example of `libpseudo` is provided by the implementation of `pseudo-cli.c`.

## Callback hooks
`libpseudo` provides callback hooks for:
* Parent process post-`clone`
* Child process pre-`execvp` and before seccomp filters are installed.
* Custom `syscall` handling

`pseudopod` uses the parent post-`clone` hook to set up namespaces for the child process and the child pre-`execvp` hook to set up volume mounts and environment variables.

---

# Limitations

- Permission checks are not modeled
- Currently only supports x86_64, aarch64, and ppc64le
- Requires a Linux kernel with seccomp SCMP_ACT_TRACE and process_vm_writev support, and ptrace permissions to trace the target and its children
- ID calls are modeled per-thread rather than per-process

---

# Technical Details

- Launches a target program under ptrace and attaches recursively to any children it creates.
- Installs a seccomp filter that triggers ptrace events only on specific syscalls, while allowing everything else to run normally.
- Intercepts and emulates the following syscalls in userspace:
  - `setuid`, `setreuid`, `setresuid`
  - `setgid`, `setregid`, `setresgid`
  - `getuid`, `geteuid`, `getresuid`
  - `getgid`, `getegid`, `getresgid`
- Seccomp fakes a return value of 0 on these syscalls:
  - `setgroups`
  - `chown`
  - `lchown`
  - `fchown`
  - `fchownat`
- Maintains a per-thread “virtual” credential state: real, effective, and saved UIDs and GIDs.
- Returns results to the tracee as if the syscalls executed, but without changing kernel state.
- For getresuid/getresgid, writes results directly into the tracee’s memory using process_vm_writev, with a PTRACE_PEEK/POKE fallback.

---

# Building

Dependencies:
- C and C++ compiler
- A recent linux kernel (targets RHEL's 4.16)
- libcap (for detecing if subuids are usable)

Note: `libgcc` and `libc++` are linked statically by default.

---

# Examples

- Run a command with simulated root, without real privilege changes:
```bash
$ pseudo --root id
uid=0(root) gid=0(root) groups=0(root),65534
```

- Build a container:
```bash
pseudopod podman build -t ubuntu -f Dockerfile.ubuntu .
```

- Attach the trace seccomp filter after starting the container:
```bash
pseudopod virtual --tracer off podman build --security-opt=seccomp=./trace.json -t ubuntu -f Dockerfile.ubuntu .
pseudopod virtual --tracer off podman run --security-opt=seccomp=./trace.json ubuntu:latest
```

---

# Authors

Elena Green (green97@llnl.gov)

---

# License

This project is licensed under the Apache 2.0 license (with LLVM exceptions) - see the [LICENSE.md](LICENSE.md) file for details.

SPDX-License-Identifier: Apache-2.0
