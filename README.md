# pseudopod
Pseudopod is a utility that makes it easier to build and run **unprivileged containers** with Podman in Livermore Computing's HPC environment.

It provides a lightweight UID/GID emulation layer without requiring `subuid` and `subgid` allocations or privileged user namespaces.

## Overview
This repository contains these components:

| Component   | Description |
|-------------|-------------|
| `pseudopod` | User-facing CLI tool that sets up namespaces, tmpfs mounts, and environment variables for Podman and other tools. |
| `libpseudo` | The core library that implements the syscall emulation logic. |
| `pseudo`    | Demonstrates a minimal implementation of `libpseudo`. Emulates UID and GID related syscalls using `seccomp` and `ptrace`. |

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

- `auto` (default)
   Automatically use `subuid` if available, otherwise fall back to `virtual` mode.
- `subuid`
   No emulation. Use a privileged user namespace with `subuid` ranges. This gives the lowest overhead when `subuid` is available.
- `virtual`
   Enable UID/GID virtualization in an **unprivileged** user namespace with a single root mapping. This simulates a privileged namespace for the application, without needing real `subuid` mappings.
- `fakeroot`
   No virtualization of IDs. Installs a `seccomp` based fakeroot filter so that `setuid` and `getuid` always appear to return `0`. This is similar to classic `fakeroot`, and may be sufficient for many build workflows.

### `tmpfs` mount helper
Pseudopod sets up a mount namespace, and can mount `tmpfs` volumes on host paths before invoking the target program.

- By default, a `tmpfs` is mounted on top of `/run/user/`.
- This behavior can be disabled with a flag, or extended by specifying additional `tmpfs` mount points.

This is useful for keeping Podman state and container metadata off shared filesystems, and can improve performance and reduce filesystem lock contention on HPC systems.

### Podman namespace setup helper
Pseudopod sets environment variables expected by rootless Podman, similar to `podman unshare`:

- `_CONTAINERS_USERNS_CONFIGURED`
- `_CONTAINERS_ROOTLESS_UID`
- `_CONTAINERS_ROOTLESS_GID`

This allows Podman to understand that it is already running inside an appropriately configured user namespace.

### MPI launch helper
A common hurdle to launching MPI jobs with Podman containers is ensuring that the PMI file descriptor is forwarded correctly so that the rank inside the container can set up the MPI communicator. Pseudopod helps with this:

- If the `PMI_FD` environment variable is set, Pseudopod moves it to the lowest unused file descriptor and updates `PMI_FD` accordingly.
- Pseudopod also sets `PRESERVE_FDS` to a suitable `--preserve-fds=...` argument for `podman run`. For example, if `PMI_FD=3`, then `PRESERVE_FDS=--preserve-fds=1`

This simplifies launching MPI jobs under Podman by preserving the PMI file descriptor across the container boundary.

```bash
$ srun -N 1 -n 4 pseudopod podman run '$PRESERVE_FDS' ...
```

### Deferred `seccomp` filtering in `virtual` mode

Podman allows the user to specify a custom `seccomp` profile via:
```
pseudopod virtual --trace=off podman run --security-opt=seccomp=<profile.json> ...
```
When running in `virtual` mode:

- The `--trace=off` flag tells Pseudopod **not** to install its built in `seccomp` filter.
- When used with the Podman compatible `trace.json` provided in this repository, emulation is applied only to processes **inside** the container, not to Podman itself.

## Requirements
- Linux with user namespaces enabled
  `sysctl user.max_user_namespaces` must be greater than 0.
- Linux kernel built with `seccomp` support, with `SCMP_ACT_TRACE`.
- `process_vm_writev` support, plus `ptrace` permission to trace the target and its children.

Pseudopod currently supports `x86_64`, `aarch64`, and `ppc64le` architectures.

## Building
Dependencies:

- C and C++ compiler.
- `libcap` (used to detect whether `subuid` / `subgid` are usable).

By default, `libgcc` and `libc++` are linked statically.

## Performance
The emulation layer imposes:

- No overhead for unrelated syscalls.
- No pthread attach latency on thread/fork creation.
- Low overhead for intercepted syscalls, since `seccomp` only traps the specific calls Pseudopod implements.

### Potential performance bottlenecks
- The syscall emulation layer is currently single threaded.
- Increased latency for intercepted syscalls, especially on syscall heavy workloads.
- Maintains a state table for each running subprocess.


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

## `libpseudo` and callback hooks
The core emulation logic is provided by `libpseudo`. It is responsible for:

- Launching a target program under `ptrace`. Any children it creates automatically inherit the `libpseudo` implementation as a ptracer without needing to explicitly attach or seize.
- Installing a `seccomp` filter that triggers ptrace events only on specific syscalls, while allowing everything else to run normally.
- Event loop with callback hooks that allow implementations to emulate syscalls in userspace.

Client calls to `pseudo_run_child` do not return until all child processes have terminated.

### Callback hooks
`libpseudo` exposes callback hooks for:

- Parent process after `clone`
  For example, Pseudopod uses this to set up namespaces for the child process.
- Child process before `execvp` and before `seccomp` filters are installed
  For example, Pseudopod uses this to configure volume mounts and environment variables.
- Custom syscall handling
  Allows callers to extend or modify the behavior of specific syscalls in the emulation layer.

## Technical details
Pseudopod's UID/GID emulation layer intercepts and implements the following syscalls in userspace:

- `setuid`, `setreuid`, `setresuid`
- `setgid`, `setregid`, `setresgid`
- `getuid`, `geteuid`, `getresuid`
- `getgid`, `getegid`, `getresgid`

The following syscalls have their return value faked as 0 via `seccomp`:
- `setgroups`
- `chown`
- `lchown`
- `fchown`
- `fchownat`

The emulation layer:
- Maintains a per thread “virtual” credential state: real, effective, and saved UIDs and GIDs.
- Returns results to the tracee as if the syscalls executed successfully, without changing kernel state.
- For `getresuid` / `getresgid`, writes results directly into the tracee’s memory using `process_vm_writev`, with a `PTRACE_PEEK` / `PTRACE_POKE` fallback.

## Limitations
- Virtual IDs **do not** affect the filesystem.
  A file created after a call to `setuid` will have its owner as the original UID. Container images built with this method will have flattened permissions (all files and directories owned by the same user/group). This also affects container images at rest on the filesystem (eg. after `podman pull`).
- Permission checks for the virual IDs are **not** modeled.
  The kernel continues to enforce the **real** UID/GID for all permission checks. `setuid` appears to succeed to the application, but does not grant real privileges. Similarly, `getuid` may imply no permissions to access a file, but access will succeed if the user would otherwise have permissions.
- ID calls are modeled per thread rather than per process. `setuid` in a thread will only affect that thread.

## Examples
Run a command with simulated root, without real privilege changes:
```bash
$ pseudo --root id
uid=0(root) gid=0(root) groups=0(root),65534
```

Build a container:
```bash
pseudopod podman build -t ubuntu -f Dockerfile.ubuntu .
```

Attach the trace seccomp filter after starting the container:
```bash
pseudopod virtual --tracer off podman build --security-opt=seccomp=./trace.json -t ubuntu -f Dockerfile.ubuntu .
pseudopod virtual --tracer off podman run --security-opt=seccomp=./trace.json ubuntu:latest
```

## Authors
- Elena Green (green97@llnl.gov) - Primary author


## License
This project is licensed under the Apache 2.0 license (with LLVM exceptions) - see the [LICENSE](LICENSE) file for details.
