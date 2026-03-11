# Architecture Overview

This document summarizes the core data structures used by `libpseudo` and the
ID tracking subsystem.

## 1. `libpseudo` Configuration Model

`pseudo_config_t` is the top-level runtime configuration object. It groups
callback lists by execution phase:

- `cfg_child` for tracee setup
- `cfg_syscall` for syscall handling
- `cfg_tracer` for ptrace and waitpid event handling
- `cfg_parent` for parent-side setup after `clone`

Each phase owns a `pseudo_callbacks_t`. This is a growable array of
`pseudo_cb_t` entries. Each `pseudo_cb_t` stores a callback pointer and an
opaque argument pointer. This is the mechanism `libpseudo` uses to let callers
attach behavior at specific points in the tracing and emulation flow.

```mermaid
classDiagram
    class pseudo_config_t {
        +pseudo_config_child_t cfg_child
        +pseudo_config_syscall_t cfg_syscall
        +pseudo_config_tracer_t cfg_tracer
        +pseudo_config_parent_t cfg_parent
    }

    class pseudo_config_child_t {
        +int clone_flags
        +char** child_argv
        +char** child_envp
        +const seccomp_fprog** filters
        +pseudo_callbacks_t cbs
    }

    class pseudo_config_syscall_t {
        +pseudo_callbacks_t cbs
    }

    class pseudo_config_tracer_t {
        +pseudo_callbacks_t cbs
    }

    class pseudo_config_parent_t {
        +pseudo_callbacks_t cbs
    }

    class pseudo_callbacks_t {
        +pseudo_cb_t* callbacks
        +int len
        +int size
    }

    class pseudo_cb_t {
        +void* cb
        +void* cbargs
    }

    pseudo_config_t --> pseudo_config_child_t
    pseudo_config_t --> pseudo_config_syscall_t
    pseudo_config_t --> pseudo_config_tracer_t
    pseudo_config_t --> pseudo_config_parent_t

    pseudo_config_child_t --> pseudo_callbacks_t
    pseudo_config_syscall_t --> pseudo_callbacks_t
    pseudo_config_tracer_t --> pseudo_callbacks_t
    pseudo_config_parent_t --> pseudo_callbacks_t

    pseudo_callbacks_t --> pseudo_cb_t
```

## 2. `idtrack_t` Sparse State Table

`idtrack_t` stores a sparse two-level table of `id_state_t` values, plus a
default `base_id`.

- `l1[]` is the top-level pointer table
- each populated `l1[i]` points to an `_idst_l2` block
- each `_idst_l2` contains a fixed `l2[]` array of `_idst_leaf`
- each `_idst_leaf` contains a `valid` flag and a stored `id_state_t`

`idtrack_t` is a client-owned state object. The current implementation stores
the sparse table and the default base state. Additional fields may be added in
the future without changing the two-level lookup structure.

The diagram below marks that extension point explicitly, but does not name or
imply any unimplemented field.

```mermaid
classDiagram
    class idtrack_t {
        +_idst_l2* l1[IDST_L1_SZ]
        +id_state_t base_id
        .. future extension point ..
    }

    class _idst_l2 {
        +_idst_leaf l2[IDST_L2_SZ]
    }

    class _idst_leaf {
        +uint32_t valid
        +id_state_t v
    }

    class id_state_t {
        +ids_t id[2]
    }

    class ids_t {
        +uint32_t real
        +uint32_t effective
        +uint32_t saved
    }

    idtrack_t --> _idst_l2 : l1[]
    _idst_l2 --> _idst_leaf : l2[]
    _idst_leaf --> id_state_t : v
    idtrack_t --> id_state_t : base_id
    id_state_t --> ids_t : id[0], id[1]
```

### `id_state_t` Payload

`id_state_t` stores two `ids_t` records:

- `id[0]` for user IDs
- `id[1]` for group IDs

This allows the tracker to store separate user and group state for each entry.

Each `ids_t` contains:

- `real`
- `effective`
- `saved`
