#!/usr/bin/env python3
"""
Generate shared syscall-table rows from a Linux kernel tree. Intended for
developer use only.

This module slurps syscall numbers for multiple architectures from a Linux
kernel source tree and generates a formatted, source-of-truth, NR_MAP table 
used in seccomp and virtid configurations.

Kernel version v6.6.129 (a stable long-term support release) is the default
source.

(Syscall numbers from UAPI headers are stable and do not change across kernel
 versions, thus suitable for canonical valid syscall mappings across different
 kernel versions.)

Supported architectures:
    - x86_64             (SC_X86_64)
    - i386               (SC_I386)
    - ARM64              (SC_AARCH64)
    - ARM                (SC_ARM)
    - PowerPC 64-bit LE  (SC_PPC64LE)
    - s390x              (SC_S390X)

The module handles architecture-specific quirks, including:
    - Legacy 16-bit uid/gid syscall interfaces on 32-bit architectures
    - Different syscall table formats across architectures
    - ABI preference ordering for syscall resolution

If the kernel tree is not present locally, it will be automatically cloned
from kernel.org's stable repository to $HOME/.pseudopod.
"""

"""Generate shared syscall-table rows from a Linux kernel tree."""

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


DEFAULT_KERNEL_VERSION = "v6.6.129"
KERNEL_GIT_URL = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"


TRACE_SYSCALLS = (
    "setuid",
    "setgid",
    "getuid",
    "getgid",
    "geteuid",
    "getegid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
    "getresuid",
    "getresgid",
)


# On 32-bit i386 and ARM, the unsuffixed uid/gid syscall names still refer to
# the legacy 16-bit interfaces. Pseudopod needs the seccomp-visible 32-bit
# variants, so those architectures must look up the kernel table's *32 names
# while still emitting the canonical syscall names in the final NR_MAP rows.
UID_GID_SYSCALL_32_OVERRIDES = {
    name: f"{name}32"
    for name in TRACE_SYSCALLS
}

@dataclass(frozen=True)
class ArchSpec:
    label: str
    nr_map_name: str
    candidates: Tuple[str, ...]
    abi_preference: Tuple[str, ...] = ()
    syscall_name_overrides: Optional[Dict[str, str]] = None


ARCH_SPECS = (
    ArchSpec(
        "SC_AARCH64",
        "aarch64",
        (
            "arch/arm64/tools/syscall_64.tbl",
            "arch/arm64/tools/syscall.tbl",
            "include/uapi/asm-generic/unistd.h",
        ),
        ("common", "64", "aarch64"),
    ),
    ArchSpec(
        "SC_ARM",
        "arm",
        ("arch/arm/tools/syscall.tbl",),
        ("common", "eabi", "oabi"),
        UID_GID_SYSCALL_32_OVERRIDES,
    ),
    ArchSpec(
        "SC_I386",
        "x86_i386",
        ("arch/x86/entry/syscalls/syscall_32.tbl",),
        ("i386", "ia32", "32", "common"),
        UID_GID_SYSCALL_32_OVERRIDES,
    ),
    ArchSpec(
        "SC_PPC64LE",
        "ppc64le",
        ("arch/powerpc/kernel/syscalls/syscall.tbl",),
        ("common", "64"),
    ),
    ArchSpec(
        "SC_S390X",
        "s390x",
        ("arch/s390/kernel/syscalls/syscall.tbl",),
        ("common", "64"),
    ),
    ArchSpec(
        "SC_X86_64",
        "x86_64",
        ("arch/x86/entry/syscalls/syscall_64.tbl",),
        ("common", "64"),
    ),
)

NR_MAP_ARCH_ORDER = (
    "SC_X86_64",
    "SC_I386",
    "SC_AARCH64",
    "SC_ARM",
    "SC_PPC64LE",
    "SC_S390X",
)


HEADER_DEFINE_RE = re.compile(r"^#define\s+__NR_([A-Za-z0-9_]+)\s+([0-9]+|0x[0-9A-Fa-f]+)\b")


def parse_args() -> argparse.Namespace:
    default_kernel_tree = Path.home() / ".pseudopod" / "dev" / DEFAULT_KERNEL_VERSION

    parser = argparse.ArgumentParser(
        description=(
            "Slurp syscall numbers for shared seccomp/virtid syscall-table "
            "rows from a Linux kernel source tree. If the tree is missing, "
            "clone the pinned longterm kernel first."
        )
    )
    parser.add_argument(
        "kernel_tree",
        type=Path,
        nargs="?",
        default=default_kernel_tree,
        help=(
            "Path to the root of the kernel source tree. "
            "Default: %(default)s"
        ),
    )
    parser.add_argument(
        "--kernel-version",
        default=DEFAULT_KERNEL_VERSION,
        help=(
            "Kernel tag or branch to clone from kernel.org stable. "
            "Default: %(default)s"
        ),
    )
    return parser.parse_args()


def parse_syscall_tbl(path: Path) -> Dict[str, List[Tuple[str, int]]]:
    out: Dict[str, List[Tuple[str, int]]] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        fields = line.split()
        if len(fields) < 3:
            continue

        try:
            nr = int(fields[0], 0)
        except ValueError:
            continue

        abi = fields[1]
        name = fields[2]
        out.setdefault(name, []).append((abi, nr))

    return out


def parse_unistd_header(path: Path) -> Dict[str, int]:
    out: Dict[str, int] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        match = HEADER_DEFINE_RE.match(raw_line)
        if not match:
            continue
        out[match.group(1)] = int(match.group(2), 0)

    return out


def load_syscall_map(root: Path, spec: ArchSpec) -> Dict[str, int]:
    for relpath in spec.candidates:
        path = root / relpath
        if not path.is_file():
            continue

        if path.suffix == ".tbl":
            table = parse_syscall_tbl(path)
            resolved: Dict[str, int] = {}
            for name in TRACE_SYSCALLS:
                lookup_name = name
                if spec.syscall_name_overrides is not None:
                    lookup_name = spec.syscall_name_overrides.get(name, name)

                entries = table.get(lookup_name)
                if not entries:
                    raise KeyError(
                        f"{spec.label}: missing syscall '{lookup_name}' "
                        f"for '{name}' in {path}"
                    )

                chosen_nr = None
                for abi in spec.abi_preference:
                    for entry_abi, nr in entries:
                        if entry_abi == abi:
                            chosen_nr = nr
                            break
                    if chosen_nr is not None:
                        break

                if chosen_nr is None:
                    if len(entries) == 1:
                        chosen_nr = entries[0][1]
                    else:
                        abi_list = ", ".join(abi for abi, _nr in entries)
                        raise KeyError(
                            f"{spec.label}: ambiguous syscall '{name}' in {path} "
                            f"(available ABIs: {abi_list})"
                        )

                resolved[name] = chosen_nr

            return resolved

        header = parse_unistd_header(path)
        missing = [name for name in TRACE_SYSCALLS if name not in header]
        if missing:
            missing_text = ", ".join(missing)
            raise KeyError(f"{spec.label}: missing syscalls in {path}: {missing_text}")
        return {name: header[name] for name in TRACE_SYSCALLS}

    tried = ", ".join(spec.candidates)
    raise FileNotFoundError(f"{spec.label}: no supported syscall source found; tried {tried}")


def clone_kernel_tree(kernel_tree: Path, kernel_version: str) -> None:
    parent = kernel_tree.parent
    if not parent.is_dir():
        parent.mkdir(parents=True)

    subprocess.check_call(
        (
            "git",
            "clone",
            "--depth",
            "1",
            "--branch",
            kernel_version,
            KERNEL_GIT_URL,
            str(kernel_tree),
        )
    )


def ensure_kernel_tree(kernel_tree: Path, kernel_version: str) -> Path:
    if kernel_tree.is_dir():
        return kernel_tree

    if kernel_tree.exists():
        raise RuntimeError(
            "kernel tree path exists but is not a directory: {0}".format(kernel_tree)
        )

    print("info: cloning {0} from {1} into {2}".format(kernel_version,
                                                       KERNEL_GIT_URL,
                                                       kernel_tree), file=sys.stderr)
    clone_kernel_tree(kernel_tree, kernel_version)
    return kernel_tree


def render_nr_map_table(resolved: Dict[str, Dict[str, int]]) -> str:
    specs_by_label = {spec.label: spec for spec in ARCH_SPECS}
    ordered_specs = [specs_by_label[label] for label in NR_MAP_ARCH_ORDER]

    rows = []
    for syscall in TRACE_SYSCALLS:
        values = [str(resolved[spec.label][syscall]) for spec in ordered_specs]
        rows.append((values, syscall))

    value_widths = []
    for index, spec in enumerate(ordered_specs):
        width = len(spec.nr_map_name)
        for values, _syscall in rows:
            width = max(width, len(values[index]))
        value_widths.append(width)

    map_prefix = "NR_MAP("

    header_cells = [
        f"{spec.nr_map_name:>{value_widths[index]}}"
        for index, spec in enumerate(ordered_specs)
    ]
    lines = [f"{'':<{len(map_prefix)}} {'  '.join(header_cells)}  name"]

    for values, syscall in rows:
        padded_values = [
            f"{value:>{value_widths[index]}}" for index, value in enumerate(values)
        ]
        lines.append(f"{map_prefix} {', '.join(padded_values)} )  {syscall}")

    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    kernel_tree = args.kernel_tree.expanduser().resolve()

    try:
        kernel_tree = ensure_kernel_tree(kernel_tree, args.kernel_version)
    except (RuntimeError, OSError, subprocess.CalledProcessError) as exc:
        print("error: {0}".format(exc), file=sys.stderr)
        return 1

    try:
        resolved = {
            spec.label: load_syscall_map(kernel_tree, spec)
            for spec in ARCH_SPECS
        }
    except (FileNotFoundError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(render_nr_map_table(resolved))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
