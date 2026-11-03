#!/bin/sh
set -eu
exec python3 -I - "$@" <<'PY'
import os
from pathlib import PurePosixPath
import stat
import subprocess
import sys

MAX_LINES = 1000
SOURCE_SUFFIXES = frozenset("""
.rs .py .pyw .pyi .sh .bash .dash .zsh .ksh .fish
.ps1 .psm1 .psd1 .bat .cmd
.c .h .cc .cpp .cxx .c++ .hh .hpp .hxx .inl .inc
.cs .fs .fsx .vb
.go .java .kt .kts .scala .sc .swift .m .mm
.js .jsx .mjs .cjs .ts .tsx .mts .cts .vue .svelte
.rb .rake .gemspec .php .phtml .pl .pm .lua .r .jl
.ex .exs .erl .hrl .hs .lhs .ml .mli .clj .cljs .cljc
.lisp .lsp .scm .ss .rkt .el .vim .v .sv .vhd .vhdl
.sql .graphql .gql .proto .thrift .zig .nim .nims .d
.asm .s .sass .scss .less .css .html .htm
.cmake .mk .mak .gradle .groovy .awk .sed .tcl
""".split())
SOURCE_NAMES = frozenset({
    "makefile", "gnumakefile", "bsdmakefile", "dockerfile",
    "containerfile", "cmakelists.txt", "justfile", "rakefile",
    "gemfile", "vagrantfile", "jenkinsfile", "sconstruct",
    "sconscript", "meson.build", "meson_options.txt",
    "build", "build.bazel", "workspace", "workspace.bazel",
})
EXCLUDED_DIRECTORIES = frozenset({"vendor", "vendors"})


class GuardError(Exception):
    pass


def git(*args):
    try:
        result = subprocess.run(
            ["git", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise GuardError("cannot execute git") from exc
    if result.returncode:
        raise GuardError("git enumeration failed")
    return result.stdout


def paths(output):
    if output and not output.endswith(b"\0"):
        raise GuardError("invalid Git path framing")
    return set(output[:-1].split(b"\0")) if output else set()


def display(path):
    return ascii(os.fsdecode(path))


def selected_paths():
    prefix = git("rev-parse", "--show-prefix")
    if prefix not in (b"\n", b"\r\n"):
        raise GuardError("run from the repository root")
    candidates = paths(git(
        "ls-files", "-z", "--cached", "--others", "--exclude-standard",
    ))
    for raw in sorted(candidates):
        name = os.fsdecode(raw)
        parts = name.split("/")
        if any(part.casefold() in EXCLUDED_DIRECTORIES for part in parts[:-1]):
            continue
        if (
            not name or os.path.isabs(name) or "\\" in name
            or any(part in ("", ".", "..") for part in parts)
        ):
            raise GuardError("unsupported repository path " + display(raw))
        yield raw, parts


def open_regular(raw, parts):
    current = ""
    for part in parts[:-1]:
        current = os.path.join(current, part)
        try:
            mode = os.lstat(current).st_mode
        except OSError as exc:
            raise GuardError("cannot inspect parent of " + display(raw)) from exc
        if not stat.S_ISDIR(mode):
            raise GuardError("non-directory or symlink parent of " + display(raw))
    try:
        mode = os.lstat(os.fsdecode(raw)).st_mode
    except OSError as exc:
        raise GuardError("cannot inspect " + display(raw)) from exc
    if not stat.S_ISREG(mode):
        raise GuardError("not a regular file " + display(raw))
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(os.fsdecode(raw), flags)
    except OSError as exc:
        raise GuardError("cannot open " + display(raw)) from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise GuardError("not a regular file " + display(raw))
        return os.fdopen(fd, "r", encoding="latin-1", newline=None)
    except BaseException:
        os.close(fd)
        raise


def inspect(raw, parts):
    name = parts[-1].casefold()
    suffix = PurePosixPath(name).suffix
    conventional = (
        suffix in SOURCE_SUFFIXES or name in SOURCE_NAMES
        or name.startswith(("dockerfile.", "containerfile."))
    )
    with open_regular(raw, parts) as source:
        try:
            first = source.readline()
            if not conventional and not first.startswith("#!"):
                return None
            count = int(bool(first))
            if "\0" in first:
                raise GuardError("NUL byte in source " + display(raw))
            for row in source:
                if "\0" in row:
                    raise GuardError("NUL byte in source " + display(raw))
                count += 1
        except OSError as exc:
            raise GuardError("cannot read " + display(raw)) from exc
    return count


def main():
    if len(sys.argv) != 1:
        raise GuardError("arguments are not supported")
    failures = []
    for raw, parts in selected_paths():
        count = inspect(raw, parts)
        if count is not None and count > MAX_LINES:
            failures.append((raw, count))
    for raw, count in failures:
        print(
            f"line-limit: ERROR: {display(raw)}: {count} physical lines "
            f"exceeds the {MAX_LINES}-line limit",
            file=sys.stderr,
        )
    return int(bool(failures))


try:
    result = main()
except GuardError as exc:
    print("line-limit: ERROR: " + str(exc), file=sys.stderr)
    result = 2
except OSError:
    print("line-limit: ERROR: filesystem operation failed", file=sys.stderr)
    result = 2
sys.exit(result)
PY
