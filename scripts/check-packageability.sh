#!/bin/sh
# Package-check every publishable crate from scripts/publishable-crates.sh —
# the same single source the publish-guard enforces. Enforced by CI
# (.github/workflows/ci.yml, packageability job); locally, crate names may
# also be passed as arguments instead: `sh scripts/check-packageability.sh
# <crate> ...` (docs/publishing.md).
#
# Uses `cargo package`, not `cargo publish --dry-run`: every current manifest
# carries `publish = false`, which makes `--dry-run` fail by construction,
# while `cargo package` only builds the .crate tarball and uploads nothing.
# `--no-verify` keeps the job cheap: the full build+test matrix is already
# covered by the clippy/test/msrv jobs. In CI `--allow-dirty` is unnecessary
# (the checkout is clean); locally, pass it when the worktree is dirty.
#
# An empty publishable set is a legitimate state (today's state: everything
# is `publish = false`), so it is reported explicitly rather than failing or
# skipping silently.

set -u

if [ $# -gt 0 ]; then
    crates="$*"
else
    crates=$(sh "$(dirname "$0")/publishable-crates.sh")
fi

if [ -z "$crates" ]; then
    printf 'packageability: no publishable crates, skipping (scripts/publishable-crates.sh is empty)\n'
    exit 0
fi

status=0
for crate in $crates; do
    printf 'packageability: cargo package -p %s --no-verify\n' "$crate"
    if ! cargo package -p "$crate" --no-verify; then
        printf 'packageability: ERROR: cargo package -p %s --no-verify failed\n' "$crate"
        status=1
    fi
done

exit $status
