#!/bin/sh
# Single source of truth for the set of crates this repository is allowed to
# publish to crates.io (docs/publishing.md). Consumed by BOTH
# scripts/check-publish-guard.sh and the CI packageability job
# (.github/workflows/ci.yml), so the two can never drift apart.
#
# Prints one package name per line on stdout. Empty output means "nothing is
# publishable" — the current state: all 20 package manifests (13 first-party
# members + 7 vendored Arti forks) carry `publish = false`, enforced by
# scripts/check-publish-guard.sh.
#
# The only crate ever expected on this list is the single consolidated
# `tor-socks5` package created by the SDK-01 merge (docs/sdk-package-design.md,
# §1/§6). vendor/* forks, apps/* and packages/android-ffi never go to crates.io
# (docs/publishing.md, "Что публикуется и что нет"). Publication itself stays
# blocked until the vendor gate of docs/sdk-package-design.md §4 is open.
#
# To make a crate publishable, do BOTH in the same change:
#   1. add its package name to PUBLISHABLE below;
#   2. remove `publish = false` from its manifest.
# scripts/check-publish-guard.sh cross-checks the two sides: an entry without
# a matching publishable manifest — or a manifest without `publish = false`
# and without an entry — fails CI.

set -u

# One package name per line; blank lines and #-comments are ignored.
PUBLISHABLE="
# tor-socks5
"

printf '%s\n' "$PUBLISHABLE" | sed -e '/^[[:space:]]*$/d' -e '/^[[:space:]]*#/d'
