#!/bin/sh
# Fail if any package manifest may be published to crates.io without being
# listed in scripts/publishable-crates.sh, or if that allowlist itself is
# stale. Enforced by CI (.github/workflows/ci.yml, publish-guard job).
#
# Default posture: nothing in this repo may be published — a `cargo publish`
# is irreversible (yank only hides a version, the name+version pair is burned
# forever), and the vendor/* forks live under upstream-owned crates.io names,
# so publishing one would hijack another project's crate. The single future
# exception is the consolidated `tor-socks5` package
# (docs/sdk-package-design.md): a manifest may drop `publish = false` only
# after its package name is added to scripts/publishable-crates.sh — see
# docs/publishing.md.
#
# The root Cargo.toml is a pure [workspace] manifest; files without a
# [package] section are silently skipped by the content test below.

set -u

status=0

# Single source of truth for what MAY be published (currently empty).
publishable=$(sh "$(dirname "$0")/publishable-crates.sh")

# Tracked plus untracked-but-not-ignored manifests, so brand-new crates are
# caught before they are ever committed.
files=$(git ls-files --cached --others --exclude-standard -- 'Cargo.toml' '*/Cargo.toml')

# Package name from the [package] section only (not [lib], not
# [package.metadata]); empty output if there is no readable name.
package_name() {
    awk '
        /^[ \t]*\[/ { inpkg = ($0 ~ /^[ \t]*\[package\][ \t]*(#.*)?$/) }
        inpkg && match($0, /^[ \t]*name[ \t]*=[ \t]*"/) {
            s = substr($0, RLENGTH + 1)
            sub(/".*$/, "", s)
            print s
            exit
        }
    ' "$1"
}

# Package names whose manifests are legitimately without `publish = false`.
allowlisted_ok=""

while IFS= read -r file; do
    [ -n "$file" ] || continue
    grep -q '^\[package\]' "$file" || continue
    if grep -Eq '^[[:space:]]*publish[[:space:]]*=[[:space:]]*false([[:space:]]|#|$)' "$file"; then
        continue
    fi
    name=$(package_name "$file")
    if [ -n "$name" ] && printf '%s\n' "$publishable" | grep -Fxq -- "$name"; then
        printf "publish-guard: NOTE: %s: package '%s' is on the publishable allowlist; 'publish = false' not required\n" "$file" "$name"
        allowlisted_ok="$allowlisted_ok
$name"
    else
        printf "publish-guard: ERROR: %s: [package] present but 'publish = false' is missing and the package is not on the scripts/publishable-crates.sh allowlist; an accidental 'cargo publish' would upload to crates.io\n" "$file"
        status=1
    fi
done <<EOF
$files
EOF

# Allowlist hygiene: every entry must have a matching manifest that actually
# dropped `publish = false`; stale entries fail, so the list can only move
# deliberately (docs/publishing.md).
while IFS= read -r name; do
    [ -n "$name" ] || continue
    if printf '%s\n' "$allowlisted_ok" | grep -Fxq -- "$name"; then
        continue
    fi
    printf "publish-guard: ERROR: scripts/publishable-crates.sh lists '%s', but its manifest is missing, still carries 'publish = false', or has no readable [package] name; keep the allowlist and the manifests in sync (docs/publishing.md)\n" "$name"
    status=1
done <<EOF
$publishable
EOF

exit $status
