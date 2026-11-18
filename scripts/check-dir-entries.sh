#!/bin/sh
# Fail if a first-party folder directly holds more than MAX_FILES code files.
# Which files are code (tests included) is defined in scripts/code-files.sh;
# documentation, manifests, data files and sub-folders are not counted, and
# vendor/* is out of scope. Enforced by CI (.github/workflows/ci.yml,
# dir-entries job) and by the pre-push hook. Together with
# scripts/check-line-limit.sh (at most 1000 lines per code file) it is the
# project's code-structure rule: small folders, small files, so a reader can
# hold a folder in their head.
#
# There is no baseline: a folder over the limit is decomposed by moving
# cohesive modules into sub-folders.

set -u

MAX_FILES=7

here=$(dirname "$0")
status=0

# "<code files> <dir>" for every folder that holds code files directly (the
# repository root is ".").
counts=$(sh "$here/code-files.sh" | awk '
    {
        n = split($0, part, "/")
        dir = "."
        if (n > 1) {
            dir = part[1]
            for (i = 2; i < n; i++) dir = dir "/" part[i]
        }
        count[dir]++
    }
    END { for (dir in count) print count[dir], dir }
' | sort -k2)

while read -r files dir; do
    [ -n "$dir" ] || continue
    if [ "$files" -gt "$MAX_FILES" ]; then
        printf 'dir-entries: ERROR: %s: %d code files exceeds the %d-file limit\n' "$dir" "$files" "$MAX_FILES"
        status=1
    fi
done <<EOF
$counts
EOF

exit $status
