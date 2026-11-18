#!/bin/sh
# Fail if a first-party code file has more than MAX_LINES lines. Every line
# counts (blank lines and comments included). Which files are code is defined
# in scripts/code-files.sh; vendor/* is out of scope. Enforced by CI
# (.github/workflows/ci.yml, line-limit job) and by the pre-push hook.
#
# There is no baseline: a file over the limit is split into modules, and the
# modules go into a sub-folder when the folder would otherwise pass the
# 7-code-file limit of scripts/check-dir-entries.sh.

set -u

MAX_LINES=1000

here=$(dirname "$0")
status=0

files=$(sh "$here/code-files.sh")

while IFS= read -r file; do
    [ -n "$file" ] || continue
    # NR counts a last line that has no trailing newline, which wc -l misses.
    lines=$(awk 'END { print NR }' "$file")
    if [ "$lines" -gt "$MAX_LINES" ]; then
        printf 'line-limit: ERROR: %s: %d lines exceeds the %d-line limit\n' "$file" "$lines" "$MAX_LINES"
        status=1
    fi
done <<EOF
$files
EOF

exit $status
