#!/bin/sh
# Fail if a first-party Rust file exceeds MAX_LINES physical lines.
# Enforced by CI (.github/workflows/ci.yml, line-limit job).
#
# vendor/* is deliberately out of scope: it is vendored upstream Arti code,
# synced with upstream and split along upstream module boundaries, so the
# first-party limit does not apply to it
# (docs/stability-review-2026-09-08.md, "Проверки, которые стоит закрепить в CI").
#
# BASELINE lists files that still exceeded the limit when this check was
# introduced; splitting them is tracked separately. Any file outside the
# baseline going over the limit fails this check, so the baseline can only
# shrink. Prune an entry once its file is back under the limit.

set -u

MAX_LINES=1000

BASELINE=""

status=0

# Tracked plus untracked-but-not-ignored files, so brand-new oversized
# files are caught before they are ever committed.
files=$(git ls-files --cached --others --exclude-standard -- '*.rs' | grep -v '^vendor/')

while IFS= read -r file; do
    [ -n "$file" ] || continue
    lines=$(wc -l < "$file" | tr -d ' ')
    if [ "$lines" -gt "$MAX_LINES" ]; then
        if printf '%s\n' "$BASELINE" | grep -Fxq -- "$file"; then
            printf 'line-limit: %s: %d lines (over %d; baseline, split pending)\n' "$file" "$lines" "$MAX_LINES"
        else
            printf 'line-limit: ERROR: %s: %d lines exceeds the %d-line limit\n' "$file" "$lines" "$MAX_LINES"
            status=1
        fi
    fi
done <<EOF
$files
EOF

# Baseline hygiene: entries that no longer need the exemption.
while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    if [ ! -f "$entry" ]; then
        printf 'line-limit: NOTE: baseline entry %s no longer exists; remove it\n' "$entry"
    else
        lines=$(wc -l < "$entry" | tr -d ' ')
        if [ "$lines" -le "$MAX_LINES" ]; then
            printf 'line-limit: NOTE: baseline entry %s is now %d lines; remove it from the baseline\n' "$entry" "$lines"
        fi
    fi
done <<EOF
$BASELINE
EOF

exit $status
