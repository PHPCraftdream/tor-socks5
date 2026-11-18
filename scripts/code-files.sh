#!/bin/sh
# Prints the first-party code files, one path per line: the single definition
# of "code file" behind scripts/check-line-limit.sh and
# scripts/check-dir-entries.sh. Tests are code files too (they have the same
# extensions); documentation, manifests and data files are not.
#
# Tracked plus untracked-but-not-ignored files, so brand-new files are checked
# before they are ever committed; a tracked file deleted in the working tree
# is skipped. vendor/* is deliberately out of scope: it is vendored upstream
# Arti code, synced with upstream and laid out along upstream module
# boundaries, so the first-party structure rules do not apply to it.
#
# Run from the repository root.

set -u

git ls-files --cached --others --exclude-standard \
    | grep -E '\.(rs|py|sh|ps1|c|h|cc|cpp|cs|go|java|kt|js|ts|swift)$' \
    | grep -v '^vendor/' \
    | sort -u \
    | while IFS= read -r file; do
        [ -f "$file" ] && printf '%s\n' "$file"
    done
exit 0
