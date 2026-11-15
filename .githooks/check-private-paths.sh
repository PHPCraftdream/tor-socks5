#!/bin/sh
# Fail if a tracked file mentions a machine-private path: a local disk path
# with a drive letter leading into a development or user-profile directory on
# the author's machine, or a POSIX-style absolute path into a named user's
# home directory. Such paths leak one machine's layout into the documentation
# and rot quickly; they belong in local configuration only, never in the
# repository.
#
# Scans what git tracks, so the result is the same locally and in CI, and
# untracked scratch files are ignored. Files deleted in the worktree but not
# yet committed are skipped by git grep, so a pending deletion does not break
# the check.
#
# Generic documentation placeholders stay allowed: a name between two slashes
# that contains angle brackets (a "<user>" style placeholder) is not a
# machine-private path and does not match. A segment name followed directly by
# a longer word (a directory whose name merely starts the same way) does not
# match either; the segment must end at the boundary.
#
# vendor/* is deliberately out of scope: it is vendored upstream Arti code,
# synced with upstream and laid out along upstream module boundaries.
#
# The patterns below are assembled from separate fragments on purpose: no
# single line of this file may contain a complete pattern, or the script would
# flag itself once committed. For the same reason no example path is quoted
# anywhere in this header — the shapes of the patterns are described in words.

set -u

drv='[A-Za-z]:'              # drive letter with colon
sep='[\\/]'                  # either path separator
dev='[Dd][Ee][Vv]'           # the development-directory name, any case
usr='[Uu][Ss][Ee][Rr][Ss]'   # the user-profile directory name, any case
bnd='([^A-Za-z0-9]|$)'       # segment boundary: end of the name, not a longer word
name='[^/<>]+'               # a concrete directory name: no slashes, no placeholder
home='home'                  # the POSIX home-directory root
sl='/'                       # the POSIX-style separator

pat_dev="${drv}${sep}${dev}${bnd}"
pat_drive_users="${drv}${sep}${usr}${bnd}"
pat_home="${sl}${home}${sl}${name}${sl}"
pat_home_users="${sl}${usr}${sl}${name}${sl}"

hits=$(git grep -I -n -E \
    -e "$pat_dev" -e "$pat_drive_users" -e "$pat_home" -e "$pat_home_users" \
    -- ':(exclude)vendor')
code=$?
if [ "$code" -eq 0 ]; then
    printf '%s\n' "$hits" | while IFS= read -r hit; do
        printf 'private-paths: ERROR: %s\n' "$hit"
    done
    exit 1
elif [ "$code" -eq 1 ]; then
    printf 'private-paths: OK\n'
    exit 0
fi
printf 'private-paths: ERROR: git grep failed with status %d\n' "$code"
exit "$code"
