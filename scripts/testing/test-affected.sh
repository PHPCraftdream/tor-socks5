#!/bin/sh
# test-affected.sh — T1 tier: select packages affected by changed files and
# (transitively) their reverse dependencies, per docs/plans/test-tiers.md.
#
# Usage:
#   scripts/testing/test-affected.sh [--base <ref>] [--files-from <file|->]
#                            [--mode list|args|run] [--kind test|clippy|all]
#                            [--full]
#
# Depends on: sh, git, jq, cargo. POSIX sh only (must pass `sh -n`).
set -u

progname=test-affected.sh
base_ref=""
files_from=""
mode=list
kind=test
force_full=0

usage() {
	cat >&2 <<'EOF'
Usage: test-affected.sh [--base <ref>] [--files-from <file|->] [--mode list|args|run]
                        [--kind test|clippy|all] [--full]
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--base)
		[ $# -ge 2 ] || { usage; exit 2; }
		base_ref=$2; shift 2 ;;
	--files-from)
		[ $# -ge 2 ] || { usage; exit 2; }
		files_from=$2; shift 2 ;;
	--mode)
		[ $# -ge 2 ] || { usage; exit 2; }
		mode=$2; shift 2 ;;
	--kind)
		[ $# -ge 2 ] || { usage; exit 2; }
		kind=$2; shift 2 ;;
	--full)
		force_full=1; shift ;;
	-h|--help)
		usage; exit 0 ;;
	*)
		echo "$progname: unknown option: $1" >&2; usage; exit 2 ;;
	esac
done

case "$mode" in
list|args|run) ;;
*) echo "$progname: invalid --mode: $mode" >&2; exit 2 ;;
esac
case "$kind" in
test|clippy|all) ;;
*) echo "$progname: invalid --kind: $kind" >&2; exit 2 ;;
esac

command -v git >/dev/null 2>&1 || { echo "$progname: git not found" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "$progname: jq not found" >&2; exit 1; }

# Repo root, forward slashes.
root=$(git rev-parse --show-toplevel 2>/dev/null) || {
	echo "$progname: not inside a git repository" >&2
	exit 1
}
root=$(printf '%s' "$root" | tr '\\' '/')

# ---------------------------------------------------------------- changed files

changed_files=""
if [ -n "$files_from" ]; then
	if [ "$files_from" = "-" ]; then
		changed_files=$(cat)
	else
		changed_files=$(while IFS= read -r line || [ -n "$line" ]; do printf '%s\n' "$line"; done < "$files_from")
	fi
else
	if [ -z "$base_ref" ]; then
		base_ref=""
		base_note=""
		if [ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" = true ] && [ -z "$(git symbolic-ref -q HEAD 2>/dev/null)" ]; then
			base_note="detached HEAD"
		elif [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
			base_note="shallow repository"
		else
			for cand in '@{upstream}' 'origin/main' 'main'; do
				if git rev-parse --verify --quiet "$cand" >/dev/null 2>&1; then
					mb=$(git merge-base HEAD "$cand" 2>/dev/null) || mb=""
					if [ -n "$mb" ]; then base_ref=$mb; else base_note="merge-base with $cand failed"; fi
					break
				fi
			done
			if [ -z "$base_ref" ] && [ -z "$base_note" ]; then base_note="no upstream/origin/main/main ref found"; fi
		fi
	else
		base_note=""
		if ! git rev-parse --verify --quiet "$base_ref^{commit}" >/dev/null 2>&1; then
			base_note="explicit base '$base_ref' is not a locally resolvable commit"
		fi
	fi
	# A failed git call must never read as "nothing changed": the sentinel
	# makes the selection fail safe to FULL. --no-renames lists both sides of
	# a rename; -z + quotePath=false keeps spaces/non-ASCII paths intact. NUL
	# output goes through a temp file: command substitution silently drops
	# NUL bytes.
	diff_tmp=$(mktemp) || exit 1
	read_git_z() { # $@ = git args; NUL-delimited output -> newlines, "__GIT_FAILED__" on error
		if git -c core.quotePath=false "$@" >"$diff_tmp" 2>/dev/null; then
			tr '\0' '\n' <"$diff_tmp"
		else
			echo "__GIT_FAILED__"
		fi
	}
	changed_files=$( {
		read_git_z diff --name-only --no-renames -z "$base_ref"
		read_git_z diff --name-only --no-renames --cached -z "$base_ref"
		read_git_z ls-files --others --exclude-standard -z
	} )
	rm -f "$diff_tmp"
fi

# Deduplicate, skip empty lines, normalize backslashes to forward slashes.
files=$(printf '%s\n' "$changed_files" | tr '\\' '/' | sed '/^[[:space:]]*$/d' | awk '!seen[$0]++')

# Respect pre-existing cargo env tuning; provide cheap defaults otherwise.
if [ -z "${CARGO_BUILD_JOBS:-}" ]; then
	CARGO_BUILD_JOBS=2
	export CARGO_BUILD_JOBS
fi
if [ -z "${CARGO_PROFILE_DEV_DEBUG:-}" ]; then
	CARGO_PROFILE_DEV_DEBUG=0
	export CARGO_PROFILE_DEV_DEBUG
fi

# ---------------------------------------------------------------- workspace graph

meta=$(cargo metadata --offline --no-deps --format-version 1 2>/dev/null) || {
	echo "$progname: cargo metadata failed" >&2
	exit 1
}

# "name<TAB>member_dir_abs" (dir of manifest_path, forward slashes).
# A jq failure or empty member table must not yield a silently empty plan:
# exit non-zero so hook/CI fall back to FULL.
members=$(printf '%s' "$meta" | jq -r '
	.packages[] | [ .name, (.manifest_path | gsub("\\\\"; "/") | sub("/Cargo\\.toml$"; "")) ] | @tsv') || {
	echo "$progname: jq failed on cargo metadata output" >&2
	exit 1
}
if [ -z "$members" ]; then
	echo "$progname: no workspace members in cargo metadata output" >&2
	exit 1
fi

# member-dir-relative table: "dir_rel<TAB>name"
dir_to_name=$(printf '%s\n' "$members" | awk -F'\t' -v OFS='\t' -v root="$root" '
	{ d = $2; if (index(d, root "/") == 1) d = substr(d, length(root) + 2); print d, $1 }')

# Reverse-dependency edges between members: "dep_name<TAB>dependent_name"
# (normal + dev dependency kinds only). A dependency counts as a member edge
# when its name matches a workspace member name (covers vendored crates whose
# manifest still refers to siblings via registry coordinates).
rdeps=$(printf '%s' "$meta" | jq -r '
	.packages as $ps |
	$ps[] as $p |
	$p.dependencies[]? |
	.name as $dn |
	select($ps | map(.name) | any(. == $dn)) |
	select($dn != $p.name) |
	(if has("dep_kinds")
	 then select([.dep_kinds[].kind] | any(. == null or . == "dev"))
	 else select(.kind == null or .kind == "dev")
	 end) |
	[$dn, $p.name] | @tsv') || {
	echo "$progname: jq failed building the reverse-dependency table" >&2
	exit 1
}

# ---------------------------------------------------------------- selection

full=0
full_trigger=""
seeds=""
nl='
'

add_seed() { # $1 = package name
	case "$nl$seeds$nl" in
	*"$nl$1$nl"*) ;;
	*) seeds="$seeds$nl$1" ;;
	esac
}

mark_full() { # $1 = triggering file or reason
	if [ "$full" -eq 0 ]; then
		full=1
		full_trigger=$1
	fi
}

# Undeterminable base must not degrade to "compare with HEAD" (an empty,
# silently passing selection): force FULL with the reason.
if [ -n "${base_note:-}" ]; then
	mark_full "cannot determine base: $base_note"
fi

map_data_file() { # $1 = file
	case "$1" in
	README.md|tor-socks5.example.ktav)
		add_seed tor-socks5-config
		add_seed socks5-proxy
		;;
	docs/architecture.md|docs/guide/*)
		add_seed socks5-proxy
		;;
	esac
}

while IFS= read -r f || [ -n "$f" ]; do
	[ -n "$f" ] || continue
	# FULL triggers (checked before member mapping).
	case "$f" in
		__GIT_FAILED__) mark_full "git diff failed (fail-safe)"; continue ;;
		Cargo.toml|Cargo.lock|*/Cargo.toml|*/Cargo.lock) mark_full "$f"; continue ;;
		rust-toolchain|rust-toolchain*) mark_full "$f"; continue ;;
		.cargo/*|.config/*|scripts/testing/*) mark_full "$f"; continue ;;
		scripts/testing/test-affected.sh) mark_full "$f"; continue ;;
		vendor/*)
			# ANY edit under vendor/ goes FULL: vendored crates reach the
			# workspace through registry coordinates too (e.g. saturating-time
			# -> tor-netdoc -> tor-circmgr), so member-prefix mapping alone
			# would miss those dependents.
			mark_full "$f"; continue ;;
	esac

	# Member prefix mapping: longest matching member dir.
	owner=""
	owner_len=0
	while IFS="$(printf '\t')" read -r dir name; do
		[ -n "$dir" ] || continue
		case "$f" in
		"$dir"|"$dir"/*) l=${#dir} ;;
		*) continue ;;
		esac
		if [ "$l" -gt "$owner_len" ]; then
			owner_len=$l
			owner=$name
		fi
	done <<EOF
$(printf '%s\n' "$dir_to_name")
EOF
	if [ -n "$owner" ]; then
		add_seed "$owner"
	else
		map_data_file "$f"
	fi
done <<EOF
$files
EOF

if [ "$force_full" -eq 1 ] && [ "$full" -eq 0 ]; then
	full=1
	full_trigger="--full flag"
fi

# ---------------------------------------------------------------- closure

# Reverse-dependency closure over seeds (BFS through rdeps edges).
if [ -n "$seeds" ]; then
	seed_list=$seeds
	selected=$seeds
	frontier=$seeds
	while [ -n "$frontier" ]; do
		new=""
		for p in $frontier; do
			while IFS="$(printf '\t')" read -r _dep dependent; do
				[ -n "$dependent" ] || continue
				case "$nl$selected$nl" in
				*"$nl$dependent$nl"*) ;;
				*) selected="$selected$nl$dependent"; new="$new$nl$dependent" ;;
				esac
			done <<EOF
$(printf '%s\n' "$rdeps" | awk -F'\t' -v p="$p" '$1 == p { print }')
EOF
		done
		frontier=$new
	done
	seed_count=$(printf '%s\n' "$seed_list" | sed '/^$/d' | wc -l | tr -d ' ')
	total_count=$(printf '%s\n' "$selected" | sed '/^$/d' | wc -l | tr -d ' ')
	sorted=$(printf '%s\n' "$selected" | sed '/^$/d' | sort)
else
	seed_count=0
	total_count=0
	sorted=""
fi

# ---------------------------------------------------------------- plan output

if [ "$full" -eq 1 ]; then
	echo "T2: FULL (trigger: $full_trigger)" >&2
else
	if [ "$total_count" -eq 0 ]; then
		echo "T1: no affected packages (nothing to test)" >&2
	else
		echo "T1: $total_count packages: $(printf '%s\n' "$sorted" | awk 'NR > 1 { printf ", " } { printf "%s", $0 } END { printf "\n" }')" >&2
	fi
fi

case "$mode" in
list)
	if [ "$full" -eq 1 ]; then
		echo "FULL"
	elif [ "$total_count" -gt 0 ]; then
		printf '%s\n' "$sorted"
	fi
	exit 0
	;;
esac

args=""
if [ "$full" -eq 1 ]; then
	args="--workspace"
elif [ "$total_count" -gt 0 ]; then
	for p in $sorted; do
		args="$args -p $p"
	done
	args=${args# }
fi

if [ "$mode" = "args" ]; then
	if [ -n "$args" ]; then
		printf '%s\n' "$args"
	fi
	exit 0
fi

# mode = run
if [ "$total_count" -eq 0 ] && [ "$full" -eq 0 ]; then
	echo "$progname: nothing to test, not running cargo" >&2
	exit 0
fi

run_cmd() {
	if [ "${TEST_AFFECTED_DRY:-0}" = "1" ]; then
		echo "dry-run: $*"
	else
		echo "$progname: running: $*" >&2
		"$@"
	fi
}

nextest=0
if command -v cargo-nextest >/dev/null 2>&1 || cargo nextest --version >/dev/null 2>&1; then
	nextest=1
fi

rc=0
if [ "$kind" = "test" ] || [ "$kind" = "all" ]; then
	if [ "$nextest" -eq 1 ]; then
		run_cmd cargo nextest run $args || rc=$?
	else
		run_cmd cargo test $args || rc=$?
	fi
	if [ "$rc" -eq 0 ]; then
		doc_args=$(printf '%s' "$args" | sed 's/-p saturating-time//g')
		[ -n "${doc_args// /}" ] || doc_args="--workspace --exclude saturating-time"
		run_cmd cargo test --doc $doc_args || rc=$?
	fi
fi
if { [ "$kind" = "clippy" ] || [ "$kind" = "all" ]; } && [ "$rc" -eq 0 ]; then
	run_cmd cargo clippy $args --all-targets -- -D warnings || rc=$?
fi
exit "$rc"
