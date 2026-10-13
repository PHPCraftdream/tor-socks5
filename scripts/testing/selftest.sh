#!/bin/sh
# Selftest for scripts/testing/test-affected.sh. Run from the repo root.
# No cargo build/test/clippy is performed: only --files-from selection is exercised.
set -u

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || {
	echo "test-affected-selftest: must run inside the repository" >&2
	exit 1
}
target="$repo_root/scripts/testing/test-affected.sh"
[ -f "$target" ] || { echo "test-affected-selftest: $target not found" >&2; exit 1; }

export CARGO_BUILD_JOBS=2
export CARGO_PROFILE_DEV_DEBUG=0

tmpdir=$(mktemp -d) || exit 1
trap 'rm -rf "$tmpdir"' EXIT

failures=0
case_no=0

# run_case <description> <input files (newline separated, may be empty)>
#           <expected sorted packages (newline separated, may be empty)>
run_case() {
	case_no=$((case_no + 1))
	desc=$1
	input=$2
	expected=$3

	infile="$tmpdir/in.$case_no"
	printf '%s\n' "$input" > "$infile"
	got=$(sh "$target" --files-from "$infile" --mode list 2>"$tmpdir/err.$case_no")
	got_sorted=$(printf '%s\n' "$got" | sed '/^$/d' | sort)
	expected_sorted=$(printf '%s\n' "$expected" | sed '/^$/d' | sort)

	if [ "$got_sorted" = "$expected_sorted" ]; then
		echo "PASS: case $case_no: $desc"
	else
		failures=$((failures + 1))
		echo "FAIL: case $case_no: $desc"
		echo "  expected: $(printf '%s' "$expected_sorted" | tr '\n' ' ')"
		echo "  got:      $(printf '%s' "$got_sorted" | tr '\n' ' ')"
		echo "  stderr:   $(cat "$tmpdir/err.$case_no")"
	fi
}

# 1. persist-lock -> full reverse-dependency closure (9 packages)
run_case "persist-lock closure" \
	"packages/persist-lock/src/lib.rs" \
	"persist-lock
android-ffi
bridge-fetcher
bridge-probe
bridge-store
socks5-proxy
tor-socks5-auth
tor-socks5-config
tor-socks5-dns"

# 2. dns-server -> its reverse dependents
run_case "dns-server closure" \
	"packages/dns-server/src/x.rs" \
	"tor-socks5-dns
socks5-proxy"

# 3. leaf app: only itself
run_case "socks5-proxy only" \
	"apps/socks5-proxy/src/main.rs" \
	"socks5-proxy"

# 4. Cargo.lock -> FULL
run_case "Cargo.lock -> FULL" \
	"Cargo.lock" \
	"FULL"

# 5. non-member vendor crate -> FULL
run_case "vendor/tor-dirmgr -> FULL" \
	"vendor/tor-dirmgr/src/x.rs" \
	"FULL"

# 6. member vendor crate -> closure (7 packages)
run_case "vendor/tor-circmgr closure" \
	"vendor/tor-circmgr/src/x.rs" \
	"tor-circmgr
android-ffi
arti-client
arti-wrapper
bridge-fetcher
socks5-proxy
tor-socks5-dns"

# 7. README.md -> data-file mapping (+ true reverse closure:
#    android-ffi depends on tor-socks5-config, per inventory.json)
run_case "README.md" \
	"README.md" \
	"tor-socks5-config
android-ffi
socks5-proxy"

# 8. docs/guide/** -> socks5-proxy
run_case "docs/guide/auth.md" \
	"docs/guide/auth.md" \
	"socks5-proxy"

# 9. docs/plans/x.md -> empty
run_case "docs/plans/x.md -> empty" \
	"docs/plans/x.md" \
	""

# 10. script itself -> FULL
run_case "scripts/testing/test-affected.sh -> FULL" \
	"scripts/testing/test-affected.sh" \
	"FULL"

# 11. empty file list -> empty
run_case "empty list" \
	"" \
	""

# 12. --mode args with FULL -> --workspace
infile="$tmpdir/in.12"
printf 'Cargo.lock\n' > "$infile"
got=$(sh "$target" --files-from "$infile" --mode args 2>/dev/null)
if [ "$got" = "--workspace" ]; then
	echo "PASS: case 12: --mode args with FULL"
else
	failures=$((failures + 1))
	echo "FAIL: case 12: --mode args with FULL"
	echo "  expected: --workspace"
	echo "  got:      $got"
fi

# 13. a member manifest change can alter unified features -> FULL
run_case "member Cargo.toml -> FULL" 	"packages/auth/Cargo.toml" 	"FULL"

# 14. failed git call (sentinel) must fail safe to FULL, never to "nothing"
run_case "git failure sentinel -> FULL" 	"__GIT_FAILED__" 	"FULL"

if [ "$failures" -eq 0 ]; then
	echo "test-affected-selftest: all $case_no cases passed"
	exit 0
else
	echo "test-affected-selftest: $failures of $case_no cases FAILED" >&2
	exit 1
fi
