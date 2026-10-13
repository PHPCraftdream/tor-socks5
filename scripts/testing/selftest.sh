#!/bin/sh
# Selftest for scripts/testing/test-affected.sh. Run from the repo root.
# No cargo build/test/clippy is performed: only --files-from/--base selection
# is exercised (the git-fixture cases run cargo metadata on a tiny workspace).
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
#           [<expected exit code>, default 0]
run_case() {
	case_no=$((case_no + 1))
	desc=$1
	input=$2
	expected=$3
	expected_rc=${4:-0}

	infile="$tmpdir/in.$case_no"
	printf '%s\n' "$input" > "$infile"
	got_rc=0
	got=$(sh "$target" --files-from "$infile" --mode list 2>"$tmpdir/err.$case_no") || got_rc=$?
	got_sorted=$(printf '%s\n' "$got" | sed '/^$/d' | sort)
	expected_sorted=$(printf '%s\n' "$expected" | sed '/^$/d' | sort)

	if [ "$got_sorted" = "$expected_sorted" ] && [ "$got_rc" -eq "$expected_rc" ]; then
		echo "PASS: case $case_no: $desc"
	else
		failures=$((failures + 1))
		echo "FAIL: case $case_no: $desc"
		echo "  expected: rc=$expected_rc packages: $(printf '%s' "$expected_sorted" | tr '\n' ' ')"
		echo "  got:      rc=$got_rc packages: $(printf '%s' "$got_sorted" | tr '\n' ' ')"
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

# 6. ANY vendor/ edit -> FULL, even workspace members: they reach the
#    workspace through registry coordinates too (saturating-time ->
#    tor-netdoc -> tor-circmgr), which member-prefix mapping would miss.
run_case "vendor/tor-circmgr -> FULL" \
	"vendor/tor-circmgr/src/x.rs" \
	"FULL"

run_case "vendor/saturating-time -> FULL" \
	"vendor/saturating-time/src/x.rs" \
	"FULL"

# 8. README.md -> data-file mapping (+ true reverse closure:
#    android-ffi depends on tor-socks5-config, per inventory.json)
run_case "README.md" \
	"README.md" \
	"tor-socks5-config
android-ffi
socks5-proxy"

# 9. docs/guide/** -> socks5-proxy
run_case "docs/guide/auth.md" \
	"docs/guide/auth.md" \
	"socks5-proxy"

# 10. docs/plans/x.md -> empty
run_case "docs/plans/x.md -> empty" \
	"docs/plans/x.md" \
	""

# 11. script itself -> FULL
run_case "scripts/testing/test-affected.sh -> FULL" \
	"scripts/testing/test-affected.sh" \
	"FULL"

# 12. empty file list -> empty
run_case "empty list" \
	"" \
	""

# 13. --mode args with FULL -> --workspace
case_no=$((case_no + 1))
infile="$tmpdir/in.$case_no"
printf 'Cargo.lock\n' > "$infile"
got_rc=0
got=$(sh "$target" --files-from "$infile" --mode args 2>/dev/null) || got_rc=$?
if [ "$got" = "--workspace" ] && [ "$got_rc" -eq 0 ]; then
	echo "PASS: case $case_no: --mode args with FULL"
else
	failures=$((failures + 1))
	echo "FAIL: case $case_no: --mode args with FULL"
	echo "  expected: rc=0 --workspace"
	echo "  got:      rc=$got_rc $got"
fi

# 14. a member manifest change can alter unified features -> FULL
run_case "member Cargo.toml -> FULL" 	"packages/auth/Cargo.toml" 	"FULL"

# 15. failed git call (sentinel) must fail safe to FULL, never to "nothing"
run_case "git failure sentinel -> FULL" 	"__GIT_FAILED__" 	"FULL"

# 16. First jq call fails.
case_no=$((case_no + 1))
fakebin="$tmpdir/fakebin"
mkdir -p "$fakebin"
printf '#!/bin/sh
exit 3
' > "$fakebin/jq"
chmod +x "$fakebin/jq"
infile="$tmpdir/in.$case_no"
printf 'packages/dns-server/src/x.rs
' > "$infile"
PATH="$fakebin:$PATH" sh "$target" --files-from "$infile" --mode list >/dev/null 2>"$tmpdir/err.$case_no"
jq_rc=$?
if [ "$jq_rc" -eq 1 ]; then echo "PASS: case $case_no: first jq failure -> rc=1"; else failures=$((failures + 1)); echo "FAIL: case $case_no: first jq failure expected rc=1 got $jq_rc"; fi

# 17. Second jq call fails: forward the first invocation to the real jq.
case_no=$((case_no + 1))
real_jq=$(command -v jq)
cat > "$fakebin/jq" <<'STUB'
#!/bin/sh
n=0
[ ! -f "$JQ_COUNTER" ] || n=$(cat "$JQ_COUNTER")
n=$((n + 1))
printf '%s
' "$n" > "$JQ_COUNTER"
if [ "$n" -eq 1 ]; then exec "$REAL_JQ" "$@"; fi
exit 3
STUB
chmod +x "$fakebin/jq"
PATH="$fakebin:$PATH" REAL_JQ="$real_jq" JQ_COUNTER="$tmpdir/jq-count" sh "$target" --files-from "$infile" --mode list >/dev/null 2>"$tmpdir/err.$case_no"
jq_rc=$?
if [ "$jq_rc" -eq 1 ]; then echo "PASS: case $case_no: second jq failure -> rc=1"; else failures=$((failures + 1)); echo "FAIL: case $case_no: second jq failure expected rc=1 got $jq_rc"; fi

# 18. Empty members table from jq is rejected.
case_no=$((case_no + 1))
printf '#!/bin/sh
cat >/dev/null
exit 0
' > "$fakebin/jq"
chmod +x "$fakebin/jq"
PATH="$fakebin:$PATH" sh "$target" --files-from "$infile" --mode list >/dev/null 2>"$tmpdir/err.$case_no"
jq_rc=$?
if [ "$jq_rc" -eq 1 ]; then echo "PASS: case $case_no: empty members -> rc=1"; else failures=$((failures + 1)); echo "FAIL: case $case_no: empty members expected rc=1 got $jq_rc"; fi

# 19-20. git diff path and rename handling in a minimal workspace.
fixture="$tmpdir/fx"
mkdir -p "$fixture/pkg space/src" "$fixture/pkg2/src"
printf '[workspace]\nmembers = ["pkg space", "pkg2"]\nresolver = "2"\n' > "$fixture/Cargo.toml"
for name in fxspace fxpkg2; do
	if [ "$name" = fxspace ]; then member='pkg space'; else member=pkg2; fi
	mkdir -p "$fixture/$member/src"
	printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n' "$name" > "$fixture/$member/Cargo.toml"
	echo 'pub fn f() {}' > "$fixture/$member/src/lib.rs"
done
echo 'pub fn g() {}' > "$fixture/pkg space/src/a.rs"
echo 'pub fn q() {}' > "$fixture/pkg2/src/b.rs"

if ! git -C "$fixture" init -q; then echo 'FAIL: fixture git init'; exit 1; fi
if ! git -C "$fixture" -c user.email=t@t -c user.name=t add -A; then echo 'FAIL: fixture git add'; exit 1; fi
if ! git -C "$fixture" -c user.email=t@t -c user.name=t commit -qm base; then echo 'FAIL: fixture git commit'; exit 1; fi
base_sha=$(git -C "$fixture" rev-parse HEAD) || { echo 'FAIL: fixture base SHA'; exit 1; }


run_fixture_case() { # <desc> <expected output> <git mv args...>
	case_no=$((case_no + 1))
	desc=$1
	expected=$2
	shift 2
	if ! git -C "$fixture" mv "$@"; then
		failures=$((failures + 1)); echo "FAIL: case $case_no: git mv failed: $desc"; return
	fi
	# no commit: the rename must be picked up as a staged change
	got_rc=0
	got=$(cd "$fixture" && sh "$target" --base "$base_sha" --mode list 2>"$tmpdir/err.$case_no") || got_rc=$?
	if [ "$got" = "$expected" ] && [ "$got_rc" -eq 0 ]; then
		echo "PASS: case $case_no: $desc"
	else
		failures=$((failures + 1))
		echo "FAIL: case $case_no: $desc"
		echo "  expected: $expected"
		echo "  got:      rc=$got_rc out=$got"
		echo "  stderr:   $(cat "$tmpdir/err.$case_no")"
	fi
}

# 19. Rename between two actual workspace members; both packages are selected.
if ! git -C "$fixture" reset --hard -q "$base_sha"; then echo 'FAIL: fixture reset'; exit 1; fi
echo 'pub fn different_contents_for_second_member() {}' > "$fixture/pkg space/src/a.rs"
run_fixture_case "rename between members" "fxpkg2
fxspace" "pkg space/src/a.rs" "pkg2/src/c.rs"
# 20. Independent new path in a member directory containing spaces/cyrillic.
case_no=$((case_no + 1))
if ! git -C "$fixture" reset --hard -q "$base_sha"; then echo 'FAIL: fixture reset'; exit 1; fi
printf 'pub fn h() {}\n' > "$fixture/pkg space/src/тест файл.rs"
got_rc=0
got=$(cd "$fixture" && sh "$target" --base "$base_sha" --mode list 2>"$tmpdir/err.$case_no") || got_rc=$?
if [ "$got" = "fxspace" ] && [ "$got_rc" -eq 0 ]; then echo "PASS: case $case_no: spaced member path"; else failures=$((failures + 1)); echo "FAIL: case $case_no: spaced member path rc=$got_rc out=$got"; fi

# 22. undeterminable base (no refs) must yield FULL.
case_no=$((case_no + 1))
nobase="$tmpdir/nobase"
mkdir -p "$nobase/pkg space/src" "$nobase/pkg2/src"
cp "$fixture/Cargo.toml" "$nobase/Cargo.toml"
cp "$fixture/pkg space/Cargo.toml" "$nobase/pkg space/Cargo.toml"
cp "$fixture/pkg space/src/lib.rs" "$nobase/pkg space/src/lib.rs"
cp "$fixture/pkg2/Cargo.toml" "$nobase/pkg2/Cargo.toml"
cp "$fixture/pkg2/src/lib.rs" "$nobase/pkg2/src/lib.rs"
if ! git -C "$nobase" init -q; then echo 'FAIL: no-base fixture git init'; exit 1; fi
(cd "$nobase" && sh "$target" --mode list >"$tmpdir/out.$case_no" 2>"$tmpdir/err.$case_no")
nobase_rc=$?
nobase_out=$(sed '/^$/d' "$tmpdir/out.$case_no")
if [ "$nobase_out" = "FULL" ] && [ "$nobase_rc" -eq 0 ]; then
	echo "PASS: case $case_no: no base available -> FULL"
else
	failures=$((failures + 1))
	echo "FAIL: case $case_no: no base available -> FULL"
	echo "  expected: rc=0 out=FULL"
	echo "  got:      rc=$nobase_rc out=$nobase_out"
	echo "  stderr: $(cat "$tmpdir/err.$case_no")"
fi

# Base failure modes must all report FULL with rc=0.
expect_full_case() { # desc cwd command...
	case_no=$((case_no + 1)); desc=$1; workdir=$2; shift 2
	got_rc=0; got=$(cd "$workdir" && "$@" 2>"$tmpdir/err.$case_no") || got_rc=$?
	if [ "$got" = FULL ] && [ "$got_rc" -eq 0 ]; then echo "PASS: case $case_no: $desc (rc=0 FULL)"; else failures=$((failures + 1)); echo "FAIL: case $case_no: $desc expected rc=0 FULL got rc=$got_rc out=$got stderr=$(cat "$tmpdir/err.$case_no")"; fi
}
# Detached HEAD with an available main merge-base.
detached="$tmpdir/detached"
mkdir -p "$detached/pkg space/src" "$detached/pkg2/src"
cp "$nobase/Cargo.toml" "$detached/Cargo.toml"
cp "$nobase/pkg space/Cargo.toml" "$detached/pkg space/Cargo.toml"
cp "$nobase/pkg space/src/lib.rs" "$detached/pkg space/src/lib.rs"
cp "$nobase/pkg2/Cargo.toml" "$detached/pkg2/Cargo.toml"
cp "$nobase/pkg2/src/lib.rs" "$detached/pkg2/src/lib.rs"
if ! git -C "$detached" init -q; then echo 'FAIL: detached init'; exit 1; fi
if ! git -C "$detached" add -A; then echo 'FAIL: detached add'; exit 1; fi
if ! git -C "$detached" -c user.email=t@t -c user.name=t commit -qm base; then echo 'FAIL: detached commit'; exit 1; fi
detached_sha=$(git -C "$detached" rev-parse HEAD) || { echo 'FAIL: detached sha'; exit 1; }
if ! git -C "$detached" update-ref refs/heads/main "$detached_sha"; then echo 'FAIL: detached main ref'; exit 1; fi
if ! git -C "$detached" checkout -q --detach "$detached_sha"; then echo 'FAIL: detach checkout'; exit 1; fi
expect_full_case "detached HEAD -> FULL" "$detached" sh "$target" --mode list
# An explicit unresolved base.
expect_full_case "missing explicit base -> FULL" "$fixture" sh "$target" --base absent-base --mode list
# Shallow clone from a local file URL.
shallow="$tmpdir/shallow"
fixture_abs=$(cd "$detached" && pwd)
case "$fixture_abs" in
	[A-Za-z]:/*)
		if command -v cygpath >/dev/null 2>&1; then fixture_abs=$(cygpath -m "$fixture_abs"); fi
		fixture_url="file:///$fixture_abs"
		;;
	/*) fixture_url="file://$fixture_abs" ;;
	*) echo "FAIL: unsupported fixture path: $fixture_abs"; exit 1 ;;
esac
if ! git clone -q --depth 1 "$fixture_url" "$shallow"; then echo 'FAIL: shallow clone'; exit 1; fi
expect_full_case "shallow repo -> FULL" "$shallow" sh "$target" --mode list

hook="$repo_root/.githooks/pre-push"
head_sha=$(git -C "$repo_root" rev-parse HEAD) || { echo 'FAIL: hook HEAD'; exit 1; }
zero=0000000000000000000000000000000000000000
hook_case() { # desc expected-rc stdin expected-pattern stderr|stdout
	case_no=$((case_no + 1))
	desc=$1; expected_rc=$2; input=$3; pattern=$4; stream=$5
	got_rc=0
	(cd "$repo_root" && printf '%b' "$input" | TEST_AFFECTED_DRY=1 sh "$hook" >"$tmpdir/hook-out.$case_no" 2>"$tmpdir/hook-err.$case_no") || got_rc=$?
	if [ "$stream" = stdout ]; then output_file="$tmpdir/hook-out.$case_no"; else output_file="$tmpdir/hook-err.$case_no"; fi
	if [ "$got_rc" -eq "$expected_rc" ] && grep -q "$pattern" "$output_file"; then
		echo "PASS: case $case_no: $desc (rc=$got_rc, output matched)"
	else
		failures=$((failures + 1)); echo "FAIL: case $case_no: $desc expected rc=$expected_rc /$pattern/"
		echo "  got rc=$got_rc stdout=$(cat "$tmpdir/hook-out.$case_no") stderr=$(cat "$tmpdir/hook-err.$case_no")"
	fi
}
hook_case "hook mismatch blocks" 1 "refs/heads/other 1111111111111111111111111111111111111111 refs/heads/other $zero\\n" "проверяется рабочее дерево" stderr
hook_case "hook multiple commits blocks" 1 "refs/heads/a $head_sha refs/heads/a $zero\\nrefs/heads/b 1111111111111111111111111111111111111111 refs/heads/b $zero\\n" "refs target different commits" stderr
hook_case "hook deletion-only skips checks" 0 "refs/heads/a $zero refs/heads/a $head_sha\\n" "deletion-only push; no checks" stdout
hook_case "hook unknown remote SHA forces FULL" 0 "refs/heads/a $head_sha refs/heads/a 1111111111111111111111111111111111111111\\n" "remote sha .* is not available locally" stdout
tag_sha=$(printf 'object %s
type commit
tag selftest-tag
tagger t <t@t> 0 +0000

m
' "$head_sha" | git -C "$repo_root" hash-object -t tag -w --stdin) || { echo 'FAIL: hook tag object'; exit 1; }
hook_case "hook annotated tag at HEAD is not a mismatch" 0 "refs/tags/v0 $tag_sha refs/tags/v0 $zero\n" "tier T2 (FULL): push to refs/tags/v0" stdout

case_no=$((case_no + 1))
hookrepo="$tmpdir/hook-no-origin"
mkdir -p "$hookrepo"
if ! git -C "$hookrepo" init -q; then echo 'FAIL: hook no-origin init'; exit 1; fi
if ! git -C "$hookrepo" -c user.email=t@t -c user.name=t fetch -q "$fixture" "$base_sha"; then echo 'FAIL: hook no-origin fetch'; exit 1; fi
if ! git -C "$hookrepo" checkout -q FETCH_HEAD; then echo 'FAIL: hook no-origin checkout'; exit 1; fi
if ! mkdir -p "$hookrepo/scripts/testing"; then echo 'FAIL: hook no-origin script dir'; exit 1; fi
if ! cp "$target" "$hookrepo/scripts/testing/test-affected.sh"; then echo 'FAIL: hook no-origin script copy'; exit 1; fi
if ! git -C "$hookrepo" add scripts/testing/test-affected.sh; then echo 'FAIL: hook no-origin script add'; exit 1; fi
if ! git -C "$hookrepo" -c user.email=t@t -c user.name=t commit -qm 'fixture selector'; then echo 'FAIL: hook no-origin script commit'; exit 1; fi
hook_head=$(git -C "$hookrepo" rev-parse HEAD) || { echo 'FAIL: no-origin HEAD'; exit 1; }
(cd "$hookrepo" && printf '%b' "refs/heads/a $hook_head refs/heads/a $zero\\n" | TEST_AFFECTED_DRY=1 sh "$hook") >"$tmpdir/hook-out.$case_no" 2>"$tmpdir/hook-err.$case_no"
hook_rc=$?
if [ "$hook_rc" -eq 0 ] && grep -q 'origin/main unavailable' "$tmpdir/hook-out.$case_no"; then echo "PASS: case $case_no: new ref without origin/main -> FULL (rc=0)"; else failures=$((failures + 1)); echo "FAIL: case $case_no: expected rc=0 and FULL output"; echo "  stdout=$(cat "$tmpdir/hook-out.$case_no") stderr=$(cat "$tmpdir/hook-err.$case_no")"; fi
case_no=$((case_no + 1))
hookrepo="$tmpdir/hook-base"
if ! git init -q "$hookrepo"; then echo 'FAIL: hook-base init'; exit 1; fi
if ! git -C "$hookrepo" -c user.email=t@t -c user.name=t fetch -q "$fixture" "$base_sha"; then echo 'FAIL: hook-base fetch'; exit 1; fi
if ! git -C "$hookrepo" checkout -q FETCH_HEAD; then echo 'FAIL: hook-base checkout'; exit 1; fi
if ! mkdir -p "$hookrepo/scripts/testing"; then echo 'FAIL: hook-base script dir'; exit 1; fi
if ! cp "$target" "$hookrepo/scripts/testing/test-affected.sh"; then echo 'FAIL: hook-base script copy'; exit 1; fi
if ! git -C "$hookrepo" add scripts/testing/test-affected.sh; then echo 'FAIL: hook-base script add'; exit 1; fi
if ! git -C "$hookrepo" -c user.email=t@t -c user.name=t commit -qm 'fixture selector'; then echo 'FAIL: hook-base script commit'; exit 1; fi
hook_head=$(git -C "$hookrepo" rev-parse HEAD) || { echo 'FAIL: hook-base HEAD'; exit 1; }
if ! git -C "$hookrepo" update-ref refs/remotes/origin/main "$hook_head"; then echo 'FAIL: hook-base ref'; exit 1; fi
(cd "$hookrepo" && printf '%b' "refs/heads/a $hook_head refs/heads/a $zero\\n" | TEST_AFFECTED_DRY=1 sh "$hook") >"$tmpdir/hook-out.$case_no" 2>"$tmpdir/hook-err.$case_no"
hook_rc=$?
if [ "$hook_rc" -eq 0 ] && grep -q 'OK (T1, empty)' "$tmpdir/hook-out.$case_no" && ! grep -q 'tier T2' "$tmpdir/hook-out.$case_no"; then echo "PASS: case $case_no: new ref uses origin/main (rc=0, T1 empty)"; else failures=$((failures + 1)); echo "FAIL: case $case_no: expected rc=0 and T1 empty"; echo "  stdout=$(cat "$tmpdir/hook-out.$case_no") stderr=$(cat "$tmpdir/hook-err.$case_no")"; fi

if [ "$failures" -eq 0 ]; then
	echo "test-affected-selftest: all $case_no cases passed"
	exit 0
else
	echo "test-affected-selftest: $failures of $case_no cases FAILED" >&2
	exit 1
fi
