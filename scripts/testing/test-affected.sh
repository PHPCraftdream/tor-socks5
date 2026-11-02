#!/bin/sh
# Локальный выбор пакетов; полный список — по --full или явному commit footer.
set -eu
base=""
mode=list
kind=test
full=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --base) [ "$#" -ge 2 ] || exit 2; base=$2; shift 2 ;;
        --mode) [ "$#" -ge 2 ] || exit 2; mode=$2; shift 2 ;;
        --kind) [ "$#" -ge 2 ] || exit 2; kind=$2; shift 2 ;;
        --full) full=1; shift ;;
        *) echo "test-affected: unknown option: $1" >&2; exit 2 ;;
    esac
done
case "$mode" in list|args|run) ;; *) exit 2 ;; esac
case "$kind" in test|clippy|all) ;; *) exit 2 ;; esac
head=$(git rev-parse --verify 'HEAD^{commit}')
if [ "$full" = 1 ]; then
    plan=$(python -I scripts/testing/ci_planner.py --event workflow_dispatch --mode sprint-full --head "$head")
else
    [ -n "$base" ] || { echo 'test-affected: --base is required' >&2; exit 1; }
    plan=$(python -I scripts/testing/ci_planner.py --event push --base "$base" --head "$head")
fi
export plan mode kind
python -I -c '
import json, os, shutil, subprocess
p = json.loads(os.environ["plan"])
names = p["command_packages"]["rust"]
args = sum((["-p", n] for n in names), [])
mode, kind = os.environ["mode"], os.environ["kind"]
if mode == "list":
    print(*names, sep="\n") if names else None
elif mode == "args":
    print(" ".join(args)) if args else None
elif names:
    def run(cmd):
        print(("dry-run: " if os.environ.get("TEST_AFFECTED_DRY") == "1" else "running: ") + " ".join(cmd), flush=True)
        if os.environ.get("TEST_AFFECTED_DRY") != "1":
            subprocess.run(cmd, check=True)
    if kind in ("clippy", "all"):
        run(["cargo", "clippy", "--locked", *args, "--all-targets", "--", "-D", "warnings"])
    if kind in ("test", "all"):
        cmd = ["cargo", "nextest", "run"] if shutil.which("cargo-nextest") else ["cargo", "test"]
        run([*cmd, "--locked", *args])
        libs = sum((["-p", n] for n in p["library_packages"]), [])
        if libs:
            run(["cargo", "test", "--doc", "--locked", *libs])
'
