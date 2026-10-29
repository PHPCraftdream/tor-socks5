#!/usr/bin/env bash
set -euo pipefail
[ "${GITHUB_ACTIONS:-}" = true ] || exit 1
: "${TOR_REAL_BINARY:?}"
: "${GITHUB_WORKSPACE:?}"
cd "$GITHUB_WORKSPACE"
source_file="$GITHUB_WORKSPACE/packages/arti-wrapper/src/lib.rs"
work=$(mktemp -d "$GITHUB_WORKSPACE/target/real-tor-mutations.XXXXXXXX")
cp "$source_file" "$work/original.rs"
restore() { cp "$work/original.rs" "$source_file"; }
trap restore EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

for mutation in terminate reconfigure; do
    restore
    python3 -I - "$source_file" "$mutation" <<'PY'
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
if sys.argv[2] == "terminate":
    old = "        chanmgr.terminate_all_channels();\n"
    new = "        let _ = chanmgr;\n"
else:
    old = "        self.inner\n            .reconfigure(&config, Reconfigure::AllOrNothing)\n            .map_err(TorError::Reconfigure)?;\n"
    new = "        let _ = &config;\n"
if text.count(old) != 1:
    raise SystemExit("Не найдено единственное место мутации")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY
    cargo test -p socks5-proxy --bin socks5-proxy --locked --no-run --message-format=json > "$work/$mutation.json"
    binary=$(python3 -I - "$work/$mutation.json" <<'PY'
import json
import sys
items = [x["executable"] for line in open(sys.argv[1], encoding="utf-8")
         if (x := json.loads(line)).get("reason") == "compiler-artifact"
         and x.get("target", {}).get("name") == "socks5-proxy"
         and x.get("profile", {}).get("test") and x.get("executable")]
if len(items) != 1:
    raise SystemExit("Не найден единственный тестовый исполняемый файл")
print(items[0])
PY
)
    set +e
    sudo unshare --net -- timeout --signal=TERM --kill-after=15s 10m env \
        GITHUB_ACTIONS=true TOR_REAL_ISOLATED=yes TOR_REAL_BINARY="$TOR_REAL_BINARY" \
        TOR_REAL_TEST_BINARY="$binary" bash scripts/testing/real-tor-channel.sh \
        > "$work/$mutation.log" 2>&1
    status=$?
    set -e
    cat "$work/$mutation.log"
    [ "$status" -eq 101 ] || { printf 'Неожиданный код мутации %s: %s\n' "$mutation" "$status" >&2; exit 1; }
    if [ "$mutation" = terminate ]; then
        expected='исходный канал менеджера не закрыт'
    else
        expected='Arti не выбрал новый мост'
    fi
    if ! python3 -I - "$work/$mutation.log" "$expected" <<'PY'
import pathlib
import sys
sys.exit(0 if sys.argv[2] in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace") else 1)
PY
    then
        printf 'Отсутствует ожидаемая ошибка мутации %s\n' "$mutation" >&2
        exit 1
    fi
done
