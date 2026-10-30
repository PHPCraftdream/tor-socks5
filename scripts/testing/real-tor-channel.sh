#!/usr/bin/env bash
set -euo pipefail

# Скрипт выполняется только внутри отдельного сетевого пространства имён CI.
[ "${GITHUB_ACTIONS:-}" = true ] && [ "${TOR_REAL_ISOLATED:-}" = yes ] || exit 1
: "${TOR_REAL_BINARY:?}"
: "${TOR_REAL_TEST_BINARY:?}"
[ "$(ip -o link show | wc -l)" -eq 1 ]
[ "$(ip -o link show | awk '{print $2}')" = 'lo:' ]
[ -z "$(ip -4 route show default)" ]
[ -z "$(ip -6 route show default)" ]
ip link set lo up
work=$(mktemp -d)
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    for attempt in $(seq 1 5); do
        alive=false
        for pid in "${pids[@]}"; do if kill -0 "$pid" 2>/dev/null; then alive=true; fi; done
        [ "$alive" = true ] || break
        sleep 1
    done
    for pid in "${pids[@]}"; do kill -KILL "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

for name in a b; do
    if [ "$name" = a ]; then port=39101; else port=39102; fi
    mkdir -m 700 "$work/$name"
    conf="$work/$name/torrc"
    printf '%s\n' \
        "DataDirectory $work/$name" \
        "Nickname local$name" \
        "Address 127.0.0.1" \
        "ORPort 127.0.0.1:$port" \
        'SocksPort 0' \
        'BridgeRelay 1' \
        'ExitRelay 0' \
        'PublishServerDescriptor 0' \
        'AssumeReachable 1' \
        'TestingTorNetwork 1' \
        'DirAuthority local orport=39103 v3ident=1111111111111111111111111111111111111111 127.0.0.1:39104 2222222222222222222222222222222222222222' > "$conf"
    "$TOR_REAL_BINARY" -f "$conf" --list-fingerprint > "$work/$name/fingerprint-output" 2>&1
    "$TOR_REAL_BINARY" -f "$conf" > "$work/$name/log" 2>&1 &
    pids+=("$!")
done

for name in a b; do
    for attempt in $(seq 1 120); do
        if [ "$name" = a ]; then port=39101; index=0; else port=39102; index=1; fi
        if [ -s "$work/$name/fingerprint" ] && (echo > "/dev/tcp/127.0.0.1/$port") 2>/dev/null; then break; fi
        kill -0 "${pids[$index]}"
        sleep 1
    done
    [ -s "$work/$name/fingerprint" ] && (echo > "/dev/tcp/127.0.0.1/$port") 2>/dev/null || { printf 'Мост не готов %s\n' "$name" >&2; exit 1; }
done
export TOR_REAL_A_PORT=39101 TOR_REAL_B_PORT=39102
export TOR_REAL_A_BRIDGE="127.0.0.1:$TOR_REAL_A_PORT $(awk '{print $2}' "$work/a/fingerprint")"
export TOR_REAL_B_BRIDGE="127.0.0.1:$TOR_REAL_B_PORT $(awk '{print $2}' "$work/b/fingerprint")"
test_name=bridge_maintenance::real_channel_tests::real_channel_heal_and_config_selection
[ "$("$TOR_REAL_TEST_BINARY" --ignored --exact "$test_name" --list | awk -v name="$test_name: test" '$0 == name { n++ } END { print n+0 }')" -eq 1 ]
"$TOR_REAL_TEST_BINARY" --ignored --exact "$test_name" --nocapture
