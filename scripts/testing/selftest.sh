#!/bin/sh
# Проверка маршрутизации только в CI; локальные хуки её не запускают.
set -eu
[ "${GITHUB_ACTIONS:-}" = true ] || { echo 'selftest is CI-only' >&2; exit 1; }
exec python -I scripts/testing/test_ci_planner.py
