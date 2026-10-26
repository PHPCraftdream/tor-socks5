#!/usr/bin/env bash
# Валидация имени релизного тега (vMAJOR.MINOR.PATCH или vMAJOR.MINOR.PATCH-prerelease).
#
# Контракт для тестов:
#   Вход: имя тега в argv[1]; если аргумент НЕ передан — из env TAG.
#     Пустой argv[1] (аргумент передан, но пуст) — ошибка, тихий fallback на TAG запрещён.
#   Выход: exit 0 при успехе; exit 1 при любой ошибке (текст ошибки в stderr).
#   stdout при успехе (формат для $GITHUB_OUTPUT), строго ПОСЛЕ полной валидации:
#     tag=<tag>
#     prerelease=true|false
#   Вход жёстко фильтруется, НЕ санитизируется: разрешены только [A-Za-z0-9.-].
#   Build metadata '+' не поддерживается (установщики её не принимают).
#   Ядро — ровно X.Y.Z (anchored regex), без ведущих нулей:
#     valid: v0.3.10, v10.20.300, v0.0.0; invalid: v0.3, v0.3.0.1, v01.2.3, пустые поля.
#   Любой суффикс после PATCH через '-' => prerelease=true; prerelease — непустые
#   dot-separated идентификаторы без пустых (`.rc`, `rc.`, `rc..1` — reject);
#   числовой идентификатор с ведущим нулём reject (SemVer: `01` нельзя, `0`/`10` можно).

set -euo pipefail

# ${1-...}: различает unset и present-empty — пустой argv[1] НЕ заменяется env TAG.
tag="${1-${TAG:-}}"
if [ -z "$tag" ]; then
  if [ "$#" -ge 1 ]; then
    echo "ОШИБКА: argv[1] передан пустым; fallback на env TAG не выполняется" >&2
  else
    echo "ОШИБКА: имя тега не передано (argv[1] или env TAG)" >&2
  fi
  exit 1
fi

# Жёсткий фильтр: переводы строк, кавычки, пробелы, '+' и прочие shell-символы запрещены.
case "$tag" in
  *[!A-Za-z0-9.-]*)
    echo "ОШИБКА: недопустимые символы в теге (разрешены только A-Z a-z 0-9 . -)" >&2
    exit 1
    ;;
esac

case "$tag" in
  v*) : ;;
  *)
    echo "ОШИБКА: тег '$tag' должен начинаться с 'v'" >&2
    exit 1
    ;;
esac

rest="${tag#v}"

# Разделение на ядро и prerelease по ПЕРВОМУ '-'.
prerelease=false
core="$rest"
pre=""
case "$rest" in
  *-*)
    core="${rest%%-*}"
    pre="${rest#*-}"
    prerelease=true
    ;;
esac

# Ядро версии: ровно X.Y.Z, каждое поле — без ведущих нулей (0 допустим).
core_re='^([0-9]|[1-9][0-9]*)\.([0-9]|[1-9][0-9]*)\.([0-9]|[1-9][0-9]*)$'
if ! [[ $core =~ $core_re ]]; then
  echo "ОШИБКА: тег '$tag' должен быть формы vX.Y.Z (три числа без ведущих нулей)" >&2
  exit 1
fi

# Prerelease: непустые dot-separated идентификаторы; символы уже гарантированы
# фильтром выше ([A-Za-z0-9.-]); числовой идентификатор с ведущим нулём запрещён.
if [ "$prerelease" = true ]; then
  if [ -z "$pre" ]; then
    echo "ОШИБКА: пустой prerelease-суффикс в теге '$tag'" >&2
    exit 1
  fi
  id_re='^[0-9]+$'
  # Явный фильтр: ведущая/хвостовая точка и две точки подряд запрещены.
  # `read -a` теряет последний пустой элемент (rc. дал бы один id "rc"),
  # поэтому без этого фильтра `v0.3.0-rc.` ошибочно проходил бы.
  case "$pre" in
    .*|*.|*..*)
      echo "ОШИБКА: пустой идентификатор в prerelease тега '$tag'" >&2
      exit 1
      ;;
  esac
  IFS='.' read -r -a ids <<< "$pre"
  for id in "${ids[@]}"; do
    if [ -z "$id" ]; then
      echo "ОШИБКА: пустой идентификатор в prerelease тега '$tag'" >&2
      exit 1
    fi
    if [[ $id =~ $id_re ]] && [ "${#id}" -gt 1 ] && [ "${id:0:1}" = "0" ]; then
      echo "ОШИБКА: ведущие нули запрещены в числовом идентификаторе prerelease ('$id' в '$tag')" >&2
      exit 1
    fi
  done
fi

# stdout — только после полной валидации.
printf 'tag=%s\n' "$tag"
printf 'prerelease=%s\n' "$prerelease"
