#!/usr/bin/env bash
# Публикация GitHub Release по валидированному тегу. Запускать из корня checkout
# (не из каталога артефактов); все сетевые вызовы — только через `gh` в PATH
# (в тестах подменяется stub'ом).
#
# === Контракт для тестов ===
# Входные данные (только env, аргументов нет):
#   TAG           — имя тега (vX.Y.Z или vX.Y.Z-prerelease); повторно валидируется
#                   через .github/release/validate-tag.sh, класс сверяется с PRERELEASE;
#   PRERELEASE    — true|false (из validate-tag.sh);
#   ARTIFACTS_DIR — каталог РОВНО с 8 файлами (4 архива + 4 .sha256); каждая запись
#                   каталога (включая hidden/dangling symlinks/подкаталоги) обязана
#                   быть одним из 8 ожидаемых имён: regular, non-empty, НЕ symlink;
#   GH_TOKEN      — токен GitHub (задаёт workflow; никогда не печатается);
#   REMOTE_REPO   — "owner/name" (в workflow = github.repository); не печатается.
# Выход: exit 0 — успех; exit 1 — ошибка любого шага. Прогресс — в stdout/stderr.
# Шаг 0 (без сети): TAG через validate-tag.sh; prerelease= из вывода должен
#   совпасть с PRERELEASE, иначе fail.
# Шаг 1 (без сети): строгий local entry check + побайтная сверка .sha256:
#   пересчёт sha256 архивов (статус sha256sum проверяется отдельно, не в pipeline),
#   затем cmp <(printf '<hash>  <имя>\n') для tar.gz и <(printf '<hash> *<имя>')
#   без LF для zip. Bad hex/CRLF/вторая строка/hash mismatch — fail БЕЗ gh-вызовов.
# Шаг 2 (read-only gh): `gh api --paginate --slurp "repos/$REMOTE_REPO/releases"`
#   + jq поиск exact tag => absent | draft | published. Сбой API/сети — явная
#   ошибка (НЕ 'absent'). Пустой список — честный 'absent'.
# Шаг 3 (мутации): published c полным комплектом (ровно один asset на имя,
#   size>0, state=uploaded) и совпадающим классом — no-op, exit 0 БЕЗ строки
#   «Готово: ... опубликован»; published с несоответствием — fail без мутаций;
#   draft/absent — ПЕРЕД upload отдельный GET releases/$id с typed-проверками
#   (id/tag/draft==true/prerelease — boolean) => fail без загрузки при любом
#   несоответствии; затем upload --clobber своих 8 файлов + повторная
#   state-проверка + check_assets + сверка размеров ВСЕХ 8 файлов (числа
#   байтов, manifest локальных размеров считается до первого gh-вызова)
#   + PATCH {"draft":false,...,"make_latest":...} + readback с typed-
#   предикатами (id/tag/draft==false/prerelease==JSON boolean) + ассеты и
#   размеры. Extra user-ассеты на remote no-op не мешают. Размеры при
#   published НЕ сравниваются с локальными (недетерминизм rebuild'а).
#   ID релиза валидируется как число ДО URL-мутаций; несколько релизов с тем
#   же тегом (length>1) — fail.

set -euo pipefail

fail() { echo "ОШИБКА (publish.sh): $*" >&2; exit 1; }

[ -n "${TAG:-}" ] || fail "не задан env TAG"
[ -n "${PRERELEASE:-}" ] || fail "не задан env PRERELEASE"
[ -n "${ARTIFACTS_DIR:-}" ] || fail "не задан env ARTIFACTS_DIR"
[ -n "${REMOTE_REPO:-}" ] || fail "не задан env REMOTE_REPO"
[ -n "${GH_TOKEN:-}" ] || fail "не задан env GH_TOKEN"
[ "$PRERELEASE" = "true" ] || [ "$PRERELEASE" = "false" ] || fail "PRERELEASE должен быть true|false"

# === Шаг 0: повторная валидация тега и сверка класса prerelease ===
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
vt_out="$(bash "$script_dir/validate-tag.sh" "$TAG")" || fail "тег '$TAG' не прошёл validate-tag.sh"
vt_pre="$(printf '%s\n' "$vt_out" | sed -n 's/^prerelease=//p')"
[ "$vt_pre" = "$PRERELEASE" ] || fail "класс тега (validate-tag.sh: prerelease=$vt_pre) не совпадает с PRERELEASE=$PRERELEASE"

# Ожидаемые ассеты: 2 цели tar.gz (Unix), 1 zip (Windows) — итого 4 таргета, 8 файлов.
UNIX_TARGETS="x86_64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin"
WIN_TARGETS="x86_64-pc-windows-msvc"

# === Шаг 1: строгая локальная проверка комплекта (без сети) ===

shopt -s dotglob nullglob

expected_files=""
for t in $UNIX_TARGETS; do
  expected_files="$expected_files tor-socks5-$TAG-$t.tar.gz tor-socks5-$TAG-$t.tar.gz.sha256"
done
for t in $WIN_TARGETS; do
  expected_files="$expected_files tor-socks5-$TAG-$t.zip tor-socks5-$TAG-$t.zip.sha256"
done

in_expected() { # имя файла входит в список ожидаемых
  local b="$1" f
  for f in $expected_files; do [ "$b" = "$f" ] && return 0; done
  return 1
}

[ -d "$ARTIFACTS_DIR" ] || fail "ARTIFACTS_DIR не существует или не каталог: $ARTIFACTS_DIR"

expected_count=0
for f in $expected_files; do
  expected_count=$((expected_count + 1))
  p="$ARTIFACTS_DIR/$f"
  [ -e "$p" ] || fail "не найден файл: $f"
  [ -L "$p" ] && fail "файл является symlink: $f"
  [ -f "$p" ] || fail "не обычный файл: $f"
  [ -s "$p" ] || fail "файл пуст: $f"
done

# Каждая запись каталога (dotglob: включая hidden, dangling symlinks, подкаталоги)
# обязана быть одним из 8 ожидаемых имён. Лишнее не удаляем — только fail.
actual_count=0
for p in "$ARTIFACTS_DIR"/*; do
  actual_count=$((actual_count + 1))
  b="${p##*/}"
  in_expected "$b" || fail "посторонняя запись в каталоге артефактов: $b"
  [ -e "$p" ] || fail "запись является dangling symlink: $b"
  [ -L "$p" ] && fail "запись является symlink: $b"
  [ -f "$p" ] || fail "запись не обычный файл: $b"
  [ -s "$p" ] || fail "файл пуст: $b"
done
[ "$actual_count" -eq "$expected_count" ] || fail "ожидалось $expected_count файлов, найдено $actual_count"

# Побайтная сверка .sha256: пересчёт sha256 (статус НЕ маскируем pipeline'ом),
# затем точное сравнение ожидаемой строки через cmp с process substitution.
# tar.gz: "<hash>  <имя>\n" (два пробела, LF); zip: "<hash> *<имя>" без LF.
verify_checksum() {
  local archive_name="$1" archive="$ARTIFACTS_DIR/$1" sum_file="$ARTIFACTS_DIR/$1.sha256" out actual
  # sha256sum читает архив через stdin: имя файла не попадает в вывод и не может
  # сбить парсинг (filename-escaping). Вывод формы "<hash> -" — берём 1-е поле.
  out="$(sha256sum < "$archive")" || fail "не удалось посчитать sha256 для $archive_name"
  actual="${out%% *}"
  # Настоящая hex-валидация: ровно 64 символа [0-9a-f].
  case "$actual" in
    *[!0-9a-f]*|"") fail "sha256sum вернул не 64 hex-символа для $archive_name" ;;
  esac
  [ "${#actual}" -eq 64 ] || fail "sha256sum вернул не 64 hex-символа для $archive_name"
  if [[ "$archive_name" == *.zip ]]; then
    cmp -s <(printf '%s *%s' "$actual" "$archive_name") "$sum_file" \
      || fail "checksum-файл $archive_name.sha256 не совпадает с ожидаемым (формат: '<hash> *<имя>', без LF)"
  else
    cmp -s <(printf '%s  %s\n' "$actual" "$archive_name") "$sum_file" \
      || fail "checksum-файл $archive_name.sha256 не совпадает с ожидаемым (формат: '<hash>  <имя>' + LF)"
  fi
}

for f in $expected_files; do
  case "$f" in
    *.sha256) : ;;
    *) verify_checksum "$f" ;;
  esac
done
echo "Шаг 1: комплект из $expected_count файлов и контрольные суммы в порядке."

# Заранее (до ПЕРВОГО gh-вызова) строим manifest размеров ВСЕХ 8 локальных
# файлов, включая .sha256 — чтобы сетевые шаги не зависели от локального stat.
sizes_json='{}'
for f in $expected_files; do
  p="$ARTIFACTS_DIR/$f"
  sz="$(stat -c%s "$p")" || fail "не удалось определить размер $f"
  sizes_json="$(printf '%s' "$sizes_json" | jq -c --arg n "$f" --argjson s "$sz" '. + {($n): $s}')"
done

shopt -u dotglob nullglob

# Имена ассетов для jq — построчно (word splitting безопасен: только [A-Za-z0-9.-]).
names_json="$(printf '%s\n' $expected_files | jq -Rn '[inputs]')"

# === Шаг 2: read-only — состояние релиза на remote (только через gh) ===

releases_json="$(gh api --paginate --slurp "repos/$REMOTE_REPO/releases?per_page=100")" \
  || fail "не удалось получить список релизов (gh api); сеть/API недоступна — повторите запуск"

state="$(printf '%s' "$releases_json" | jq -r --arg tag "$TAG" '
  (if type != "array" then error("ожидался массив релизов или страниц")
   elif all(.[]; type == "array") then (add // [])
   elif all(.[]; type == "object") then .
   else error("неверная структура списка релизов") end)
  | if all(.[]; type == "object"
      and (.tag_name | type) == "string"
      and (.draft | type) == "boolean"
      and (.prerelease | type) == "boolean"
      and (.id | type) == "number" and .id > 0)
    then . else error("неверная структура объекта релиза") end
  | map(select(.tag_name == $tag))
  | if length == 0 then "absent"
    elif length > 1 then "ambiguous"
    elif (.[0].draft | type) != "boolean"
      or (.[0].prerelease | type) != "boolean"
      or ((.[0].id // 0) | type) != "number"
      or (.[0].id // 0) <= 0 then "invalid-type"
    elif .[0].draft then "draft"
    else "published"
    end
')" || fail "не удалось разобрать ответ GitHub API (jq)"
case "$state" in
  absent|draft|published) : ;;
  ambiguous) fail "на remote найдено несколько релизов с тегом $TAG — состояние неоднозначно" ;;
  invalid-type) fail "поля release для $TAG имеют неверные типы (draft/prerelease не boolean или id не число>0)" ;;
  *) fail "неожиданное состояние релиза: '$state'" ;;
esac

# === Общая проверка ассетов по ответу API ===
# Для КАЖДОГО из 8 ожидаемых имён: ровно один asset, .size — число > 0,
# .state == "uploaded". Аргумент: JSON объекта release (stdin).
# Вывод: список «плохих» имён (пустая строка = всё в порядке).
check_assets() {
  local report="$1"
  printf '%s' "$report" | jq -r --argjson names "$names_json" '
    [.assets[]?] as $assets
    | [ $names[] as $n
        | ([$assets[] | select(.name == $n)]) as $m
        | select(
            ($m | length) != 1
            or (($m[0].size // null) | type) != "number"
            or ($m[0].size // 0) <= 0
            or (($m[0].state // "") != "uploaded"))
        | $n ]
    | join(", ")
  ' || fail "не удалось проверить ассеты (jq)"
}

# Для DRAFT после upload: размеры каждого asset из API должны совпасть с
# размерами локальных файлов (сравнение чисел байтов/размеров; для published
# не используется — rebuild недетерминирован).
# Аргументы: report (JSON release, stdin) и sizes_json (готовый manifest
# размеров всех 8 файлов, включая .sha256).
check_asset_sizes() {
  local report="$1" sizes_json="$2"
  printf '%s' "$report" | jq -r --argjson sizes "$sizes_json" '
    [ ($sizes | keys[]) as $n
      | ([.assets[]? | select(.name == $n)][0].size) as $s
      | select(($sizes[$n] // -1) != $s) | $n ]
    | if length == 0 then ""
      else "размеры не совпали: " + join(", ") end
  ' || fail "не удалось сверить размеры ассетов (jq)"
}

# === Шаг 3: draft-ветка — загрузка своих 8 ассетов и публикация ===

# Узкая проверка state релиза перед мутацией/после неё (НЕ атомарная защита
# от любых внешних гонок). Аргументы: report (stdin) и ожидаемый числовой id.
# Typed-предикаты: id/tag/draft=false/prerelease=JSON boolean. Любой сбой — fail.
verify_release_obj() {
  local report="$1" expected_id="$2" pre_json
  if [ "$PRERELEASE" = "true" ]; then pre_json=true; else pre_json=false; fi
  printf '%s' "$report" | jq -e --argjson id "$expected_id" --arg tag "$TAG" --argjson pre "$pre_json" '
    .id == $id and .tag_name == $tag
    and (.draft | type) == "boolean" and .draft == false
    and (.prerelease | type) == "boolean" and .prerelease == $pre
  ' >/dev/null || fail "проверка релиза не пройдена (id/tag/draft=false/prerelease=$pre_json)"
}

upload_and_publish() {
  local release_id="$1" report bad
  # Числовой ID проверяем ДО любых URL-мутаций.
  expr "$release_id" : '[0-9]\{1,\}$' >/dev/null || fail "некорректный числовой ID релиза: '$release_id'"

  # Отдельный GET целевого релиза: не доверяем объекту из списка — он мог
  # устареть (например, релиз уже опубликован другой гонкой).
  report="$(gh api "repos/$REMOTE_REPO/releases/$release_id")" \
    || fail "не удалось перечитать релиз перед загрузкой ассетов"
  # До загрузки требуется именно draft; опубликованный релиз не изменяем.
  printf '%s' "$report" | jq -e --argjson id "$release_id" --arg tag "$TAG" '
    .id == $id and .tag_name == $tag and (.draft | type) == "boolean" and .draft == true
    and (.prerelease | type) == "boolean"
  ' >/dev/null || fail "перед upload релиз не является draft с ожидаемым id/tag — прерываем БЕЗ загрузки"

  for f in $expected_files; do
    gh release upload "$TAG" "$ARTIFACTS_DIR/$f" --clobber --repo "$REMOTE_REPO" \
      || fail "не удалось загрузить ассет $f (релиз остался в draft, latest не изменён)"
  done

  report="$(gh api "repos/$REMOTE_REPO/releases/$release_id")" \
    || fail "не удалось перечитать релиз после загрузки ассетов"
  # Повторная state-проверка после загрузки: всё ещё наш draft с тем же id/tag.
  printf '%s' "$report" | jq -e --argjson id "$release_id" --arg tag "$TAG" '
    .id == $id and .tag_name == $tag and (.draft | type) == "boolean" and .draft == true
    and (.prerelease | type) == "boolean"
  ' >/dev/null || fail "после загрузки релиз не является draft с ожидаемым id/tag"
  bad="$(check_assets "$report")"
  [ -z "$bad" ] || fail "проверка ассетов не пройдена: $bad (релиз остался в draft, latest не изменён)"
  bad="$(check_asset_sizes "$report" "$sizes_json")"
  [ -z "$bad" ] || fail "сверка размеров ассетов не пройдена: $bad (релиз остался в draft, latest не изменён)"

  # PATCH: make_latest — STRING enum по GitHub REST; draft/prerelease — JSON boolean.
  # Для prerelease используем "false" (не в /releases/latest), для stable — "legacy"
  # (latest = новейший stable по правилам GitHub).
  if [ "$PRERELEASE" = "true" ]; then
    body='{"draft": false, "prerelease": true, "make_latest": "false"}'
  else
    body='{"draft": false, "prerelease": false, "make_latest": "legacy"}'
  fi
  printf '%s' "$body" | gh api --method PATCH "repos/$REMOTE_REPO/releases/$release_id" --input - \
    || fail "PATCH публикации не удался; НЕ утверждаем, что релиз остался draft — сервер мог применить изменение до сбоя сети; безопасный повторный запуск распознает published и сделает no-op"

  # Readback: сервер обязан подтвердить draft=false, класс и все 8 ассетов.
  report="$(gh api "repos/$REMOTE_REPO/releases/$release_id")" \
    || fail "не удалось перечитать релиз после PATCH"
  # Typed-сравнение через jq (не shell-текст): id/tag/draft=false/prerelease.
  verify_release_obj "$report" "$release_id"
  bad="$(check_assets "$report")"
  [ -z "$bad" ] || fail "readback: проверка ассетов не пройдена: $bad"
  bad="$(check_asset_sizes "$report" "$sizes_json")"
  [ -z "$bad" ] || fail "readback: сверка размеров ассетов не пройдена: $bad"
}

case "$state" in
  published)
    info="$(printf '%s' "$releases_json" | jq -c --arg tag "$TAG" '
      (if (type == "array") and ((.[0]? // null | type) == "array") then flatten else . end)
      | map(select(.tag_name == $tag))[0]')"
    bad="$(check_assets "$info")"
    [ -z "$bad" ] || fail "релиз $TAG уже PUBLISHED, но ассеты неполны/невалидны: $bad; перезапись/удаление запрещены — исправьте вручную"
    is_pre="$(printf '%s' "$info" | jq -r '.prerelease | tostring')" || fail "jq: prerelease"
    [ "$is_pre" = "$PRERELEASE" ] || fail "класс prerelease релиза ($is_pre) не совпадает с тегом ($PRERELEASE) — мутации запрещены"
    # Размеры при published намеренно НЕ сверяем с локальным rebuild (недетерминизм).
    echo "Релиз $TAG уже полностью опубликован с корректным набором ассетов — no-op, изменений не требуется."
    exit 0
    ;;

  absent)
    # Тег должен существовать на remote: --verify-tag заставит gh отказаться
    # создавать релиз по несуществующему тегу. Тег сами НЕ создаём.
    gh release create "$TAG" --draft --verify-tag --repo "$REMOTE_REPO" \
      --title "tor-socks5 $TAG" \
      --notes "Сборка tor-socks5 $TAG" \
      || fail "не удалось создать draft release (существует ли тег $TAG на remote?)"
    release_id="$(gh api "repos/$REMOTE_REPO/releases/tags/$TAG" | jq -r '.id')" \
      || fail "не удалось получить ID созданного релиза"
    upload_and_publish "$release_id"
    ;;

  draft)
    release_id="$(gh api "repos/$REMOTE_REPO/releases/tags/$TAG" | jq -r '.id')" \
      || fail "не удалось получить ID draft-релиза"
    upload_and_publish "$release_id"
    ;;
esac

echo "Готово: релиз $TAG опубликован (prerelease=$PRERELEASE)."
