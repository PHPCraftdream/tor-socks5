# Отчёт по находкам: research p/q

## Parent-пересчёт выполнен

Parent выполнил p и независимый q с `python -I`, неизменными input pins и source SHA-256 `204b4ffe542b298dd1da120078cf193941f65a7cbba9fe31ee5e60fd6e793f6c`. Оба data-only запуска завершились exit 0. Все три файла дополнительно сравнены прямым `cmp`: побайтно идентичны. Подтверждены 727 компонентов, 727 обработанных архивов, 0 archive failures; все 15 ложных `branch_substantive_text_not_located_by_content` исчезли. Ни project tests, ни production validators не запускались. Это не legal approval. Команда выполненного p (для нового запуска требуется новое эксклюзивное имя output):

```sh
python -I docs/project/license/release-components-40934653900-repro/materials/research.py \
  --report target/materials-20261030-d/report.json \
  --report-size 14665213 \
  --report-sha256 ca11d57b71928b2d23400d2df0cb04fc08580f3b97cd2988fa7ea083d2fa0055 \
  --materials target/materials-20261030-d/materials.json \
  --materials-size 86208679 \
  --materials-sha256 aa67048c936c30403499338457aee93af52a2b05ff64e6897e8468c10e1ff399 \
  --target-root target \
  --output target/materials-research-20261030-p
```

Текущие результаты — p/q; n/o сохранены как история до сверки. Показатели содержательного чтения ниже относятся к ledger n/o, если явно не указано иное: parent не выдаёт новый машинный пересчёт за самостоятельное чтение всех 402 групп. Полные pins p/q приведены в README этого каталога.

## Покрытие

- Слой archives/copies: 727/727 registry crate разобраны (`DATA_COMPLETE`), 1212/1212 копий совпали побайтно, независимый повтор audit идентичен. 18 ранее отклонённых raw modes поддержаны только как redundant regular-случаи (0o100000 при typeflag 0/NUL, права ≤ 0o777), устройств 0; совместимость — по локальному stdlib Python, не происхождение producer.
- Содержательное чтение: 1184 material records, 402 уникальных группы полных текстов (SHA-256); все 1184 `substantively_read=true`, непрочитанных 0. 366 групп прочитаны заново в этом раунде, 36 — покрыты более ранними верифицированными чтениями. Новая evidence привязана к 624 компонентам.
- 645 из 727 компонентов имеют condition evidence; каждый из 727 — либо condition evidence, либо явный blocker; 0 без обоих.
- `condition_evidence` — только ручные/содержательные span, не keyword-совпадения; автоматический marker scan помечен отдельно и не устанавливает permissions/conditions/limits; `conclusion_ru` не выводит юридические эффекты.

## Что прочитано заново

366 групп полных текстов прочитаны заново с русскими мотивировками, решениями и line span в `target/unread-evidence-20261030-merged-v2/all.json` (425379 байт, SHA-256 `d3c85af14dcd911355a04ee42f0503d9d36e778442a1e9b5b124ba27a5cc2d9c`, ровно 366 ключей). Верифицированные полные/смешанные чтения включают: разбиение XZ `COPYING`, ring BoringSSL/other-bits/once_cell, CDLA, Text-Template Artistic/GPL, sqlcipher, стандартные семейства MIT/Apache/BSD/MPL/GPL.

## Решения — ровно 366 заново прочитанных групп

Распределение групповых решений ниже — **только по 366 группам, прочитанным заново**: `full_terms_observed` 353, `mixed_terms_observed` 6, `native_or_data_specific_terms` 3, `referral_only` 2, `declaration_only` 2. Всего покрытых групп: **402 = 366 новых + 36 ранее верифицированных**; значения, производные от 366, не выдаются за распределение по всем 402 группам. По всем 1184 записям: `full_terms_observed` 1114, `mixed_terms_observed` 23, `native_or_data_specific_terms` 22, `declaration_only` 7, `declaration_only_candidate` 8, `referral_only` 7, `explicit_no_license_statement` 1, `pointer_multiple_materials` 1, `substantive_terms_observed` 1. Это наблюдения текста, **не** юридические заключения и не одобрение.

## Provenance семантического review span

35 записей part1 (заново открытые/suspect) и named-группа `c144680885b29e4719e2a51f0aab5439a1e02d980692b5aaf086cae12727f28b` прошли review чтением текста (read-only); в `research.py` — множество `SEMANTIC_SPAN_REVIEWED_HASHES` (36 хешей), поля `semantic_span_review: 'confirmed_by_read_only_text_review'`. Пины: part1 review JSON 24996 байт, SHA-256 `9aea66865464fa3c9b464417a564c6e2030e4610d5d45131c85ea4dfbc48f5b4`; named-group review JSON 5623 байта, SHA-256 `269b45b3049aaf4fbe74fee96a84256024e2678100d1ce53dc4c691fef761892`. Это подтверждает provenance записей и само по себе не одобряет какую-либо лицензию. Сверка branch-matcher: карта `MANUAL_BRANCH_RECONCILIATION` фиксирует все 15 случаев `branch_substantive_text_not_located_by_content` из n (review-сверка, не утверждение о наличии отсутствующих внешних текстов и не одобрение выбора лицензии).

## Исторические counts n и исправленный остаток p/q

В p/q отсутствуют 15 ложных `branch_substantive_text_not_located_by_content`; значения остальных девяти типов совпадают с таблицей ниже. Ни один настоящий внешний/missing-material blocker не снимался ради положительного результата.

| Blocker | Count |
| --- | ---: |
| `absent_standalone_branch_material` | 164 |
| `branch_material_missing_from_named_text_set` | 2 |
| `branch_substantive_text_not_located_by_content` | 15 |
| `declaration_and_missing_named_license` | 2 |
| `declaration_not_full_license` | 2 |
| `declaration_or_referral_only` | 10 |
| `external_ccadb_terms_not_saved` | 2 |
| `llvm_exception_full_text_not_found_in_retained_materials` | 4 |
| `outside_crate_readme_referral` | 2 |
| `referenced_material_not_in_archive_inventory` | 83 |

`license_text_not_substantively_read` больше не остаётся. Эти blockers означают: содержательный review всё ещё **не завершён** на уровне источника/обязанностей; это конкретные отсутствующие/внешние/декларативные границы, не доказательство отсутствия прав или текстов. PASS не утверждается.

## Конкретные результаты

- LLVM exception: полный текст ранее отсутствовал среди retained материалов для `wasip3 0.4.0+wasi-0.3.0-rc-2026-01-06`, `wasmparser 0.244.0`, `wit-component 0.244.0`, `wit-parser 0.244.0`; manifest всех четырёх: `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`. Захвачен официальный LLVM `LICENSE.TXT`: `target/llvm-primary-20261030-c/LICENSE.TXT`, commit `e9996a2e210d021783d597d99ccd3199b0885d49`, blob `fa6ac540007032cbd0ec772a1c72e6cb5527a4fe`, 15141 bytes, SHA-256 `8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee`; capture/provenance и условия — в [README](README.md). Официальная цепочка сайта→репозитория установлена через llvm.org и его ссылку на llvm/llvm-project; текущий текст не является разрешением выбора пакетной ветви. §4 исключение (210–213) применимо только при компиляции YOUR source с embedded Software в Object form YOUR source и касается только §§4(a), 4(b), 4(d), не §4(c); GPLv2 условие (215–222) — только Combined Software при судебном конфликте. Не выбирать OR-ветвь. SHA `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5` для reference TEXT относится к другим 12 компонентам. Пины n/o и их исторические counts не обновлены; p/q сохраняет четыре исторических blocker и 12 distinct reference-material ссылок, не доказывающих применимость.

- r-efi: объявлен LGPL-2.1-or-later, полный текст отсутствует.
- dynasm/dynasmrt: объявлен MPL, `LICENSE` отсутствует.
- enum_dispatch/ident_case: полный MIT присутствует, объявленный текст Apache отсутствует.
- plotters×3 и objc2×2: ссылки вне crate.
- webpki-roots: внешний CCADB terms blocker сохранён. Supplemental source capture описан в [README](README.md); запрос текущего raw `curl -L --max-filesize 262144 -D - https://www.ccadb.org/rootstores/usage` был отклонён: `ERROR command is not allowed for security reasons`. Не обходить отказ. Исторический repo snapshot — supplement, не official identity proof и не доказательство исторического grant; современная официальная parent page — не raw. Data/Results не классифицированы автоматически; approval отсутствует. p/q ledger не изменён.

## Исторические пины n/o

До parent-исправлений выполнен `target/materials-research-20261030-n`, повтор `-o` побайтно идентичен: `research.json` 96294938/`ecf78385…f303c24`; `summary.json` 1763/`ace3c424…25395d`; `components.md` 2462830/`13980e67…84637`. Входы закреплены: `report.json` 14665213/`ca11d57b…fa0055`; `materials.json` 86208679/`aa67048c…1ff399`.

## История

Родительский небезопасный инцидент сохранён; legacy больше не запускались. Чтения transcript без pin (63, 66) и `components.md` без size/hash (340–341) — факты. Новые процедурные нарушения дочерних сессий: `643f705a…$$call_6fa515…` сообщения 54/60 — `python -c` и `json.load(open(...))` без `-I` и без pin; `643f705a…$$call_a70cc…` сообщение 47 — то же; `9b84faab…$$call_78eaef…` — `python - <<EOF` и повторные прямые чтения JSON при нормализации span. Позднейшие pinned-выходы эти нарушения не искупают. Отказ `a` — списание бюджета; три отклонённых wrapper; ошибка кодировки консоли; лимит `g` устранён дедупликацией; ложные NOTICE/branch counts `e` исправлены; прежнее заявление о закрытых находках отозвано. Pin до/после применяется к новым разборам, прошлые нарушения не исправлены.

## Границы

Только source distribution; binary composition, native linkage, production origin — вне работы. Семь vendor notices открыты. MPL/LGPL/CDLA/CCADB — human legal review. Allowlist/approval JSON нет. Юридическое одобрение отсутствует. #53 остаётся **PARTIAL**.

## Дальнейшие действия

1. Получить и оценить перечисленные отсутствующие внешние тексты и ссылки.
2. Направить прочитанные условия (особенно смешанные, native/data-specific, альтернативы) в human legal review.
3. Завершить vendor attribution (семь vendor).
4. Только затем рассматривать закрытие конкретных пунктов.
