# Материалы исходного дистрибутива: research p/q

## Подтверждённый parent-пересчёт

Parent выполнил два независимых bounded data-only запуска с `python -I` после проверки исходника и input pins. Оба завершились с exit 0; все три результата p/q дополнительно совпали при прямом `cmp` и SHA-256. В p/q 727 компонентов, 727 обработанных архивов, 0 archive failures; все 15 программно ложных `branch_substantive_text_not_located_by_content` исчезли. Настоящие внешние/отсутствующие материалы остаются blockers. Это не project test, не полный per-file аудит и не legal approval. Команда выполненного p (для нового воспроизведения требуется другое эксклюзивное имя output):

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

Каталоги `target/materials-research-20261030-p` и `-q` созданы эксклюзивно. Входы — прежние закреплённые `report.json` 14665213/`ca11d57b…fa0055` и `materials.json` 86208679/`aa67048c…1ff399`, проверенные до и после разбора. Исторические n/o сохранены без перезаписи.

| Результат p/q | Размер | SHA-256 |
| --- | ---: | --- |
| `research.json` | 96454549 | `43f39d841bf58b128c07f5cecd7359209e0cb1cd6da019c82328e1ab5b81d2a6` |
| `summary.json` | 1711 | `8daf33662c94c5dd1b8d64d54a6e9c6877b106e22920e6a845dc64713aae4a88` |
| `components.md` | 2462522 | `f56c80f8186fb3f4e33ce649ae0f9638292b3cfa3e00f9448969a803e64d07e7` |

В p/q осталось 164 `absent_standalone_branch_material`, 2 `branch_material_missing_from_named_text_set`, 2 `declaration_and_missing_named_license`, 2 `declaration_not_full_license`, 10 `declaration_or_referral_only`, 2 `external_ccadb_terms_not_saved`, 4 `llvm_exception_full_text_not_found_in_retained_materials`, 2 `outside_crate_readme_referral`, 83 `referenced_material_not_in_archive_inventory`. Это разные записи, не число уникальных компонентов. Остальные показатели ниже, помеченные n, сохранены как история; parent не выдаёт их за новое независимое содержательное чтение всех текстов.

## Что сделано

### Слой archives/copies

Завершён и воспроизводим: 727/727 registry crate разобраны (`DATA_COMPLETE`, exit 0, blockers 0); 1212/1212 копий совпали побайтно; независимый повтор audit дал идентичные hash. 18 ранее отклонённых raw modes поддерживаются только как redundant regular-типовые случаи (типовой бит `0o100000` при typeflag `0`/NUL и правах ≤ `0o777`), устройств 0. Совместимость подтверждена текстом локального stdlib Python; это **не** доказательство происхождения producer.

### Новый слой содержательного чтения текстов (завершён для доступных полных retained текстов лицензионных ролей)

- 1184 material records, 402 уникальных группы полных текстов (SHA-256). Все 1184 — `substantively_read=true`; непрочитанных 0.
- 366 групп прочитаны заново в этом раунде; 36 уже были покрыты более ранними верифицированными чтениями.
- Новая evidence привязана к 624 компонентам.
- 645 из 727 компонентов имеют condition evidence; каждый из 727 имеет либо condition evidence, либо явный blocker; 0 не имеют ни того, ни другого.

### Групповые решения — ровно 366 заново прочитанных групп

Распределение ниже — **только по 366 группам, прочитанным заново в этом раунде**, а не по всем 402 покрытым группам: `full_terms_observed` 353; `mixed_terms_observed` 6; `native_or_data_specific_terms` 3; `referral_only` 2; `declaration_only` 2. Всего покрытых групп: **402 = 366 новых + 36 ранее верифицированных**; распределение решений по всем 402 группам из этих значений не выводится.

Распределение решений по всем 1184 записям: `full_terms_observed` 1114; `mixed_terms_observed` 23; `native_or_data_specific_terms` 22; `declaration_only` 7; `declaration_only_candidate` 8; `referral_only` 7; `explicit_no_license_statement` 1; `pointer_multiple_materials` 1; `substantive_terms_observed` 1.

Это **наблюдения текста**, не юридические заключения и не одобрение.

### Семантика evidence

`condition_evidence` содержит только ручные/содержательные span, не keyword-совпадения. Автоматический marker scan помечен отдельно и не устанавливает permissions/conditions/limits. `conclusion_ru` не выводит юридические эффекты. Наблюдения по веткам различают содержательную ручную evidence и keyword marker-совпадения.

### Provenance семантического review span

35 записей part1 (заново открытые/suspect) плюс named-группа `c144680885b29e4719e2a51f0aab5439a1e02d980692b5aaf086cae12727f28b` прошли семантический review чтением текста (read-only); в `research.py` это множество `SEMANTIC_SPAN_REVIEWED_HASHES` (36 хешей), и соответствующим `manual_observation` добавляется `semantic_span_review: 'confirmed_by_read_only_text_review'`. Пины источников: part1 review JSON 24996 байт, SHA-256 `9aea66865464fa3c9b464417a564c6e2030e4610d5d45131c85ea4dfbc48f5b4`; named-group review JSON 5623 байта, SHA-256 `269b45b3049aaf4fbe74fee96a84256024e2678100d1ce53dc4c691fef761892`. Это подтверждает provenance этих записей и **само по себе не одобряет** какую-либо лицензию.

Перед запуском p parent перечитал полные libm и Apache-with-LLVM тексты из `target/unread-groups-20261030-a/unread-groups.txt` (1519674 байта, SHA-256 `6aec8686bbbb5bc21bc603cb20a2ffc26690b7ce5cae457461e4238323b0571d`; hash сверён до и после чтения). Для libm `3823dda7…16bb7` исправления включают contributor declaration, полный Apache и native/source notices до локальной строки 258. Для LLVM `268872b9…86bc5` включены раздел 9 до строки 175 и GPLv2-conflict clause 212–219. `PARENT_SPAN_CORRECTIONS` изменяет реальные входные spans до их построения; прежние review JSON сохранены как история, а не выданы за исправленные. Отсутствие цитаты короче 1500 bytes больше не означает отсутствие содержательного чтения: сводка ссылается на полную `condition_evidence`.

Сверка branch-matcher: карта `MANUAL_BRANCH_RECONCILIATION` в `research.py` документирует все 15 случаев `branch_substantive_text_not_located_by_content` из n (компонент/версия/ветвь + подтверждённый hash материала). Это карта сверки review, не утверждение о существовании отсутствующих внешних текстов и не одобрение выбора лицензии.

## Pins research n

Финальный закреплённый запуск `target/materials-research-20261030-n`, независимый повтор `target/materials-research-20261030-o`, выходы побайтно идентичны:

| Файл | Размер | SHA-256 |
| --- | ---: | --- |
| `research.json` | 96294938 | `ecf783859be8bb718e093c669f8242ae7bc14903a3900ddbb52eec379f303c24` |
| `summary.json` | 1763 | `ace3c424b96883fb775b10a84dc89943717b4f616ec7520b0360639c8325395d` |
| `components.md` | 2462830 | `13980e67e39473011ab3d47bda1cc8e5f9848ca6d9d0d0893da5e5a8fbc84637` |

Входы остаются закреплёнными: `report.json` 14665213 байт, SHA-256 `ca11d57b71928b2d23400d2df0cb04fc08580f3b97cd2988fa7ea083d2fa0055`; `materials.json` 86208679 байт, SHA-256 `aa67048c936c30403499338457aee93af52a2b05ff64e6897e8468c10e1ff399`.

Объединённый файл содержательной evidence: `target/unread-evidence-20261030-merged-v2/all.json`, 425379 байт, SHA-256 `d3c85af14dcd911355a04ee42f0503d9d36e778442a1e9b5b124ba27a5cc2d9c`; ровно 366 ключей; одна известная опечатка ключа исправлена на точный hash. Файл фиксирует русскую мотивировку, решение и локальные line span. Evidence получена чтением экспортированных полных текстов групп, не keyword-выводом.

## Точные counts blockers n

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

`license_text_not_substantively_read` больше не остаётся. Эти blockers означают, что содержательный review всё ещё **не завершён** на уровне источника/обязанностей; это конкретные границы отсутствующего/внешнего/декларативного, не доказательство отсутствия прав или текстов. PASS/закрытие не утверждается.

## Инструменты

| Инструмент | Размер | SHA-256 |
| --- | ---: | --- |
| `audit.py` | 13553 | `fdfd1768ba9bb4d23c83dd9f3ed97022cbc5d90546190e32716e7797a9d4db0d` |
| `archive-data.py` | 12441 | `d6b5e7e2ffaa4d6dda634230ef29be43df9f05ffd43654b7ee9ad55e7fe6c8e2` |
| `tar-data.py` | 7758 | `b1ac0f8bf8e1a4b4bdf0fedb4a642c6048549eae7a5476a9469c944e62216fa9` |
| `research.py` | 503744 (855 строк) | `204b4ffe542b298dd1da120078cf193941f65a7cbba9fe31ee5e60fd6e793f6c` |
| `summarize.py` | 5024 | `cc4342ec6fe33cbd2a61e6a3093021023da3c8d149fd1e9d4737503bdd78c146` |
| `../analyze-safe.py` | 23856 | `e02523826493e5816d644bf77d802917bb7773b5d01c158ccb06227af8f43a43` |

## Воспроизведение

```sh
python -I docs/project/license/release-components-40934653900-repro/materials/research.py \
  --report target/materials-20261030-d/report.json \
  --report-size 14665213 \
  --report-sha256 ca11d57b71928b2d23400d2df0cb04fc08580f3b97cd2988fa7ea083d2fa0055 \
  --materials target/materials-20261030-d/materials.json \
  --materials-size 86208679 \
  --materials-sha256 aa67048c936c30403499338457aee93af52a2b05ff64e6897e8468c10e1ff399 \
  --target-root target \
  --output target/materials-research-new
```

Pin проверяется до и после каждого разбора; для каждого запуска требуется новое эксклюзивное имя выходного каталога. Текущий инструмент воспроизводит исправленный результат p/q, а не исторический n/o. Для независимого повтора выберите ещё одно новое имя; parent сравнил все три файла p/q побайтно.

## Конкретные результаты и отсутствия

- LLVM exception: полный текст отсутствует среди retained материалов для `wasip3 0.4.0+wasi-0.3.0-rc-2026-01-06`, `wasmparser 0.244.0`, `wit-component 0.244.0`, `wit-parser 0.244.0`; для всех manifest: `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`. Ссылка на reference TEXT с SHA-256 `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5` существует для других 12 компонентов и остаётся отдельной. Официальный родительский сайт, проверенный parent: https://llvm.org/; Developer Resources → Sources (GitHub): https://github.com/llvm/llvm-project/; policy: https://llvm.org/docs/DeveloperPolicy.html. Локально сохранённый capture `target/llvm-primary-20261030-c/LICENSE.TXT`: 15141 bytes, SHA-256 `8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee`, blob `fa6ac540007032cbd0ec772a1c72e6cb5527a4fe`, commit `e9996a2e210d021783d597d99ccd3199b0885d49`, metadata date `2026-10-30T09:04:11Z`; target pin/headers/contents/commit/provenance сохраняют детали. Parent независимо сверил wc/hash/git hash и прочитал все 279 строк.

  Существенные условия сохранённого текста: §2 copyright предоставляет права воспроизводить, создавать производные произведения, публично показывать/исполнять и сублицензировать исходный и объектный код; §3 предоставляет патентную лицензию только на claims, неизбежно нарушаемые вкладом Contributor отдельно или в сочетании с Work, и прекращает предоставленные для данного Work патентные лицензии с даты подачи иска против любого лица (включая cross-claim или counterclaim), утверждающего, что Work либо включённый в него Contribution составляет прямое или косвенное нарушение патента (85–91); это не прекращение всей лицензии. §4(a) требует передать получателям копию лицензии (98–99), (b) требует заметно отмечать изменения (101–102), (c) сохранять соответствующие notices в исходной форме производного произведения (104–108), (d) если исходный Work содержит NOTICE, требует читаемую копию относящихся attribution notices в NOTICE, сопроводительных исходниках/документации либо обычном месте показа notices (110–125). §6 товарные знаки (142–145); §§7–8 гарантия/ответственность (147–167); §9 поддержка от собственного имени и indemnity (169–178). Исключение (210–213) касается только случая, когда в результате компиляции YOUR source portions Software embedded в Object form YOUR source: отказ ограничен §§4(a), 4(b), 4(d), §4(c) не отменяется; это не общее исключение для linked binary. Условие GPLv2 (215–222) применимо только при combine/link и судебном конфликте с §3, §9 или иным разделом; отказ/исключение целого раздела допустимы лишь для Combined Software. Условия third-party (227–234) имеют отдельные лицензии; legacy (236–279) не означает универсального relicensing. Захват/цитирование текста лицензии не доказывает предоставление лицензии или её применимость к четырём crates, не устанавливает историческую комплектацию package и не выбирает OR-ветвь. Фиктивный blocker «LLVM URL not locally authorized» отозван.
- webpki-roots: сохранён supplemental CCADB snapshot capture и исторический текст в `target/ccadb-capture-20261030-b/`; точные pins, provenance, scope и ошибки предыдущего capture — ниже. Это supplement, не удаляет исходные два dataset blockers и не доказательство применимости к конкретному получению.
- r-efi: объявлен LGPL-2.1-or-later, полный текст отсутствует.
- dynasm/dynasmrt: объявлен MPL, файл `LICENSE` отсутствует.
- enum_dispatch/ident_case: полный MIT присутствует, объявленный текст Apache отсутствует.
- plotters×3 и objc2×2: ссылки вне crate.
- Верифицированные полные/смешанные чтения сохранены: разбиение XZ `COPYING`, ring BoringSSL/other-bits/once_cell, CDLA, Text-Template Artistic/GPL, sqlcipher, стандартные семейства MIT/Apache/BSD/MPL/GPL.

## Supplemental CCADB source capture (не изменяет ledger p/q)

Это отдельное supplemental evidence; в p/q остаются 2 blocker `external_ccadb_terms_not_saved` и всего число компонентов/записей не пересчитано. Известные до запросов размеры 3455, 3795 и 9 bytes, каждый менее 256 KiB. GitHub API repository identity: `mozilla/www.ccadb.org`, `https://github.com/mozilla/www.ccadb.org`; Contents API указывает `CNAME` blob `b3e1ca9565397ea6b38b0146c0927d6825ad2417`, raw `site-domain.raw` — 9 bytes, SHA-256 `86b0d6b8758ff0ea2f7ec6c072c5902860ddcb87f86a845c9f761cbd86174c43`, содержимое `ccadb.org`. Это repository/domain correspondence, но независимая официальная идентичность сайта и оператора **не подтверждена**.

| Snapshot | Commit и дата API | Blob | Raw file; bytes; SHA-256 |
| --- | --- | --- | --- |
| Исторический snapshot | `ed227276cd5b805ebd5ff4801bf17c7be08879e5`; 2024-02-05T18:59:53Z | `00c2471031374d39ce8513997a7c64ac86fb7f88` | `historical.raw`; 3795; `571ee086badc1fba7501838444f1cd22727d11e9d16b61d6706ea2919e4350f4` |
| Attribution/CDLA snapshot (не current master) | `499b8818c174030e979041842d1d4cfb5fcbda89`; 2025-02-03T20:55:16Z | `083d4c664ff6ce5e2a4e8bc36a4fed19462038d7` | `current.raw`; 3455; `d7cd416996cde7d455e9e8a611d34a73967d92b60365b7eae3be9cde8049320a` |

Оба содержимого получены через `gh api repos/mozilla/www.ccadb.org/git/blobs/<blob> -H 'Accept: application/vnd.github.raw+json'`; `current.http`/`historical.http` — ответы `gh api -i` с HTTP 200, датами 2026-10-30 08:46:20Z и 08:46:21Z, Content-Type text/plain; заголовка Content-Length нет. Для usage-текстов pins созданы до чтения, но для domain evidence порядок нарушен; точная последовательность приведена ниже. `provenance.md` содержит команды, размеры, hashes, response-header сведения и ограничения. README/отчёт не заменяют эти первичные captures.

В `current.raw` строки 5, 9–13: текст заявляет CDLA-Permissive 2.0; разрешает использование, изменение и redistribution при соблюдении CDLA; требует attribution CCADB при redistribution или use в derived works; запрещает endorsement/promotion именами/знаками без prior written permission; отсылает за полным текстом CDLA. Это наблюдение именно сохранённого snapshot, не доказательство условий исторического получения конкретных данных. Parent 2026-10-30 также прочитал совпадающий текст официальной страницы в преобразованном виде; это не raw capture и не устраняет разрыв применимости/исторического происхождения.
В `historical.raw` строки 5–21: redistribution/use разрешено при указанном ограничении endorsement/promotion; далее AS IS warranty/liability disclaimer. Исторический текст не является текущим snapshot. Commit dates — даты commit metadata, не доказательство публикации или условий конкретного получения данных.

**Точный локальный evidence** в pinned `target/materials-research-20261030-q/components.md` (2,462,522 bytes; SHA-256 `f56c80f8186fb3f4e33ce649ae0f9638292b3cfa3e00f9448969a803e64d07e7`), строки 648–649: оба компонента декларируют `CDLA-Permissive-2.0`; README каждого называет данные CCADB-derived; каждый имеет `external_ccadb_terms_not_saved`. Retained LICENSE span для обеих версий, SHA-256 `e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8`: §2.1 — при sharing Data сделать текст соглашения доступным вместе с Data; §3.1 — соглашение не налагает ограничения/обязательства на Results; §§5.1/5.4 определяют Data как material received under agreement, Results как outcome computational analysis. README `derived work` не решает классификацию Data/Results автоматически. В retained materials ledger остаются 2 blockers `external_ccadb_terms_not_saved`; supplemental capture их не меняет. Применимость, acquisition history, third-party rights, sufficiency/обязательства и legal approval остаются открыты.

Для двух usage-текстов отдельные current.pin/historical.pin записаны в сообщениях 110/112 до semantic views 116/118. Для site-domain.raw порядок нарушен: view106 до pin114. Поэтому каталог b целиком нельзя объявлять pin-before-read корректным; прежний provenance.md:14–19 содержит отозванное обобщение и сохранён без изменений как история.



История A: semantic views 65/67 предшествовали pins 79; поздние pins нарушение не исправляют. В новой LLVM-сессии 07be1fbd… вывод raw без pin был в сообщениях 25/26; последующий capture не исправляет это. Вызовы gh --jq без загрузки навыка и malformed вызовы сохранены как процедурные ошибки. Новый LLVM capture сначала ошибочно создан под docs/.../materials/llvm-primary-20261030-c, затем перемещён без перезаписи в target/llvm-primary-20261030-c; семь entries восстановлены. Точная история сохранена в target/llvm-primary-20261030-c/provenance.md:15–21.


Отказ на команду `curl -L --max-filesize 262144 -D - https://www.ccadb.org/rootstores/usage`: инструмент вернул `ERROR command is not allowed for security reasons` в сессии 07be1fbd… (сообщения 27/28). Обхода не было; текущий официальный raw остаётся отсутствующим.

## История

Родительский небезопасный инцидент сохранён; legacy-процедуры больше не запускались. Два чтения transcript без pin (сообщения 63 и 66) и чтение `components.md` без size/hash (transcript 340–341) остаются фактами. Дополнительно зафиксированы новые процедурные нарушения дочерних сессий: `643f705a…$$call_6fa515…` сообщения 54/60 — `python -c` и `json.load(open(...))` без `-I` и без предварительного pin; `643f705a…$$call_a70cc…` сообщение 47 — то же самое; `9b84faab…$$call_78eaef…` — `python - <<EOF` и повторные прямые чтения JSON при нормализации span. Более поздние pinned-выходы эти нарушения **не искупают**. Отказ `a` — списание бюджета; три отклонённых wrapper; ошибка кодировки консоли при чтении; лимит вывода `g` устранён дедупликацией без потерь; ложные NOTICE/branch counts `e` исправлены; прежнее заявление о «закрытых находках» отозвано. Pin до/после теперь применяется к новым разборам, но **не** исправляет прошлые нарушения задним числом.


## Границы

Только source distribution; состав binary, native linkage, происхождение production — вне работы. Семь vendor notices открыты. Альтернативы MPL/LGPL/CDLA/CCADB требуют human legal review. Allowlist/approval JSON нет. Юридическое одобрение отсутствует. #53 остаётся **PARTIAL**.

## Дальнейшие действия

1. Получить и оценить перечисленные выше конкретные отсутствующие внешние тексты и ссылки.
2. Направить прочитанные условия — особенно смешанные, native/data-specific и альтернативы — в human legal review.
3. Завершить vendor attribution (семь vendor).
4. Только после этого рассматривать закрытие конкретных пунктов.
