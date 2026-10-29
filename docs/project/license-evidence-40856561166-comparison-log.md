# Журнал локального сравнения evidence 40856561166

Дата: 2026-10-29. Вход — `target/license-evidence-40856561166/evidence.zip`. Python 3.11+; из корня worktree:

```console
python -I docs/project/license-evidence-40856561166-compare.py target/license-evidence-40856561166/evidence.zip
```

Отдельный скрипт находится вне данных evidence, читает ZIP и выбранные gzip/tar-члены только в память, не извлекает их на диск и не исполняет код пакетов. Он требует уникальных записей ZIP, lock, manifest и выбранных tar-членов, проверяет идентичность name/version/source, checksum и непосредственное равенство байтов; при несовпадении завершается ошибкой. Пути `archives/` и `files/` ниже — члены ZIP; пути членов crate — внутри tar, не файлы worktree. Все отпечатки — SHA-256.

## Происхождение и ограничения

Родительский AI-оркестратор сообщил результаты внешней сверки `gh api` и `sha256sum`: SHA-256 ZIP `2d0c6fa6b16fe96610bd9f9b63b2387bc255ad5f86c6a735911233a3b835c7c4` совпал с digest GitHub API для run `40856561166`, head `a291bb26ddbaee733867bdc9041af32ef952fba6`. Это сообщение AI-оркестратора, отдельно от приведённого ниже локального расчёта работника. Работник не делал запросов к API; независимая проверка сообщения и происхождения ZIP не проводилась. Согласованность с вложенным lock не доказывает подлинность ZIP, использование этих байтов CI/релизом или полноту лицензионного комплекта. Остальные пакеты evidence не проверялись. Тесты, сборки, check, clippy и e2e не запускались.

## Входные отпечатки

- ZIP: `2d0c6fa6b16fe96610bd9f9b63b2387bc255ad5f86c6a735911233a3b835c7c4`
- `manifest.json`: `a7247591acf9260b3ffa7a942baf3026f69eaaa805336003efc8c526cc4741f8`
- Вложенный `Cargo.lock`: `44fec566e140a674ba45477f46ff616684d5e8ab5edcccc8d295a9e8ca975811`; равен `manifest.lock_sha256`.

## Архивы

Для каждой строки вычисленный SHA-256 байтов `archives/<пакет>.crate` равен checksum соответствующей уникальной записи вложенного lock и manifest. Имя, версия и source обеих записей совпадают; source для всех — `registry+https://github.com/rust-lang/crates.io-index`. В manifest указан соответствующий путь архива и status `candidates-found`.

| Пакет | SHA-256 архива = lock checksum = manifest checksum | Результат |
|---|---|---|
| colored-2.2.0 | `117725a109d387c937a1533ce01b450cbde6b88abceea8473c4d7a85853cda3c` | OK |
| option-ext-0.2.0 | `04744f49eae99ab78e0d5c0b603ab218f515ea8cfe5a456d7629ad883a3b6e7d` | OK |
| priority-queue-2.7.0 | `93980406f12d9f8140ed5abe7155acb10bb1e69ea55c88960b9c2f117445ef96` | OK |
| webpki-roots-0.26.11 | `521bc38abb08001b01866da9f51eb7c5d647a19260e00054a8c7fd5f9e57f7a9` | OK |
| webpki-roots-1.0.7 | `52f5ee44c96cf55f1b349600768e3ece3a8f26010c05265ab73f945bb1a2eb9d` | OK |
| xxhash-rust-0.8.18 | `aee1b19627c7c60102ab80d3a9cbe18de90bfe03bfa6c3715447681f0e8c8af6` | OK |
| async_executors-0.7.0 | `a982d2f86de6137cc05c9db9a915a19886c97911f9790d04f174cede74be01a5` | OK |
| notify-8.2.0 | `4d3d07927151ff8575b7087f245456e549fea62edf0ec4e565a5ee50c8402bc3` | OK |

## Лицензионные копии

Для каждой строки копия побайтно равна указанному регулярному члену crate; приведённый hash вычислен для копии и члена и равен `sha256` соответствующей записи manifest. Сверено ровно девять заявленных кандидатов этих восьми записей.

| Копия в ZIP | Член crate | SHA-256 копии = члена = manifest | Побайтно |
|---|---|---|---|
| `files/colored-2.2.0/000000` | `colored-2.2.0/LICENSE` | `fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85` | равно |
| `files/option-ext-0.2.0/000000` | `option-ext-0.2.0/LICENSE.txt` | `66a3107d5ad6a058aab753eaac2047ccb2ed0e39465dd0fe5844da3e300d5172` | равно |
| `files/priority-queue-2.7.0/000000` | `priority-queue-2.7.0/LGPL-3.0-or-later.txt` | `da7eabb7bafdf7d3ae5e9f223aa5bdc1eece45ac569dc21b3b037520b4464768` | равно |
| `files/priority-queue-2.7.0/000001` | `priority-queue-2.7.0/MPL-2.0.txt` | `c73cc0c27b0f24d5612e76bf83b5845c4fbd0374a1a8483f3d16befe58a60c9a` | равно |
| `files/webpki-roots-0.26.11/000000` | `webpki-roots-0.26.11/LICENSE` | `e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8` | равно |
| `files/webpki-roots-1.0.7/000000` | `webpki-roots-1.0.7/LICENSE` | `e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8` | равно |
| `files/xxhash-rust-0.8.18/000000` | `xxhash-rust-0.8.18/LICENSE` | `c9bff75738922193e67fa726fa225535870d2aa1059f91452c411736284ad566` | равно |
| `files/async_executors-0.7.0/000000` | `async_executors-0.7.0/LICENSE` | `88d9b4eb60579c191ec391ca04c16130572d7eedc4a86daa58bf28c6e14c9bcd` | равно |
| `files/notify-8.2.0/000000` | `notify-8.2.0/LICENSE-CC0` | `e0456cbab4f7b5e7203e678faff37eadbdfef02e822db3b7a52a1dd9d3dc514a` | равно |

Результат запуска: `RESULT: 8 archives and 9 license copies OK`.
