# Воспроизведение run 40934653900

Три соседних script-файла — полный toolkit: `analyze-safe.py`, `verify-safe-binaries.py`, `inspect-primary.py`. Считать этот каталог доверенным: два script явно загружают соседний `analyze-safe.py`, но не импортируют код проекта. Запускать Python в isolated mode `-I`; архивы и их содержимое не исполнять. Наблюдавшиеся сохранённые запуски всех трёх завершились с exit 0; финальный binary повтор после исправления формата Darwin показывает frameworks IOKit, CoreFoundation и SystemConfiguration, а не `Versions`. Результаты и ограничения — в [отчёте](../release-components-40934653900.md).

Финальные SHA-256 scripts:
- `analyze-safe.py`: `e02523826493e5816d644bf77d802917bb7773b5d01c158ccb06227af8f43a43`.
- `inspect-primary.py`: `f39b64ebe4c36f4d641c8c9d55c4c2f55a86cad555d08086fa6ca5351a151fa6`.
- `verify-safe-binaries.py`: `8241b9a49ec1d70843e1d344a125f4d821662da86b27e4b76ff27cd45cffeb0a`.

Все команды ниже выполняются из этого каталога в Bash (на Windows — Git Bash); пути содержат четыре `..`. Нужны доверенные Python 3.12 и `gh`, предварительная аутентификация `gh` и доступ к artifacts. Убедитесь, что `../../../../target` существует, не содержит ссылок/reparse points в цепочке и не изменяется конкурентно. Скрипты не защищают от гонок. Не перезаписывайте и не удаляйте прежние evidence или outputs.

## Аутентифицированное получение восьми ZIP

Если сохранённые входы доступны, можно использовать `../../../../target/stage1-data-20261029/candidate.zip` и этот каталог для binary ZIP только для чтения. Иначе создайте **новый пустой** каталог непосредственно внутри target; команда откажет, если имя занято:

```sh
python -I -c "import os; os.mkdir('../../../../target/repro-saved-inputs')"
```

Далее каждая четвёрка аргументов — artifact ID, выходное имя, ожидаемые размер и SHA-256. Python вызывает `gh api repos/PHPCraftdream/tor-socks5/actions/artifacts/ID/zip`, направляя бинарный stdout непосредственно в файл, открытый исключительно (`xb`), затем потоково проверяет размер и hash. Сетевые запросы выполняет только `gh`, Python не импортирует сетевой код. `exec` в примере исполняет только явно приведённый доверенный литерал программы, никогда не содержимое artifact. При ошибке или несовпадении остановиться и сохранить неполный файл как evidence; для повтора выбрать новый каталог, не перезаписывать его. Сверяйте metadata с аутентифицированным API; проверка bytes не устанавливает production origin.

```sh
python -I -c "import sys,subprocess,hashlib,os; a=sys.argv[1:]; assert len(a)%4==0; exec('for i in range(0,len(a),4):\n id,p,n,w=a[i:i+4]\n with open(p,\"xb\") as f: subprocess.run([\"gh\",\"api\",\"repos/PHPCraftdream/tor-socks5/actions/artifacts/\"+id+\"/zip\"],stdout=f,check=True)\n h=hashlib.sha256()\n with open(p,\"rb\") as f:\n  for b in iter(lambda:f.read(1048576),b\"\"): h.update(b)\n if os.path.getsize(p)!=int(n) or h.hexdigest()!=w: raise ValueError(\"size/hash mismatch: \"+p)\n print(id,\"verified\")')" 12932028389 ../../../../target/repro-saved-inputs/candidate.zip 853866809 75a58bb9393525b64f083105113771680bb561e1ff2f28f337fa584954b847d4 12931773573 ../../../../target/repro-saved-inputs/binary-12931773573.zip 12126824 bcf0edb870c0dfeb1ec71bf6262328885226ae489ddd81a6493277bde63b78f8 12930598391 ../../../../target/repro-saved-inputs/binary-12930598391.zip 12678740 351d145d890ee0d8a7de555af7a2e176c693c5a621636ba0a669e571cb7af8fd 12929435820 ../../../../target/repro-saved-inputs/binary-12929435820.zip 12747241 807a36536fc8c7558829dc3c1ba89a6f22579307c6a3a8e0e0d34cf76531b393 12927756356 ../../../../target/repro-saved-inputs/binary-12927756356.zip 12982288 46861aea32f692039d5d5ce4286265a15c1adcf3244e2e8b4de0a8c78bbc9025 12926432069 ../../../../target/repro-saved-inputs/binary-12926432069.zip 13007952 8d6909f2f42b902bdced58f91cd1a96559da5a0ed08b31f1835e88657d35803c 12925166590 ../../../../target/repro-saved-inputs/binary-12925166590.zip 13223590 fd759bd0516de84edb2b3599fc3389d8240947fa228d10a27913ad4bc6506d87 12924449353 ../../../../target/repro-saved-inputs/binary-12924449353.zip 13473713 bc92c80fa638e9ef5f1fe77b6f7dfcadc8f2b16ec5bc4a6e2777685cda2f4c44
```

Соответствие ID целям и ссылки на artifact API приведены в таблице отчёта; retained artifact не скачивается.

## Наблюдавшиеся запуски

Ниже точные аргументы и занятые outputs наблюдавшихся запусков, приведённые для протокола; **не запускать повторно с этими именами**:

```sh
python -I analyze-safe.py --candidate ../../../../target/stage1-data-20261029/candidate.zip --target-root ../../../../target --output ../../../../target/repro-saved-inventory-20261029-d
python -I verify-safe-binaries.py --candidate ../../../../target/stage1-data-20261029/candidate.zip --binary-dir ../../../../target/stage1-data-20261029 --target-root ../../../../target --output ../../../../target/repro-saved-binaries-20261029-c
python -I inspect-primary.py --candidate ../../../../target/stage1-data-20261029/candidate.zip --target-root ../../../../target --output ../../../../target/repro-saved-primary-20261029-c
```

Все exit 0: `inventory.json` — 824 outer, 2642 nested, 736 компонентов, 743 blockers; `primary.json` — 13 crates, 12 project/SDK файлов-кандидатов по имени (6 `LICENSE-*` и 6 workflow/аналитических файлов, не первичные лицензии), 10 строк CCADB; `summary.json` — семь совпадений receipt, все true, graph counts как в отчёте.

Поле `project_sdk_license_files` имеет историческое имя: это результаты широкого filename-фильтра, а не классификация первичных лицензионных текстов. Наличие в этом списке workflow, аналитического документа или скрипта не подтверждает лицензионное обязательство и не увеличивает число проверенных первичных лицензий.

## Ограниченный анализ: свежие outputs

Примеры используют старые входы только для чтения; для новых замените оба входных пути на `repro-saved-inputs`. Каждый output должен быть новым каталогом под target; в примерах он непосредственно дочерний; скрипты создают его эксклюзивно, отказывают при существующем имени или ссылке/reparse point в проверяемой цепочке. При повторе выберите другие несуществующие имена, включая после ошибки; outputs сохраняются.

```sh
python -I analyze-safe.py --candidate ../../../../target/stage1-data-20261029/candidate.zip --target-root ../../../../target --output ../../../../target/repro-saved-inventory
python -I verify-safe-binaries.py --candidate ../../../../target/stage1-data-20261029/candidate.zip --binary-dir ../../../../target/stage1-data-20261029 --target-root ../../../../target --output ../../../../target/repro-saved-binaries
python -I inspect-primary.py --candidate ../../../../target/stage1-data-20261029/candidate.zip --target-root ../../../../target --output ../../../../target/repro-saved-primary
```

Проверяются закреплённые размеры и hashes, имена и типы членов и бюджеты потоков. Ручной разбор TAR проверяет checksum заголовка, тип и padding; JSON ограничивается глубиной 64 до `json.loads`. Лимит выбранных данных — 150 МБ суммарно; около 600 МБ пик памяти ориентировочно, не жёсткий RSS-лимит. Данные не извлекаются и не исполняются; это не универсальный архивный валидатор, полный legal review или подтверждение состава и production authority.

Первый новый analyzer отказал на виртуальном PAX-маркере `././@PaxHeader`; новые primary запуски a/b отказали на GNU longname `L` размером 102 в OpenSSL. Поддержан только точный PAX metadata-маркер; GNU `L` ограничен 513 байтами, одним завершающим NUL и проверкой пути. `K`, ссылки и sparse отклоняются; общие проверки типов и путей не ослаблены. Неудачные outputs a/b сохранены как evidence. Историю первоначальной небезопасной обработки см. в отчёте; legacy scripts больше не запускать.
