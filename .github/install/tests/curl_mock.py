#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stub `curl` для offline-тестов install.sh.

Ставится harness'ом (fixtures.make_fakebin) в начало PATH ПОД ИМЕНЕМ `curl`
(shebang переписывается на системный python3). Production install.sh не
меняется — он вызывает обычный curl.

Сценарий: JSON в env TORSOCKS_CURL_SCENARIO:
  owner/repo/tag        — репозиторий и тег latest (v9.8.7, не Cargo-тег)
  latest_final_url      — что вернуть в -w '%{url_effective}' для /releases/latest
  latest_exit           — код выхода для /releases/latest (сетевой сбой)
  files                 — {имя ассета: путь к файлу с байтами на диске}
  fail_download         — имя ассета, при скачивании которого выйти с ошибкой

Журнал: каждая строка TORSOCKS_CURL_LOG — JSON {argv, url, out, proto_ok}.
Тесты ассертят ФАКТИЧЕСКИЕ argv/URI/число запросов и флаги
--proto '=https' / --proto-redir '=https'.
"""

import json
import os
import sys


def main():
    scen_path = os.environ["TORSOCKS_CURL_SCENARIO"]
    log_path = os.environ["TORSOCKS_CURL_LOG"]
    argv = list(sys.argv[1:])
    with open(scen_path, "r", encoding="utf-8") as f:
        scen = json.load(f)

    rec = {"argv": argv}

    def proto_arg(flag):
        return argv[argv.index(flag) + 1] if flag in argv else None

    rec["proto_ok"] = (proto_arg("--proto") == "=https"
                       and proto_arg("--proto-redir") == "=https")

    out_path = None
    if "-o" in argv:
        out_path = argv[argv.index("-o") + 1]
    url = argv[-1]
    rec["url"] = url
    rec["out"] = out_path

    def append():
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    if not rec["proto_ok"] or not url.startswith("https://"):
        rec["error"] = "ожидается HTTPS и --proto/--proto-redir '=https'"
        append()
        sys.exit(6)

    latest = "https://github.com/%s/%s/releases/latest" % (scen["owner"], scen["repo"])
    if url == latest:
        append()
        if int(scen.get("latest_exit", 0)) != 0:
            sys.exit(int(scen["latest_exit"]))
        # curl -w печатает формат без перевода строки
        sys.stdout.write(scen["latest_final_url"])
        return

    dl = "https://github.com/%s/%s/releases/download/" % (scen["owner"], scen["repo"])
    if url.startswith(dl):
        rest = url[len(dl):]
        tag, name = rest.split("/", 1)
        if not out_path:
            rec["error"] = "нет -o для download URL"
            append()
            sys.exit(3)
        append()
        if scen.get("fail_download") == name:
            sys.exit(22)
        files = scen.get("files", {})
        if name not in files:
            sys.exit(22)
        with open(files[name], "rb") as f:
            data = f.read()
        with open(out_path, "wb") as f:
            f.write(data)
        return

    rec["error"] = "неожидаемый URL (не перехвачен сценарий)"
    append()
    sys.exit(3)


if __name__ == "__main__":
    main()
