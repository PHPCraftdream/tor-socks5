#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stub `gh` для offline-тестов publish.sh.

Ставится harness'ом в начало PATH ПОД ИМЕНЕМ `gh`. Сети нет: состояние —
JSON-файл (env GH_MOCK_STATE), журнал вызовов — JSONL (env GH_MOCK_LOG),
каждая запись помечена mutation=true/false. Тесты ассертят ФАКТИЧЕСКИЕ
argv, число мутаций и типы полей (JSON boolean/number/string) по состоянию.

Поддержка (точные формы вызовов publish.sh):
  gh api --paginate --slurp repos/<repo>/releases?per_page=100
  gh api repos/<repo>/releases/tags/<TAG>
  gh api repos/<repo>/releases/<id>
  gh api --method PATCH repos/<repo>/releases/<id> --input -   (body в stdin)
  gh release create <TAG> --draft --verify-tag --repo <r> --title T --notes N
  gh release upload <TAG> <FILE> --clobber --repo <r>

Сценарий (состояние):
  releases            — список release-объектов (tag_name/draft/prerelease/id/assets)
  tags                — существующие на remote теги (для --verify-tag)
  next_id             — счётчик id при create
  releases_raw        — если задано, сырой вывод --paginate (bad API / list{})
  duplicate_tag       — true: два релиза с одним tag_name в списке
  wrong_types         — true: у релиза draft/prerelease/id неверных типов
  fail_upload         — имена ассетов, при upload которых ошибка сети
  patch_fail          — true: PATCH падает (сеть) БЕЗ применения — состояние
                        и latest-pointer не меняются
  asset_size_override — {имя: размер} — remote вернул неверный размер
  upload_state        — состояние ассетов после upload ('uploaded'|'pending')
  tags_get_fail       — GET releases/tags/<TAG> падает (сеть/API)
  get_by_id_fail      — GET releases/<id> падает
  corrupt_get_after_patch — true: после PATCH GET возвращает draft=true
                            (модель неуспешного readback)

Форматы как у реального CLI:
  --paginate --slurp — МАССИВ СТРАНИЦ (массив массивов release-объектов);
  id (релизов и ассетов) — числа; draft/prerelease — JSON boolean;
  state='uploaded', size — число. latest-pointer (state['latest_tag'])
  ведётся ОТДЕЛЬНО и меняется ТОЛЬКО после успешного PATCH: при failed
  create/upload/PATCH сохраняется прежний (или отсутствует).
"""

import json
import os
import sys


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save(path, state):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)


def main():
    state_path = os.environ["GH_MOCK_STATE"]
    log_path = os.environ["GH_MOCK_LOG"]
    argv = list(sys.argv[1:])
    state = load(state_path)

    def done(mutation, rc, out=""):
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"argv": argv, "mutation": mutation},
                               ensure_ascii=False) + "\n")
        if rc != 0:
            sys.stderr.write("gh stub: ошибка вызова\n")
        if out:
            sys.stdout.write(out if out.endswith("\n") else out + "\n")
        save(state_path, state)
        sys.exit(rc)

    def repo_of():
        # --repo owner/name — последняя форма в publish.sh
        if "--repo" in argv:
            return argv[argv.index("--repo") + 1]
        return None

    def find_by_tag(tag):
        return [r for r in state["releases"] if r.get("tag_name") == tag]

    if argv[:1] == ["api"]:
        rest = argv[1:]
        if rest[:2] == ["--paginate", "--slurp"]:
            endpoint = rest[2]
            assert endpoint.endswith("releases?per_page=100"), endpoint
            if "releases_raw" in state:
                done(False, 0, state["releases_raw"])
            rels = list(state["releases"])
            if state.get("wrong_types"):
                # один релиз с неверными типами полей (draft/prerelease/id)
                rels.append({"id": "x", "draft": "yes", "prerelease": 1,
                             "tag_name": state.get("probe_tag", "v1.2.3")})
            # как реальный CLI --paginate --slurp: МАССИВ СТРАНИЦ
            done(False, 0, json.dumps([rels]))
        endpoint = rest[-1] if rest and not rest[-1].startswith("-") else rest[0]
        parts = endpoint.strip("/").split("/")
        # repos/<owner>/<name>/releases/tags/<TAG>
        if "/releases/tags/" in endpoint:
            if state.get("tags_get_fail"):
                done(False, 1)
            tag = parts[-1]
            found = find_by_tag(tag)
            if len(found) != 1:
                done(False, 1)
            done(False, 0, json.dumps(found[0]))
        # repos/<owner>/<name>/releases/<id>
        if len(parts) >= 5 and parts[-2] == "releases" and parts[-1].isdigit():
            if state.get("get_by_id_fail"):
                done(False, 1)
            rid = int(parts[-1])
            found = [r for r in state["releases"] if r.get("id") == rid]
            if len(found) != 1:
                done(False, 1)
            obj = dict(found[0])
            if state.get("corrupt_get_after_patch") and state.get("patched"):
                obj["draft"] = True  # имитация устаревшего/сбойного readback
            done(False, 0, json.dumps(obj))
        # PATCH --method PATCH <endpoint> --input -
        if "--method" in rest and "PATCH" in rest:
            if "--input" not in rest:
                done(True, 2)
            body = sys.stdin.read()
            try:
                payload = json.loads(body)
            except ValueError:
                done(True, 2)
            ep = [a for a in rest if a.startswith("repos/")][0]
            rid = int(ep.rstrip("/").split("/")[-1])
            found = [r for r in state["releases"] if r.get("id") == rid]
            if len(found) != 1:
                done(True, 1)
            if state.get("patch_fail"):
                # сеть упала на PATCH: состояние и latest НЕ изменены
                done(True, 1)
            rel = found[0]
            # Применяем ТОЛЬКО типизированные поля: draft/prerelease — boolean,
            # make_latest — строка-enum (записывается в состояние для ассертов).
            rel["draft"] = bool(payload.get("draft"))
            rel["prerelease"] = bool(payload.get("prerelease"))
            state["make_latest"] = payload.get("make_latest")
            state["patch_body"] = payload
            state["patched"] = True
            # Prerelease не меняет прежний latest даже после успешного PATCH.
            if not rel["draft"] and not rel["prerelease"] and payload.get("make_latest") != "false":
                state["latest_tag"] = rel["tag_name"]
            done(True, 0, json.dumps(rel))
        done(False, 2)

    if argv[:2] == ["release", "create"]:
        tag = argv[2]
        assert "--verify-tag" in argv and "--draft" in argv, argv
        if tag not in state.get("tags", []):
            done(True, 1)  # --verify-tag: тега нет на remote
        rel = {"id": state.get("next_id", 100), "tag_name": tag,
               "draft": True, "prerelease": bool(state.get("create_prerelease", False)),
               "assets": []}
        state["next_id"] = rel["id"] + 1
        state["releases"].append(rel)
        done(True, 0, json.dumps("https://github.com/x/release/%d" % rel["id"]))

    if argv[:2] == ["release", "upload"]:
        tag = argv[2]
        src = argv[3]
        assert "--clobber" in argv, argv
        name = os.path.basename(src)
        if name in state.get("fail_upload", []):
            done(True, 1)  # сеть упала ДО изменения remote
        size = os.path.getsize(src)
        override = state.get("asset_size_override", {})
        if name in override:
            size = int(override[name])
        st = state.get("upload_state", "uploaded")
        found = find_by_tag(tag)
        assert len(found) == 1, tag
        assets = found[0].setdefault("assets", [])
        for a in assets:
            if a["name"] == name:
                a["size"] = size
                a["state"] = st
                break
        else:
            # numeric asset id + state + числовой размер, как в реальном API
            aid = state.get("next_asset_id", 500)
            state["next_asset_id"] = aid + 1
            assets.append({"id": aid, "name": name, "size": size,
                           "state": st})
        done(True, 0)

    done(False, 2)


if __name__ == "__main__":
    main()
