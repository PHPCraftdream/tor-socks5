# -*- coding: utf-8 -*-
"""Offline-тесты НАСТОЯЩИХ release-хелперов (.github/release/validate-tag.sh,
publish.sh) как дочерних процессов + узкая проверка wiring'а release.yml.

`gh` подменяется stub'ом (gh_mock.py) в начале PATH: состояние — JSON-файл,
журнал вызовов — JSONL с меткой mutation. jq/sha256sum/stat/cmp — РЕАЛЬНЫЕ
инструменты Ubuntu. GH_TOKEN — фиктивный, REMOTE_REPO — fixture owner/name.
Запуск: python3 -I .github/install/tests/test_release.py   (только Ubuntu)
"""

import json
import os
import shutil
import stat
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixtures as fx

REMOTE_REPO = "octo-cat/tor-socks5"
TAG = "v1.2.3"
UNIX_TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl",
                "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
                "x86_64-apple-darwin", "aarch64-apple-darwin")
WIN_TARGETS = ("x86_64-pc-windows-msvc",)
GH = shutil.which("gh")  # настоящий gh не нужен: stub добавляется в PATH


def expected_names(tag):
    names = []
    for t in UNIX_TARGETS:
        names += ["tor-socks5-%s-%s.tar.gz" % (tag, t),
                  "tor-socks5-%s-%s.tar.gz.sha256" % (tag, t)]
    for t in WIN_TARGETS:
        names += ["tor-socks5-%s-%s.zip" % (tag, t),
                  "tor-socks5-%s-%s.zip.sha256" % (tag, t)]
    return names


def read_state(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def read_log(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8-sig") as f:
        return [json.loads(line) for line in f if line.strip()]


def mutations(log):
    return [r for r in log if r["mutation"]]


def call_kinds(log):
    """Фактическая последовательность вызовов gh по журналу: read-list /
    create / get-by-tag / get-by-id / upload / patch — чтобы ассертился
    ПОРЯДОК producer-consumer пар, а не только число мутаций."""
    kinds = []
    for r in log:
        a = r["argv"]
        if a[:2] == ["release", "create"]:
            kinds.append("create")
        elif a[:2] == ["release", "upload"]:
            kinds.append("upload")
        elif a[:1] == ["api"]:
            if a[1:3] == ["--paginate", "--slurp"]:
                kinds.append("list")
            elif "--method" in a:
                kinds.append("patch")
            else:
                endpoints = [x for x in a if isinstance(x, str)
                             and x.startswith("repos/")]
                ep = endpoints[-1] if endpoints else ""
                if "/releases/tags/" in ep:
                    kinds.append("get-by-tag")
                else:
                    kinds.append("get-by-id")
    return kinds


def has_call(log, substr):
    return any(any(substr in x for x in r["argv"] if isinstance(x, str))
               for r in log)


class ValidateTagTests(unittest.TestCase):
    def setUp(self):
        self.area = fx.TempArea(self)

    def run_vt(self, argv=(), env_tag=None):
        env = dict(os.environ)
        env.pop("TAG", None)
        if env_tag is not None:
            env["TAG"] = env_tag
        return fx.run_cmd(["bash", fx.VALIDATE_TAG_SH] + list(argv), env=env)

    def test_valid_tags_exact_stdout(self):
        cases = [("v0.0.0", "false"), ("v0.3.10", "false"),
                 ("v10.20.300", "false"), ("v1.2.3-rc.1", "true"),
                 ("v1.2.3-0", "true"), ("v1.2.3-10", "true")]
        for tag, pre in cases:
            with self.subTest(tag=tag):
                p = self.run_vt([tag])
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout.decode(), "tag=%s\nprerelease=%s\n"
                                 % (tag, pre))

    def test_env_tag_fallback(self):
        p = self.run_vt(env_tag="v0.3.10")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout.decode(), "tag=v0.3.10\nprerelease=false\n")

    def test_invalid_tags(self):
        bad = ["0.1.2", "v0.3", "v0.3.0.1", "v01.2.3", "v1.02.3", "v1.2.03",
               "v1.2.3+build", "v1.2.3-.rc", "v1.2.3-rc.", "v1.2.3-rc..1",
               "v1.2.3-01", "v1.2.3\n", 'v1.2.3"x', "v1.2.3 rc", ""]
        for tag in bad:
            with self.subTest(tag=repr(tag)):
                p = self.run_vt([tag])
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(p.stdout, b"")
        # без argv и без TAG; пустой argv при заданном TAG (fallback запрещён)
        p = self.run_vt()
        self.assertNotEqual(p.returncode, 0)
        p = self.run_vt([""], env_tag="v1.2.3")
        self.assertNotEqual(p.returncode, 0)
        p = self.run_vt(env_tag="")
        self.assertNotEqual(p.returncode, 0)


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.area = fx.TempArea(self)
        bin_dir = self.area.subdir("bin")
        fx.write_executable(bin_dir, "gh", "\n" + fx._stub_source("gh_mock.py"))
        self.bin_dir = bin_dir

    # --- helpers -------------------------------------------------------

    def gh_state(self, **kw):
        state = {"releases": kw.pop("releases", []),
                 "tags": kw.pop("tags", [TAG]), "next_id": kw.pop("next_id", 100),
                 # модель latest: в начальном состоянии УЖЕ есть прежний
                 # stable тег; меняться он может только успешным stable PATCH
                 "latest_tag": kw.pop("latest_tag", "v0.9.0")}
        state.update(kw)
        path = os.path.join(self.area.path, "gh-state.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f)
        return path

    def make_artifacts(self, tag, content_prefix=b"archive-marker"):
        """Ровно 14 файлов (7 архивов + 7 checksums); точный комплект без двойных checksum."""
        d = self.area.subdir("artifacts")
        archives = [n for n in expected_names(tag) if not n.endswith(".sha256")]
        self.assertEqual(len(archives), 7)
        for name in archives:
            data = content_prefix + b":" + name.encode("ascii") + b"\n"
            p = os.path.join(d, name)
            with open(p, "wb") as f:
                f.write(data)
            h = fx.sha256_hex(fx.file_bytes(p))
            sep, eol = (" *", "") if name.endswith(".zip") else ("  ", "\n")
            with open(p + ".sha256", "wb") as f:
                f.write(fx.checksum_text(h, name, sep=sep, eol=eol).encode("ascii"))
        # точный комплект: никакие .sha256.sha256 / лишние имена не плодятся
        self.assertEqual(sorted(os.listdir(d)), sorted(expected_names(tag)))
        return d

    def run_publish(self, state_path, tag=TAG, prerelease="false",
                    artifacts_dir=None):
        env = dict(os.environ)
        env["PATH"] = self.bin_dir + os.pathsep + env["PATH"]
        env["GH_MOCK_STATE"] = state_path
        env["GH_MOCK_LOG"] = os.path.join(self.area.path, "gh-log.jsonl")
        env["TAG"] = tag
        env["PRERELEASE"] = prerelease
        env["ARTIFACTS_DIR"] = artifacts_dir or os.path.join(self.area.path,
                                                             "artifacts")
        env["REMOTE_REPO"] = REMOTE_REPO
        env["GH_TOKEN"] = "dummy-token-for-offline-tests"
        log_path = os.path.join(self.area.path, "gh-log.jsonl")
        if os.path.exists(log_path):
            os.remove(log_path)  # каждый запуск пишет свежий журнал
        return fx.run_cmd(["bash", fx.PUBLISH_SH], env=env, cwd=fx.REPO_ROOT)

    def assets_of(self, state, tag=TAG):
        for r in state["releases"]:
            if r["tag_name"] == tag:
                return r
        return None

    # --- сценарии публикации ---------------------------------------------

    def test_absent_create_upload_publish(self):
        d = self.make_artifacts(TAG)
        sp = self.gh_state()
        p = self.run_publish(sp)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        self.assertIn("Готово", p.stdout.decode())
        state = read_state(sp)
        rel = self.assets_of(state)
        self.assertIsNotNone(rel)
        self.assertFalse(rel["draft"])
        names = sorted(a["name"] for a in rel["assets"])
        self.assertEqual(names, sorted(expected_names(TAG)))
        for a in rel["assets"]:
            self.assertEqual(a["state"], "uploaded")
            self.assertEqual(a["size"],
                             os.path.getsize(os.path.join(d, a["name"])))
        # PATCH: типизированные поля, make_latest — STRING 'legacy'
        self.assertEqual(state["patch_body"],
                         {"draft": False, "prerelease": False,
                          "make_latest": "legacy"})
        self.assertEqual(state["make_latest"], "legacy")
        # latest-pointer сдвинут ТОЛЬКО успешным PATCH
        self.assertEqual(state["latest_tag"], TAG)
        # точные имена с ТОЧКОЙ перед расширением, без старой опечатки
        self.assertIn("tor-socks5-%s-%s.tar.gz.sha256" % (TAG, UNIX_TARGETS[0]),
                      names)
        self.assertFalse(any("-target-" in n for n in names))
        muts = mutations(read_log(
            os.path.join(self.area.path, "gh-log.jsonl")))
        # 1 create + 14 uploads + 1 PATCH; GET/readback — read-only
        self.assertEqual(len(muts), 16)
        create = muts[0]["argv"]
        self.assertIn("--draft", create)
        self.assertIn("--verify-tag", create)
        # ФАКТИЧЕСКАЯ последовательность вызовов: read-list → create →
        # GET by tag → fresh GET → 14 uploads → GET verify → PATCH →
        # GET readback
        self.assertEqual(call_kinds(read_log(
            os.path.join(self.area.path, "gh-log.jsonl"))),
            ["list", "create", "get-by-tag", "get-by-id"]
            + ["upload"] * 14 + ["get-by-id", "patch", "get-by-id"])

    def test_draft_resume(self):
        d = self.make_artifacts(TAG)
        sp = self.gh_state(releases=[{"id": 7, "tag_name": TAG, "draft": True,
                                      "prerelease": False,
                                      "assets": [{"name": expected_names(TAG)[0],
                                                  "size": 1,
                                                  "state": "uploaded"}]}])
        p = self.run_publish(sp)
        self.assertEqual(p.returncode, 0, p.stderr)
        state = read_state(sp)
        rel = self.assets_of(state)
        self.assertFalse(rel["draft"])
        self.assertEqual(len(rel["assets"]), 14)
        log = read_log(os.path.join(self.area.path, "gh-log.jsonl"))
        muts = mutations(log)
        self.assertNotIn("create", muts[0]["argv"])
        # resume: без create, остальные фазы в том же порядке
        self.assertEqual(call_kinds(log),
                         ["list", "get-by-tag", "get-by-id"]
                         + ["upload"] * 14 + ["get-by-id", "patch", "get-by-id"])
        # успешный stable PATCH сдвинул legacy latest на наш тег
        self.assertEqual(read_state(sp)["latest_tag"], TAG)

    def test_published_noop_zero_mutations(self):
        d = self.make_artifacts(TAG)
        # remote PUBLISHED, но размеры ДРУГИЕ (локальный rebuild) + extra asset
        assets = [{"name": n, "size": os.path.getsize(os.path.join(d, n)) + 5,
                   "state": "uploaded"} for n in expected_names(TAG)]
        assets.append({"name": "user-notes.txt", "size": 3, "state": "uploaded"})
        sp = self.gh_state(releases=[{"id": 5, "tag_name": TAG, "draft": False,
                                      "prerelease": False, "assets": assets}])
        p = self.run_publish(sp)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("no-op", p.stdout.decode())
        self.assertEqual(mutations(read_log(
            os.path.join(self.area.path, "gh-log.jsonl"))), [])
        # extra user-asset не тронут
        self.assertTrue(any(a["name"] == "user-notes.txt"
                            for a in read_state(sp)["releases"][0]["assets"]))

    def test_legacy_published_release_is_immutable_and_rejected(self):
        self.make_artifacts(TAG)
        legacy_targets = ("x86_64-unknown-linux-gnu", "x86_64-apple-darwin",
                          "aarch64-apple-darwin", *WIN_TARGETS)
        legacy_names = []
        for target in legacy_targets:
            ext = "zip" if target in WIN_TARGETS else "tar.gz"
            name = "tor-socks5-%s-%s.%s" % (TAG, target, ext)
            legacy_names.extend((name, name + ".sha256"))
        assets = [{"name": n, "size": 10, "state": "uploaded"}
                  for n in legacy_names]
        sp = self.gh_state(releases=[{"id": 5, "tag_name": TAG,
                                      "draft": False, "prerelease": False,
                                      "assets": assets}])
        p = self.run_publish(sp)
        self.assertNotEqual(p.returncode, 0, p.stdout.decode())
        self.assertEqual(mutations(read_log(os.path.join(self.area.path,
                                                        "gh-log.jsonl"))), [])

    def test_legacy_published_partial_fails_immutable(self):
        self.make_artifacts(TAG)
        old_names = expected_names(TAG)[:8]
        assets = [{"name": n, "size": 10, "state": "uploaded"}
                  for n in old_names]
        sp = self.gh_state(releases=[{"id": 5, "tag_name": TAG,
                                      "draft": False, "prerelease": False,
                                      "assets": assets}])
        p = self.run_publish(sp)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(mutations(read_log(os.path.join(self.area.path,
                                                        "gh-log.jsonl"))), [])

    def test_prerelease_patch_typed(self):
        self.make_artifacts("v2.0.0-rc.1")
        sp = self.gh_state(tags=["v2.0.0-rc.1"], create_prerelease=True)
        p = self.run_publish(sp, tag="v2.0.0-rc.1", prerelease="true")
        self.assertEqual(p.returncode, 0, p.stderr)
        state = read_state(sp)
        # JSON boolean true + make_latest СТРОКОЙ 'false'
        self.assertIs(state["patch_body"]["prerelease"], True)
        self.assertIs(state["patch_body"]["draft"], False)
        self.assertEqual(state["patch_body"]["make_latest"], "false")
        # публикация prerelease НЕ меняет legacy latest
        self.assertEqual(state["latest_tag"], "v0.9.0")

    # --- плохие локальные артефакты: fail с НУЛЁМ gh-вызовов --------------

    def test_bad_local_artifacts_zero_gh_calls(self):
        tag = TAG
        d = self.make_artifacts(tag)
        names = expected_names(tag)

        def variant(name):
            v = self.area.subdir(name)
            shutil.copytree(d, v, dirs_exist_ok=True)
            return v

        def positive(label):
            # позитивный контроль группы: тот же harness с чистой копией
            # проходит ДО сети (маскировка одной поломкой другой исключена
            # отдельными каталогами ниже)
            sp0 = self.gh_state()
            self.assertEqual(
                self.run_publish(sp0, artifacts_dir=variant(label)).returncode,
                0)

        positive("clean-pre-symlink")
        variants = {}
        # missing / empty — отдельные сценарии
        v = variant("v-missing")
        os.remove(os.path.join(v, names[3]))
        variants["missing"] = v
        v = variant("v-empty")
        open(os.path.join(v, names[0]), "wb").close()
        variants["empty"] = v
        # symlink на валидный файл — отдельный сценарий
        v = variant("v-symlink")
        target = os.path.join(v, names[1])
        os.remove(target)                    # unlink ПЕРЕД созданием symlink
        os.symlink(os.path.join(d, names[1]), target)
        variants["symlink"] = v
        # dangling symlink под НОВЫМ именем — отдельный сценарий
        v = variant("v-dangling")
        dangling = os.path.join(v, "dangling-extra-file")
        if os.path.lexists(dangling):
            os.remove(dangling)
        os.symlink("nowhere", dangling)      # не поверх required-файла
        variants["dangling"] = v

        positive("clean-pre-extra")
        # hidden / extra / subdir — ОТДЕЛЬНЫЕ сценарии
        v = variant("v-hidden")
        open(os.path.join(v, ".hidden"), "wb").write(b"x")
        variants["hidden"] = v
        v = variant("v-extra")
        open(os.path.join(v, "extra.txt"), "wb").write(b"x")
        variants["extra"] = v
        v = variant("v-subdir")
        os.makedirs(os.path.join(v, "subdir"))
        variants["subdir"] = v
        # bad sha / bad format / постороннее имя в checksum
        v = variant("v-bad-sha")
        with open(os.path.join(v, names[0] + ".sha256"), "wb") as f:
            f.write(b"0" * 64 + b"  " + names[0].encode() + b"\n")
        variants["bad-sha"] = v
        v = variant("v-bad-format")
        with open(os.path.join(v, names[4] + ".sha256"), "wb") as f:
            f.write(b"zz" + names[4].encode())
        variants["bad-format"] = v
        v = variant("v-foreign-name")
        with open(os.path.join(v, names[0] + ".sha256"), "wb") as f:
            f.write(fx.checksum_text(fx.sha256_hex(fx.file_bytes(
                os.path.join(d, names[0]))), "someone-else.tar.gz").encode())
        variants["foreign-name"] = v

        for label, art in variants.items():
            with self.subTest(case=label):
                sp = self.gh_state()
                p = self.run_publish(sp, artifacts_dir=art)
                self.assertNotEqual(p.returncode, 0)
                # НОЛЬ gh-вызовов
                self.assertEqual(read_log(
                    os.path.join(self.area.path, "gh-log.jsonl")), [])

    # --- bad API / структура ----------------------------------------------

    def test_bad_api_states_fail_without_mutation(self):
        self.make_artifacts(TAG)
        # positive control: тот же harness без «поломки» публикует успешно
        sp_ok = self.gh_state()
        self.assertEqual(self.run_publish(sp_ok).returncode, 0)
        variants = [
            {"releases_raw": json.dumps({"a": 1})},              # не array
            {"releases_raw": json.dumps([{"tag_name": TAG}])},   # неверные типы
            {"wrong_types": True, "probe_tag": TAG},
            # duplicate tag
            {"releases": [{"id": 1, "tag_name": TAG, "draft": True,
                           "prerelease": False, "assets": []},
                          {"id": 2, "tag_name": TAG, "draft": False,
                           "prerelease": False, "assets": []}]},
        ]
        for i, kw in enumerate(variants):
            with self.subTest(variant=i):
                sp = self.gh_state(**kw)
                p = self.run_publish(sp)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(mutations(read_log(os.path.join(
                    self.area.path, "gh-log.jsonl"))), [])

    # --- published, но некомплект: fail без перезаписи ----------------------

    def test_published_incomplete_or_class_mismatch(self):
        d = self.make_artifacts(TAG)
        full = [{"name": n, "size": os.path.getsize(os.path.join(d, n)),
                 "state": "uploaded"} for n in expected_names(TAG)]
        missing = full[:-1]
        pending = [dict(full[0], state="pending")] + full[1:]
        # класс релиза не совпадает с PRERELEASE=false — ЦЕЛЫЙ release-объект
        # реалистичной схемы (typed-поля), не keys-словарь
        wrong_class = {"id": 9, "tag_name": TAG, "draft": False,
                       "prerelease": True, "assets": full}
        for label, rel in (("missing", {"id": 9, "tag_name": TAG,
                                        "draft": False, "prerelease": False,
                                        "assets": missing}),
                           ("state-wrong", {"id": 9, "tag_name": TAG,
                                            "draft": False,
                                            "prerelease": False,
                                            "assets": pending}),
                           ("class-wrong", wrong_class)):
            with self.subTest(case=label):
                sp = self.gh_state(releases=[rel])
                p = self.run_publish(sp)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(mutations(read_log(os.path.join(
                    self.area.path, "gh-log.jsonl"))), [])

    # --- draft-ветка: отказы ДО/ВОКРУГ upload --------------------------------

    def test_draft_gget_fail_zero_upload(self):
        self.make_artifacts(TAG)
        sp = self.gh_state(releases=[{"id": 7, "tag_name": TAG, "draft": True,
                                      "prerelease": False, "assets": []}],
                           tags_get_fail=True)
        p = self.run_publish(sp)
        self.assertNotEqual(p.returncode, 0)
        log = read_log(os.path.join(self.area.path, "gh-log.jsonl"))
        self.assertFalse(any("upload" in r["argv"] for r in log))

    def test_failed_upload_no_patch(self):
        d = self.make_artifacts(TAG)
        # отдельные подслучаи: сбой на archive И сбой на его .sha256
        for label, asset in (("archive", expected_names(TAG)[0]),
                             ("checksum", expected_names(TAG)[1])):
            with self.subTest(case=label):
                sp = self.gh_state(releases=[{"id": 7, "tag_name": TAG,
                                              "draft": True,
                                              "prerelease": False,
                                              "assets": []}],
                                   fail_upload=[asset])
                p = self.run_publish(sp)
                self.assertNotEqual(p.returncode, 0)
                state = read_state(sp)
                self.assertTrue(self.assets_of(state)["draft"])
                self.assertNotIn("patched", state)
                # latest-pointer не тронут failed upload'ом
                self.assertEqual(state["latest_tag"], "v0.9.0")

    def test_remote_wrong_size_and_pending_no_patch(self):
        d = self.make_artifacts(TAG)
        for label, kw in (
                ("wrong-size", {"asset_size_override":
                                {expected_names(TAG)[0]: 12345}}),
                # неверный размер У CHECKSUM-ассета тоже ловится
                ("wrong-size-checksum", {"asset_size_override":
                                {expected_names(TAG)[1]: 999}}),
                ("pending", {"upload_state": "pending"})):
            with self.subTest(case=label):
                sp = self.gh_state(releases=[{"id": 7, "tag_name": TAG,
                                              "draft": True,
                                              "prerelease": False,
                                              "assets": []}], **kw)
                p = self.run_publish(sp)
                self.assertNotEqual(p.returncode, 0)
                state = read_state(sp)
                self.assertTrue(self.assets_of(state)["draft"])
                self.assertNotIn("patched", state)
                self.assertEqual(state["latest_tag"], "v0.9.0")

    def test_fresh_get_variants_fail_before_upload(self):
        # Свежий GET releases/<id> ПЕРЕД upload с управляемым ПОЛНЫМ объектом:
        # typed-предикат publish.sh обязан отвергнуть каждый вариант ДО
        # единой загрузки и PATCH (get_by_id_fail — только сетевая ошибка,
        # здесь проверяется СОДЕРЖИМОЕ ответа).
        self.make_artifacts(TAG)
        base = {"id": 7, "tag_name": TAG, "draft": True,
                "prerelease": False}
        variants = {
            # релиз УЖЕ published (гонка): draft=false => отказ
            "already-published": dict(base, draft=False),
            # неверный id в ответе
            "wrong-id": dict(base, id=8),
            # неверный tag в ответе
            "wrong-tag": dict(base, tag_name="v0.0.1"),
            # draft строкой вместо boolean
            "draft-string": dict(base, draft="yes"),
            # prerelease числом вместо boolean
            "prerelease-number": dict(base, prerelease=1),
            # prerelease строкой вместо boolean
            "prerelease-string": dict(base, prerelease="false"),
        }
        for label, obj in variants.items():
            with self.subTest(case=label):
                sp = self.gh_state(releases=[dict(base, assets=[])],
                                   fresh_get_obj=dict(obj, assets=[]))
                p = self.run_publish(sp)
                self.assertNotEqual(p.returncode, 0)
                log = read_log(os.path.join(self.area.path, "gh-log.jsonl"))
                # fresh GET ДОСТИГНУТ (виден в журнале как releases/7)
                self.assertTrue(has_call(log, "releases/7"))
                # НЕТ upload и НЕТ PATCH
                self.assertFalse(any("upload" in r["argv"] for r in log))
                self.assertFalse(any("--method" in r["argv"] for r in log))
                state = read_state(sp)
                self.assertTrue(self.assets_of(state)["draft"])
                self.assertEqual(state["latest_tag"], "v0.9.0")

    def test_typed_readback_rejects_invalid_fields(self):
        # ПОЛНЫЙ управляемый объект readback (readback_obj) ПОСЛЕ успешного
        # PATCH: baseline — fully valid published release; каждый вариант
        # ломает ровно одно typed-поле, и typed-предикат publish.sh обязан
        # отвергнуть его БЕЗ 'Готово'. Ассеты в readback обязаны быть полными
        # и валидными (числовой id, реальный размер, state uploaded), иначе
        # негатив упадёт на missing-assets, а не на typed-предикат.
        d = self.make_artifacts(TAG)
        good_assets = [{"id": 500 + i, "name": n,
                        "size": os.path.getsize(os.path.join(d, n)),
                        "state": "uploaded"}
                       for i, n in enumerate(expected_names(TAG))]
        baseline = {"id": 7, "tag_name": TAG, "draft": False,
                    "prerelease": False, "assets": good_assets}
        variants = {
            "draft-string-false": dict(baseline, draft="false"),
            "prerelease-string-false": dict(baseline, prerelease="false"),
            "wrong-id": dict(baseline, id=8),
            "string-id": dict(baseline, id="7"),
            "wrong-tag": dict(baseline, tag_name="v0.0.1"),
        }
        for label, obj in variants.items():
            with self.subTest(case=label):
                sp = self.gh_state(releases=[{"id": 7, "tag_name": TAG,
                                              "draft": True,
                                              "prerelease": False,
                                              "assets": []}],
                                   readback_obj=obj)
                p = self.run_publish(sp)
                self.assertNotEqual(p.returncode, 0)
                self.assertNotIn("Готово", p.stdout.decode())
                log = read_log(os.path.join(self.area.path, "gh-log.jsonl"))
                # resume-путь draft-релиза: точная последовательность с 14
                # uploads, PATCH и финальным readback GET
                self.assertEqual(call_kinds(log),
                                 ["list", "get-by-tag", "get-by-id"]
                                 + ["upload"] * 14
                                 + ["get-by-id", "patch", "get-by-id"])
                state = read_state(sp)
                self.assertTrue(state["patched"])
                # PATCH-тело — настоящие JSON boolean + legacy
                self.assertEqual(state["patch_body"],
                                 {"draft": False, "prerelease": False,
                                  "make_latest": "legacy"})

    def test_missing_remote_tag_create_failure_preserves_latest(self):
        # --verify-tag: тега нет на remote — create отказывает. Проверяется
        # ИМЕННО create (он вызван и свернулся), а не «ноль мутационных
        # попыток»: mutation=True для попытки create ожидаемо. Никаких
        # upload/PATCH, releases и latest-pointer не изменены.
        self.make_artifacts(TAG)
        sp = self.gh_state(tags=[], releases=[], latest_tag="v0.9.0")
        p = self.run_publish(sp)
        self.assertNotEqual(p.returncode, 0)
        log = read_log(os.path.join(self.area.path, "gh-log.jsonl"))
        self.assertEqual(call_kinds(log), ["list", "create"])
        self.assertFalse(any("upload" in r["argv"] for r in log))
        self.assertFalse(any("--method" in r["argv"] for r in log))
        self.assertNotIn("Готово", p.stdout.decode())
        state = read_state(sp)
        self.assertEqual(state["releases"], [])
        self.assertEqual(state["latest_tag"], "v0.9.0")

    def test_bad_readback_fails(self):
        self.make_artifacts(TAG)
        sp = self.gh_state(releases=[{"id": 7, "tag_name": TAG, "draft": True,
                                      "prerelease": False, "assets": []}],
                           corrupt_get_after_patch=True)
        p = self.run_publish(sp)
        self.assertNotEqual(p.returncode, 0)
        # PATCH был, но readback (draft=true) отвергнут: успеха НЕ заявлено
        log = read_log(os.path.join(self.area.path, "gh-log.jsonl"))
        self.assertEqual(call_kinds(log),
                         ["list", "get-by-tag", "get-by-id"]
                         + ["upload"] * 14 + ["get-by-id", "patch", "get-by-id"])
        self.assertNotIn("Готово", p.stdout.decode())
        state = read_state(sp)
        self.assertTrue(state["patched"])
        # PATCH прошёл — typed-тело как у stable; readback-сбой не откатывает
        self.assertEqual(state["patch_body"],
                         {"draft": False, "prerelease": False,
                          "make_latest": "legacy"})

    def test_fresh_get_network_fail_no_uploads(self):
        # сетевая ошибка свежего GET releases/<id>: fail без единой загрузки
        # и без PATCH
        self.make_artifacts(TAG)
        sp = self.gh_state(releases=[{"id": 7, "tag_name": TAG, "draft": True,
                                      "prerelease": False, "assets": []}],
                           get_by_id_fail=True)
        p = self.run_publish(sp)
        self.assertNotEqual(p.returncode, 0)
        log = read_log(os.path.join(self.area.path, "gh-log.jsonl"))
        self.assertFalse(any("upload" in r["argv"] for r in log))
        state = read_state(sp)
        self.assertTrue(self.assets_of(state)["draft"])
        self.assertEqual(state["latest_tag"], "v0.9.0")

    def test_patch_fail_no_publish_no_latest(self):
        # PATCH падает (сеть): ассеты загружены, но релиз остаётся draft,
        # latest-pointer НЕ изменён
        self.make_artifacts(TAG)
        sp = self.gh_state(releases=[{"id": 7, "tag_name": TAG, "draft": True,
                                      "prerelease": False, "assets": []}],
                           patch_fail=True)
        p = self.run_publish(sp)
        self.assertNotEqual(p.returncode, 0)
        state = read_state(sp)
        self.assertTrue(self.assets_of(state)["draft"])
        self.assertNotIn("patched", state)
        self.assertEqual(state["latest_tag"], "v0.9.0")


class ReleaseWorkflowWiring(unittest.TestCase):
    """Узкая проверка РЕАЛЬНЫХ привязок release.yml. Это НЕ generic YAML
    validation (сам YAML принимает GitHub на PR/push): минимальный stateful
    парсер выделяет top-level job-блоки, ассерты — про привязки метаданных
    (id/outputs/needs/env/permissions/trigger/targets), а не про unrelated
    substrings где угодно в файле."""

    def setUp(self):
        self.release = self._read('.github/workflows/release.yml')
        self.producer = self._read('.github/workflows/license-bundle.yml')
        self.promotion = self._read('.github/workflows/license-promote.yml')
        self.publisher = self._read('.github/release/publish-bundle.sh')

    def _read(self, path):
        with open(os.path.join(fx.REPO_ROOT, path), encoding='utf-8') as f:
            return f.read()

    def _code(self, text):
        return '\n'.join(line.split('#', 1)[0].rstrip()
                         for line in text.splitlines())

    def _top(self, text, key):
        import re
        match = re.search(r'(?m)^' + re.escape(key) + r':[ \t]*\n((?:(?:[ \t]+[^\n]*)?\n)*)',
                          self._code(text) + '\n')
        self.assertIsNotNone(match, key)
        return match.group(1)

    def _jobs(self, text):
        import re
        block = self._top(text, 'jobs')
        matches = list(re.finditer(r'(?m)^  ([\w-]+):\s*$', block))
        return {m.group(1): block[m.end():matches[i + 1].start()
                                  if i + 1 < len(matches) else len(block)]
                for i, m in enumerate(matches)}

    def _steps(self, job):
        import re
        return re.split(r'(?m)^      - ', job)[1:]

    def _contains_line(self, block, line):
        self.assertIn(line, [s.strip() for s in self._code(block).splitlines()])

    def _command(self, block, command, flags):
        steps = [s for s in self._steps(block) if command in s]
        self.assertEqual(len(steps), 1, command)
        lines = [line.strip() for line in steps[0].splitlines() if command in line]
        self.assertEqual(len(lines), 1, command)
        for flag in flags:
            self.assertIn(flag, lines[0], command)
        return steps[0]

    def _assert_release(self, text):
        import re
        jobs = self._jobs(text)
        self.assertEqual(set(jobs), {'validate', 'license-audit', 'origin', 'release'})
        self.assertEqual([s.strip() for s in self._top(text, 'on').splitlines() if s.strip()],
                         ['push:', 'tags:', "- 'v*'"])
        self.assertEqual([s.strip() for s in self._top(text, 'permissions').splitlines() if s.strip()],
                         ['contents: read'])
        val = jobs['validate']
        steps = [s for s in self._steps(val) if 'bash .github/release/validate-tag.sh' in s]
        self.assertEqual(len(steps), 1)
        self._contains_line(steps[0], 'id: tag')
        self._contains_line(steps[0], 'GH_REF_NAME: ${{ github.ref_name }}')
        self._contains_line(steps[0], 'bash .github/release/validate-tag.sh "$GH_REF_NAME" > "$GITHUB_OUTPUT"')
        for key in ('tag', 'prerelease'):
            self._contains_line(val, key + ': ${{ steps.tag.outputs.' + key + ' }}')
        audit = jobs['license-audit']
        self.assertNotRegex(audit, r'(?m)^    needs:')
        self._contains_line(audit, '- run: cargo deny --config .github/deny.toml check licenses')
        self.assertIn('cargo metadata --locked --format-version 1 --filter-platform "$target"', audit)
        rel = jobs['release']
        self._contains_line(rel, 'needs: [validate, origin, license-audit]')
        self._contains_line(jobs['origin'], 'needs: validate')
        for job in ('origin', 'release'):
            block = jobs[job]
            for key in ('POLICY_SHA', 'BUILD_SHA', 'PROMOTION_RUN_ID', 'PROMOTION_ATTEMPT',
                        'PROMOTION_ARTIFACT_ID', 'REVIEW_COMMIT', 'PRODUCER_RUN_ID',
                        'PRODUCER_ATTEMPT', 'PRODUCER_ARTIFACT_ID'):
                self._contains_line(block, key + ': ${{ vars.LICENSE_' + key + ' }}')
            self._contains_line(block, 'TAG: ${{ needs.validate.outputs.tag }}')
            self._contains_line(block, 'actions: read')
            self._contains_line(block, 'ref: ${{ vars.LICENSE_POLICY_SHA }}')
            self._contains_line(block, 'persist-credentials: false')
            self._contains_line(block, '[ "$(git rev-parse HEAD)" = "$POLICY_SHA" ]')
            self._command(block, 'provenance.py fetch-promotion', (
                '--run-id "$PROMOTION_RUN_ID"', '--attempt "$PROMOTION_ATTEMPT"',
                '--artifact-id "$PROMOTION_ARTIFACT_ID"', '--head-sha "$BUILD_SHA"',
                '--policy-sha "$POLICY_SHA"', '--tag "$TAG"', '--review-commit "$REVIEW_COMMIT"',
                '--producer-run-id "$PRODUCER_RUN_ID"', '--producer-attempt "$PRODUCER_ATTEMPT"',
                '--producer-artifact-id "$PRODUCER_ARTIFACT_ID"', '--output target/promoted'))
            self._contains_line(block, '[ "$tag_sha" = "$BUILD_SHA" ]')
        self._contains_line(rel, 'PRERELEASE: ${{ needs.validate.outputs.prerelease }}')
        self._contains_line(rel, 'REMOTE_REPO: ${{ github.repository }}')
        publish = [s for s in self._steps(rel) if 'run: bash .github/release/publish-bundle.sh' in s]
        self.assertEqual(len(publish), 1)
        for line in ('ARTIFACTS_DIR: ${{ github.workspace }}/target/promoted/artifacts',
                     'ORIGIN_DIR: ${{ github.workspace }}/target/promoted',
                     'GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}'):
            self._contains_line(publish[0], line)
        self.assertLess(rel.index('provenance.py fetch-promotion'), rel.index('run: bash .github/release/publish-bundle.sh'))
        self._contains_line(rel, 'contents: write')
        for name, block in jobs.items():
            if name != 'release':
                self.assertNotRegex(block, r'(?m)^\s*contents:\s*write\s*$')
        self.assertNotRegex(self._code(text), r'\bcargo\s+build\b')

    def _assert_producer(self, text):
        import re
        jobs = self._jobs(text)
        self.assertEqual(set(jobs), {'offline-tests', 'build', 'aggregate'})
        job_envs = {}
        for name, job in jobs.items():
            envs = re.findall(r'(?m)^    env:[ \t]*\n((?:(?: {6,}[^\n]*|[ \t]*)\n)*)',
                              self._code(job) + '\n')
            job_envs[name] = envs
            for env in envs:
                self.assertNotRegex(env, r'(?is)\$\{\{(?:(?!\}\}).)*\brunner\s*(?:\.|\[)')
        self.assertEqual(len(job_envs['build']), 1)
        self.assertEqual(re.findall(r'(?m)^      CARGO_HOME:[ \t]*(.*)$', job_envs['build'][0]),
                         ['${{ github.workspace }}/target/license-cargo-home'])
        self.assertEqual([s.strip() for s in self._top(text, 'permissions').splitlines() if s.strip()], ['contents: read'])
        offline = jobs['offline-tests']
        for suite in ('test_source_inventory.py', 'test_provenance.py'):
            self._contains_line(offline, 'python3 -I .github/release/license/tests/unit/' + suite)
        steps = self._steps(offline)
        checkout = [i for i, s in enumerate(steps) if s.startswith('uses: actions/checkout@v7')]
        sdk = [i for i, s in enumerate(steps) if s.startswith('uses: ./.github/actions/setup-local-sdk')]
        suites = [i for i, s in enumerate(steps) if s.startswith('name: Run offline Python suites')]
        chain = [i for i, s in enumerate(steps) if s.startswith('name: TEST-ONLY transport chain (not production authority)')]
        self.assertEqual(len(checkout), 1)
        self.assertEqual(len(sdk), 1)
        self.assertEqual(len(suites), 1)
        self._contains_line(steps[suites[0]], 'python3 -I .github/install/tests/test_release.py ReleaseWorkflowWiring')
        self.assertEqual(len(chain), 1)
        self.assertLess(checkout[0], sdk[0])
        self.assertLess(sdk[0], suites[0])
        self.assertLess(suites[0], chain[0])
        self._contains_line(steps[chain[0]], 'run: python3 -I .github/release/license/tests/integration/test_release_chain.py')
        self.assertNotRegex(steps[chain[0]], r'(?m)^\s*(?:if|continue-on-error):')
        build = jobs['build']
        entries = re.findall(r'(?m)^\s*-\s*\{([^{}]+)\}\s*$', build)
        mapping = []
        for entry in entries:
            fields = dict(part.strip().split(':', 1) for part in entry.split(','))
            mapping.append((fields['runner'].strip(), fields['target'].strip()))
        self.assertEqual(mapping, [
            ('ubuntu-latest', 'x86_64-unknown-linux-gnu'),
            ('ubuntu-latest', 'x86_64-unknown-linux-musl'),
            ('ubuntu-24.04-arm', 'aarch64-unknown-linux-gnu'),
            ('ubuntu-24.04-arm', 'aarch64-unknown-linux-musl'),
            ('windows-latest', 'x86_64-pc-windows-msvc'),
            ('macos-15-intel', 'x86_64-apple-darwin'),
            ('macos-15', 'aarch64-apple-darwin')])
        self._contains_line(build, 'runs-on: ${{ matrix.runner }}')
        for needle in ('admission.py snapshot --prepared target/license-prepared',
                       'cargo build --locked --offline --release -p socks5-proxy --target "$TARGET"',
                       'admission.py record --prepared target/license-prepared'):
            self.assertIn(needle, build)
        snapshot = build.index('admission.py snapshot --prepared target/license-prepared')
        compile_at = build.index('cargo build --locked --offline --release -p socks5-proxy --target "$TARGET"')
        record = build.index('admission.py record --prepared target/license-prepared')
        self.assertLess(snapshot, compile_at)
        self.assertLess(compile_at, record)
        lifecycle = self._command(build, '.github/release/license/tests/integration/test_lifecycle.py', (
            '--prepared target/license-prepared', '--project .', '--sdk ../resocks5',
            '--registry-cache "$CARGO_HOME/registry/cache"', '--target "$TARGET"',
            '--binary "$binary"', '--messages target/license-logs/build-messages.jsonl',
            '--features target/license-logs/features.txt', '--toolchain target/license-logs/toolchain.txt',
            '--native-evidence target/license-logs', '--expanded-before target/license-expanded-before.json'))
        self._contains_line(lifecycle, "if: github.event_name == 'pull_request'")
        self.assertLess(record, build.index('test_lifecycle.py'))
        self.assertNotIn('--output', lifecycle)
        evidence_upload = [s for s in self._steps(build) if 'name: license-evidence-${{ matrix.target }}' in s]
        self.assertEqual(len(evidence_upload), 1)
        self.assertIn('            target/license-receipt\n', evidence_upload[0])
        self.assertNotIn('lifecycle', evidence_upload[0])
        self.assertIn('--expanded-before target/license-expanded-before.json', build[record:])
        self._contains_line(build, 'cmp "$TOR_SOCKS5_SOURCE_INFO" target/license-logs/actual-source-info.txt')
        self._contains_line(build, 'cmp "$TOR_SOCKS5_NOTICES" target/license-logs/actual-notices.txt')
        aggregate = jobs['aggregate']
        self._contains_line(aggregate, 'name: Retain release candidate')
        self._contains_line(aggregate, 'needs: [build, offline-tests]')
        diagnostics = [s for s in self._steps(aggregate) if 'name: license-bundle-candidate' in s]
        self.assertEqual(len(diagnostics), 1)
        self._contains_line(diagnostics[0], 'target/license-blockers.json')
        self.assertNotIn('license-blockers.json', [line.strip() for line in diagnostics[0].splitlines()])
        self._contains_line(aggregate, '[ "$BUILD_RESULT" = success ] && [ "$TEST_RESULT" = success ]')
        self._contains_line(aggregate, 'cp "artifacts/$archive" "artifacts/$archive.sha256" target/retained-artifacts/')
        self._contains_line(aggregate, 'cp -R "evidence/license-evidence-$target/license-receipt" "target/retained-evidence/license-evidence-$target/"')
        self._command(aggregate, 'provenance.py seal ', ('--artifacts target/retained-artifacts',
                      '--evidence target/retained-evidence', '--tag "$TAG"', '--output target/retained'))
        self._contains_line(aggregate, 'name: license-retained-${{ github.run_id }}-${{ github.run_attempt }}')
        self._contains_line(aggregate, 'path: target/retained/')
        targets = re.search(r'for target in (.*); do', aggregate)
        self.assertIsNotNone(targets)
        self.assertEqual(sorted(targets.group(1).split()), sorted(UNIX_TARGETS + WIN_TARGETS))

    def _assert_promotion(self, text):
        import re
        self.assertEqual([s.strip() for s in self._top(text, 'on').splitlines() if re.match(r'^  [\w-]+:', s)], ['workflow_dispatch:'])
        self.assertEqual([s.strip() for s in self._top(text, 'permissions').splitlines() if s.strip()], ['actions: read', 'contents: read'])
        jobs = self._jobs(text)
        self.assertEqual(set(jobs), {'promote'})
        block = jobs['promote']
        self._contains_line(block, "if: github.ref == 'refs/heads/main'")
        self.assertNotRegex(block, r'\b(?:cargo|rustc|rustup)\b')
        self.assertNotRegex(block, r'\bgh\s+')
        self.assertNotRegex(block, r'\b(?:tar\s|gzip\s|zip\s|Compress-Archive|publish(?:-bundle)?\.sh)')
        commands = [
            'provenance.py fetch ',
            'admission.py review ',
            'provenance.py verify-origin ',
            'cp target/retained/artifacts/* target/final-artifacts/',
            'admission.py assemble --evidence target/final-evidence --artifacts target/final-artifacts --tag "$TAG" --output "target/final-artifacts/tor-socks5-$TAG-license-bundle.tar.gz"',
            'admission.py verify-release --artifacts target/final-artifacts --tag "$TAG"',
            'provenance.py seal-promotion',
            'uses: actions/upload-artifact@v4']
        for command in commands:
            self.assertIn(command, block)
        producer_flags = ('--run-id "$PRODUCER_RUN_ID"', '--attempt "$PRODUCER_ATTEMPT"',
                          '--artifact-id "$PRODUCER_ARTIFACT_ID"', '--head-sha "$BUILD_SHA"', '--tag "$TAG"')
        self._command(block, 'provenance.py fetch ', producer_flags + ('--output target/retained',))
        self._command(block, 'provenance.py verify-origin ', producer_flags + ('--retained target/retained',))
        self._command(block, 'admission.py review ', (
            '--receipt "target/retained/evidence/license-evidence-$target/license-receipt"',
            '--review "target/reviews/.github/release/license/reviews/$target.json"',
            '--output "target/final-evidence/license-evidence-$target/license-receipt"'))
        self._contains_line(block, 'ref: ${{ inputs.review_commit }}')
        self._contains_line(block, 'path: target/reviews')
        self._contains_line(block, 'REVIEW_COMMIT: ${{ inputs.review_commit }}')
        self._contains_line(block, 'run: \'[ "$(git -C target/reviews rev-parse HEAD)" = "$REVIEW_COMMIT" ]\'')
        self.assertLess(block.index('git -C target/reviews rev-parse HEAD'), block.index('admission.py review '))
        self._command(block, 'provenance.py seal-promotion', (
            '--producer-run-id "$PRODUCER_RUN_ID"', '--producer-attempt "$PRODUCER_ATTEMPT"',
            '--producer-artifact-id "$PRODUCER_ARTIFACT_ID"', '--head-sha "$BUILD_SHA"',
            '--tag "$TAG"', '--retained target/retained', '--artifacts target/final-artifacts',
            '--evidence target/final-evidence', '--reviews target/reviews', '--review-commit "$REVIEW_COMMIT"', '--output target/promoted'))
        positions = [block.index(command) for command in commands]
        self.assertEqual(positions, sorted(positions))
        self._contains_line(block, 'path: target/promoted/')
        target_match = re.search(r'for target in (.*); do', block)
        self.assertIsNotNone(target_match)
        targets = target_match.group(1).split()
        self.assertEqual(set(targets), set(UNIX_TARGETS) | set(WIN_TARGETS))
        self.assertEqual(len(targets), 7)

    def test_workflow_graph_and_producer(self):
        self._assert_release(self.release)
        self._assert_producer(self.producer)
        self._assert_promotion(self.promotion)

    def test_publisher_provenance_and_assets(self):
        code = self._code(self.publisher)
        self.assertIn('provenance.py', code)
        self.assertIn('admission.py verify-release --artifacts "$ARTIFACTS_DIR" --tag "$TAG"', code)
        self.assertIn('provenance.py verify-promotion', code)
        for flag in ('--run-id "$PROMOTION_RUN_ID"', '--attempt "$PROMOTION_ATTEMPT"',
                     '--artifact-id "$PROMOTION_ARTIFACT_ID"', '--head-sha "$BUILD_SHA"',
                     '--policy-sha "$POLICY_SHA"', '--tag "$TAG"', '--review-commit "$REVIEW_COMMIT"',
                     '--producer-run-id "$PRODUCER_RUN_ID"', '--producer-attempt "$PRODUCER_ATTEMPT"',
                     '--producer-artifact-id "$PRODUCER_ARTIFACT_ID"', '--promoted "$ORIGIN_DIR"'):
            self.assertIn(flag, code[code.index('provenance.py verify-promotion'):code.index('promotion provenance verification failed')])
        self.assertLess(code.index('admission.py verify-release'), code.index('gh release create'))
        self.assertLess(code.index('admission.py verify-release'), code.index('gh release upload'))
        self.assertLess(code.index('admission.py verify-release'), code.index('gh api --method PATCH'))
        self.assertIn('"$ORIGIN_DIR"', code)
        self.assertLess(code.index('provenance.py'), code.index('gh release create'))
        self.assertLess(code.index('provenance.py'), code.index('gh release upload'))
        self.assertLess(code.index('provenance.py'), code.index('gh api --method PATCH'))
        self.assertIn('tor-socks5-$TAG-$t.tar.gz tor-socks5-$TAG-$t.tar.gz.sha256', code)
        self.assertIn('tor-socks5-$TAG-$t.zip tor-socks5-$TAG-$t.zip.sha256', code)
        self.assertIn('tor-socks5-$TAG-license-bundle.tar.gz tor-socks5-$TAG-license-bundle.tar.gz.sha256', code)
        self.assertIn('for f in $expected_files; do\n    gh release upload', code)
        self.assertEqual(len(expected_names(TAG)) + 2, 16)
        asset_check = code[code.index('check_assets() {'):code.index('check_asset_sizes() {')]
        self.assertIn('($m[0].digest != $hashes[$n])', asset_check)
        self.assertIn('($m[0].size // 0) <= 0', asset_check)
        self.assertIn('(($m[0].size // null) | type) != "number"', asset_check)

    def test_mutational_controls(self):
        self._assert_release(self.release)
        self._assert_producer(self.producer)
        self._assert_promotion(self.promotion)
        step_runner = self.producer.replace(
            '        run: python3 -I .github/release/license/tests/integration/test_release_chain.py',
            '        env:\n          TEMP_DIR: ${{ runner.temp }}\n'
            '        run: python3 -I .github/release/license/tests/integration/test_release_chain.py', 1)
        self.assertNotEqual(step_runner, self.producer)
        self._assert_producer(step_runner)
        cases = [
            (self._assert_producer, self.producer.replace('CARGO_HOME: ${{ github.workspace }}/target/license-cargo-home', 'CARGO_HOME: ${{ runner.temp }}/license-cargo-home', 1)),
            (self._assert_producer, self.producer.replace('    name: License tooling offline tests\n', '    name: License tooling offline tests\n    env:\n      TEMP_DIR: ${{ runner.temp }}\n', 1)),
            (self._assert_producer, self.producer.replace('CARGO_HOME: ${{ github.workspace }}/target/license-cargo-home', 'CARGO_HOME: ~/.cargo', 1)),
            (self._assert_producer, self.producer.replace('          python3 -I .github/install/tests/test_release.py ReleaseWorkflowWiring\n', '', 1)),
            (self._assert_producer, self.producer.replace('      - uses: ./.github/actions/setup-local-sdk\n', '', 1)),
            (self._assert_producer, self.producer.replace('run: python3 -I .github/release/license/tests/integration/test_release_chain.py', 'run: true', 1)),
            (self._assert_producer, self.producer.replace('            target/license-blockers.json', '            license-blockers.json', 1)),
            (self._assert_producer, self.producer.replace('          - {runner: macos-15, target: aarch64-apple-darwin, archive: tar.gz}\n', '', 1)),
            (self._assert_release, self.release.replace('needs: [validate, origin, license-audit]', 'needs: [validate, origin]', 1)),
            (self._assert_release, self.release.replace('run: bash .github/release/publish-bundle.sh', 'run: bash .github/release/publish.sh', 1)),
            (self._assert_release, self.release.replace('ORIGIN_DIR: ${{ github.workspace }}/target/promoted', 'ORIGIN_DIR: ${{ github.workspace }}/target/promoted/artifacts', 1)),
            (self._assert_release, self.release.replace('needs: [validate, origin, license-audit]', '# needs: [validate, origin, license-audit]\n    needs: [validate, origin]', 1)),
            (self._assert_promotion, self.promotion.replace('set -euo pipefail', 'set -euo pipefail\n          cargo build --release', 1)),
        ]
        for check, altered in cases:
            original = {self._assert_release: self.release, self._assert_producer: self.producer,
                        self._assert_promotion: self.promotion}[check]
            with self.subTest(check=check.__name__):
                self.assertNotEqual(altered, original)
                with self.assertRaises(AssertionError):
                    check(altered)

    def test_portability_alpine_smoke_wiring(self):
        ci_path = os.path.join(fx.REPO_ROOT, ".github", "workflows", "ci.yml")
        with open(ci_path, "r", encoding="utf-8") as f:
            ci = f.read()
        jobs = self._jobs(ci)
        block = jobs["portability-diagnostics"]
        def assert_smoke_wiring(text):
            for expected in (
                    'docker run --rm --network none --read-only',
                    '--platform "$platform"',
                    'dst=/socks5-proxy,readonly', 'alpine:3.22 /socks5-proxy --version',
                    'x86_64-*) platform=linux/amd64',
                    'aarch64-*) platform=linux/arm64',
                    'if [ "$MUSL" = "true" ]; then'):
                if expected not in text:
                    raise AssertionError("missing Alpine smoke wiring: " + expected)
        assert_smoke_wiring(block)
        self.assertNotEqual(block.replace("docker run", "podman run", 1), block)
        with self.assertRaises(AssertionError):
            assert_smoke_wiring(block.replace("docker run", "podman run", 1))


if __name__ == "__main__":
    unittest.main(verbosity=2)
