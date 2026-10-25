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
UNIX_TARGETS = ("x86_64-unknown-linux-gnu", "x86_64-apple-darwin",
                "aarch64-apple-darwin")
WIN_TARGET = "x86_64-pc-windows-msvc"
GH = shutil.which("gh")  # настоящий gh не нужен: stub добавляется в PATH


def expected_names(tag):
    names = []
    for t in UNIX_TARGETS:
        names += ["tor-socks5-%s-%s.tar.gz" % (tag, t),
                  "tor-socks5-%s-%s.tar.gz.sha256" % (tag, t)]
    for t in (WIN_TARGET,):
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
                 "tags": kw.pop("tags", [TAG]), "next_id": kw.pop("next_id", 100)}
        state.update(kw)
        path = os.path.join(self.area.path, "gh-state.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f)
        return path

    def make_artifacts(self, tag, content_prefix=b"archive-marker"):
        """Ровно 8 файлов (4 архива + 4 .sha256): каждый архив получает
        РОВНО ОДИН свой checksum в формате publish.sh (tar.gz: '<h>  <n>\n',
        zip: '<h> *<n>' без LF). Самопроверка точного набора имён ДО запуска."""
        d = self.area.subdir("artifacts")
        archives = [n for n in expected_names(tag) if not n.endswith(".sha256")]
        self.assertEqual(len(archives), 4)
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
        # 1 create + 8 uploads + 1 PATCH; GET/readback — read-only
        self.assertEqual(len(muts), 10)
        create = muts[0]["argv"]
        self.assertIn("--draft", create)
        self.assertIn("--verify-tag", create)

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
        self.assertEqual(len(rel["assets"]), 8)
        muts = mutations(read_log(
            os.path.join(self.area.path, "gh-log.jsonl")))
        self.assertNotIn("create", muts[0]["argv"])

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

    # --- плохие локальные артефакты: fail с НУЛЁМ gh-вызовов --------------

    def test_bad_local_artifacts_zero_gh_calls(self):
        tag = TAG
        d = self.make_artifacts(tag)
        names = expected_names(tag)
        # positive control: тот же harness с чистой копией проходит ДО сети
        d0 = self.area.subdir("v0")
        shutil.copytree(d, d0, dirs_exist_ok=True)
        sp0 = self.gh_state()
        self.assertEqual(self.run_publish(sp0, artifacts_dir=d0).returncode, 0)
        variants = {}
        # missing
        d1 = self.area.subdir("v1")
        shutil.copytree(d, d1, dirs_exist_ok=True)
        os.remove(os.path.join(d1, names[3]))
        variants["missing"] = d1
        # empty
        d2 = self.area.subdir("v2")
        shutil.copytree(d, d2, dirs_exist_ok=True)
        open(os.path.join(d2, names[0]), "wb").close()
        variants["empty"] = d2
        # symlink на валидный файл + ОТДЕЛЬНЫЙ dangling symlink под НОВЫМ именем
        d3 = self.area.subdir("v3")
        shutil.copytree(d, d3, dirs_exist_ok=True)
        target = os.path.join(d3, names[1])
        os.remove(target)                    # unlink ПЕРЕД созданием symlink
        os.symlink(os.path.join(d, names[1]), target)
        dangling = os.path.join(d3, "dangling-extra-file")
        if os.path.lexists(dangling):
            os.remove(dangling)
        os.symlink("nowhere", dangling)      # не поверх required-файла
        variants["symlink"] = d3
        # hidden/extra/subdir
        d4 = self.area.subdir("v4")
        shutil.copytree(d, d4, dirs_exist_ok=True)
        open(os.path.join(d4, ".hidden"), "wb").write(b"x")
        open(os.path.join(d4, "extra.txt"), "wb").write(b"x")
        os.makedirs(os.path.join(d4, "subdir"))
        variants["extra"] = d4
        # bad sha / bad format / постороннее имя в checksum
        d5 = self.area.subdir("v5")
        shutil.copytree(d, d5, dirs_exist_ok=True)
        with open(os.path.join(d5, names[0] + ".sha256"), "wb") as f:
            f.write(b"0" * 64 + b"  " + names[0].encode() + b"\n")
        variants["bad-sha"] = d5
        d6 = self.area.subdir("v6")
        shutil.copytree(d, d6, dirs_exist_ok=True)
        with open(os.path.join(d6, names[4] + ".sha256"), "wb") as f:
            f.write(b"zz" + names[4].encode())
        variants["bad-format"] = d6
        d7 = self.area.subdir("v7")
        shutil.copytree(d, d7, dirs_exist_ok=True)
        with open(os.path.join(d7, names[0] + ".sha256"), "wb") as f:
            f.write(fx.checksum_text(fx.sha256_hex(fx.file_bytes(
                os.path.join(d, names[0]))), "someone-else.tar.gz").encode())
        variants["foreign-name"] = d7

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
        sp = self.gh_state(releases=[{"id": 7, "tag_name": TAG, "draft": True,
                                      "prerelease": False, "assets": []}],
                           fail_upload=[expected_names(TAG)[0]])
        p = self.run_publish(sp)
        self.assertNotEqual(p.returncode, 0)
        state = read_state(sp)
        self.assertTrue(self.assets_of(state)["draft"])
        self.assertNotIn("patched", state)
        # latest-pointer не тронут failed upload'ом
        self.assertNotIn("latest_tag", state)

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
                self.assertNotIn("latest_tag", state)

    def test_bad_readback_fails(self):
        self.make_artifacts(TAG)
        sp = self.gh_state(releases=[{"id": 7, "tag_name": TAG, "draft": True,
                                      "prerelease": False, "assets": []}],
                           corrupt_get_after_patch=True)
        p = self.run_publish(sp)
        self.assertNotEqual(p.returncode, 0)

    def test_fresh_get_before_upload_fail_no_uploads(self):
        # свежий GET releases/<id> ПЕРЕД upload: неверный id => fail без
        # единой загрузки и без PATCH
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
        self.assertNotIn("latest_tag", state)

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
        self.assertNotIn("latest_tag", state)


class ReleaseWorkflowWiring(unittest.TestCase):
    """Узкая проверка РЕАЛЬНЫХ привязок release.yml. Это НЕ generic YAML
    validation (сам YAML принимает GitHub на PR/push): минимальный stateful
    парсер выделяет top-level job-блоки, ассерты — про привязки метаданных
    (id/outputs/needs/env/permissions/trigger/targets), а не про unrelated
    substrings где угодно в файле."""

    def setUp(self):
        with open(fx.RELEASE_YML, "r", encoding="utf-8") as f:
            self.lines = f.read().splitlines()
        self.jobs = self._job_blocks()
        self.assertTrue({"validate", "build", "release"} <= set(self.jobs),
                        self.jobs.keys())

    def _job_blocks(self):
        # job-ключи — на отступе ровно 2 под "jobs:"; всё глубже — тело
        jobs, cur = {}, None
        for line in self.lines:
            if (line.startswith("  ") and not line.startswith("   ")
                    and line.rstrip().endswith(":")
                    and ":" not in line.strip()[:-1]):
                cur = line.strip()[:-1]
                jobs[cur] = []
            elif cur is not None:
                jobs[cur].append(line)
        return {k: "\n".join(v) for k, v in jobs.items()}

    def _top_block(self, key):
        out, cur = [], False
        for line in self.lines:
            if line.strip() == key + ":":
                cur = True
                continue
            if cur and line and not line[0].isspace():
                break
            if cur:
                out.append(line)
        return "\n".join(out)

    def test_validate_step_bindings(self):
        val = self.jobs["validate"]
        # id: tag — в ТОМ ЖЕ step, который запускает validate-tag.sh
        steps = val.split("\n      - ")
        tag_steps = [s for s in steps if "validate-tag.sh" in s]
        self.assertEqual(len(tag_steps), 1)
        self.assertIn("id: tag", tag_steps[0])
        # job outputs ссылаются именно на этот step
        self.assertIn("tag: ${{ steps.tag.outputs.tag }}", val)
        self.assertIn("prerelease: ${{ steps.tag.outputs.prerelease }}", val)

    def test_publisher_env_needs_permissions(self):
        rel = self.jobs["release"]
        self.assertIn("needs: [validate, build]", rel)
        # env публикации — из outputs validate-job'а и секретов
        self.assertIn("TAG: ${{ needs.validate.outputs.tag }}", rel)
        self.assertIn("PRERELEASE: ${{ needs.validate.outputs.prerelease }}", rel)
        self.assertIn("REMOTE_REPO: ${{ github.repository }}", rel)
        self.assertIn("GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}", rel)
        self.assertIn("publish.sh", rel)
        # contents: write — ТОЛЬКО у публикации
        self.assertIn("contents: write", rel)
        for job in ("validate", "build"):
            self.assertNotIn("contents: write", self.jobs[job])

    def test_tag_only_trigger_and_native_targets(self):
        on_block = self._top_block("on")
        self.assertIn("'v*'", on_block)
        self.assertNotIn("pull_request", on_block)
        self.assertNotIn("workflow_dispatch", on_block)
        targets = set()
        for line in self.jobs["build"].splitlines():
            s = line.strip()
            if s.startswith("target:"):
                targets.add(s.split(":", 1)[1].strip())
        self.assertEqual(targets, set(UNIX_TARGETS) | {WIN_TARGET})


if __name__ == "__main__":
    unittest.main(verbosity=2)
