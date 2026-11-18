# -*- coding: utf-8 -*-
"""Offline-тесты НАСТОЯЩЕГО установщика .github/install/install.ps1 как
дочернего процесса.

Транспорт подменяется ТОЛЬКО в harness: powershell_mock.ps1 определяет mock
Invoke-RestMethod / Invoke-WebRequest (и в узких сценариях Join-Path) и
ПОЛНОСТЬЮ вызывает настоящий install.ps1.

Запуск (Python -I, изоляция sys.path, helpers подключаются явно):
  python  -I .github/install/tests/test_install_ps.py PowerShellInstallTests  # windows

Тег latest в mock (v9.8.7) заведомо не совпадает с Cargo-тегами проекта.
Payload-байты — маркеры, НИКОГДА не исполняются. Все subprocess — с таймаутом.
Версия для sh — test_install_sh.py.
"""

import json
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixtures as fx

PS_ENGINES = [e for e in ("powershell", "pwsh") if shutil.which(e)]
PS_WRAPPER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "powershell_mock.ps1")


def read_log(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8-sig") as f:
        return [json.loads(line) for line in f if line.strip()]


class PowerShellInstallTests(unittest.TestCase):
    """install.ps1: Windows PowerShell 5.1 (`powershell`) И PowerShell 7
    (`pwsh`) — обе настоящие версии движка, одна не заменяет другую."""

    ARCHIVE_NAME = "tor-socks5-%s-x86_64-pc-windows-msvc.zip" % fx.MOCK_TAG

    def setUp(self):
        self.area = fx.TempArea(self)
        self._build_n = 0   # уникальный лог-путь на каждый build: JSONL
        # одного прогона не должен смешиваться с записями других прогонов
        # того же теста (иначе ассерты на len(лог)/[] видят чужие записи)

    # --- helpers -------------------------------------------------------

    def asset_urls(self):
        base = "https://github.com/%s/%s/releases/download/%s" % (
            fx.OWNER, fx.REPO, fx.MOCK_TAG)
        a = "%s/%s" % (base, self.ARCHIVE_NAME)
        return a, a + ".sha256"

    def build(self, release=None, downloads=None, checksum=None,
              joinpath_mode=None, joinpath_path=None, fail_api=False):
        self._build_n += 1
        archive_path = self.area.file("dl/" + self.ARCHIVE_NAME,
                                      fx.MARKER)
        fx.make_zip(archive_path, [{"name": "tor-socks5.exe"}])
        # хеш считаем от РЕАЛЬНЫХ байт файла (zip сжат);
        # default — ТОЛЬКО когда checksum is None (пустой b'' не подменяем)
        archive_bytes = fx.file_bytes(archive_path)
        if checksum is None:
            checksum = fx.checksum_text(fx.sha256_hex(archive_bytes),
                                        self.ARCHIVE_NAME).encode("ascii")
        sum_path = self.area.file("dl/%s.sha256" % self.ARCHIVE_NAME,
                                  checksum if isinstance(checksum, bytes)
                                  else checksum.encode("utf-8"))
        a_url, s_url = self.asset_urls()
        if release is None:
            release = {"tag_name": fx.MOCK_TAG, "draft": False,
                       "prerelease": False,
                       "assets": [
                           {"name": self.ARCHIVE_NAME, "browser_download_url": a_url},
                           {"name": self.ARCHIVE_NAME + ".sha256",
                            "browser_download_url": s_url}]}
        if downloads is None:
            downloads = {a_url: {"file": archive_path, "redirects": []},
                         s_url: {"file": sum_path, "redirects": []}}
        scen = {"release": release, "downloads": downloads, "fail_api": fail_api,
                "joinpath_mode": joinpath_mode or "none",
                "joinpath_path": joinpath_path,
                "log": os.path.join(self.area.path,
                                    "ps-log-%d.jsonl" % self._build_n)}
        scen_path = self.area.file("scenario.json",
                                   json.dumps(scen, ensure_ascii=False).encode("utf-8"))
        return {"scen": scen_path, "log": scen["log"], "a_url": a_url,
                "s_url": s_url, "archive_path": archive_path}

    def ps_run(self, ctx, install_dir, env_extra=None, engine="powershell"):
        # Каждая оболочка строит собственный PSModulePath, не наследует модули pwsh.
        env = {key: value for key, value in os.environ.items()
               if key.upper() != "PSMODULEPATH"}
        env.pop("PROCESSOR_ARCHITEW6432", None)
        env["LOCALAPPDATA"] = self.area.subdir("appdata")
        if env_extra:
            env.update(env_extra)
        exe = shutil.which(engine)
        return fx.run_cmd([exe, "-NoProfile", "-NonInteractive",
                           "-ExecutionPolicy", "Bypass", "-File", PS_WRAPPER,
                           "-ScenarioPath", ctx["scen"],
                           "-ScriptPath", fx.INSTALL_PS1,
                           "-InstallDir", install_dir], env=env)

    def ps_log(self, ctx):
        return read_log(ctx["log"])

    def for_each_engine(self):
        # Обе версии ОБЯЗАТЕЛЬНЫ: отсутствие powershell ИЛИ pwsh — ошибка
        # (не skip); ни одна не подменяет другую
        missing = [e for e in ("powershell", "pwsh") if shutil.which(e) is None]
        self.assertFalse(
            missing, "на windows-latest отсутствуют PS-движки: %s" % missing)
        return list(PS_ENGINES)

    # --- happy path -----------------------------------------------------

    def test_happy_override_and_default_dir(self):
        for engine in self.for_each_engine():
            with self.subTest(engine=engine):
                ctx = self.build()
                dest_dir = self.area.subdir("dest my[1] dir")
                p = self.ps_run(ctx, dest_dir, engine=engine)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                exe = os.path.join(dest_dir, "tor-socks5.exe")
                self.assertEqual(fx.file_bytes(exe), fx.MARKER)
                log = self.ps_log(ctx)
                irm = [r for r in log if r["fn"] == "Invoke-RestMethod"]
                iwr = [r for r in log if r["fn"] == "Invoke-WebRequest"]
                self.assertEqual(len(irm), 1)
                self.assertEqual(irm[0]["uri"],
                                 "https://api.github.com/repos/%s/%s/releases/latest"
                                 % (fx.OWNER, fx.REPO))
                self.assertEqual(irm[0]["maximumRedirection"], 0)
                # оба ассета реально скачаны, каждый с MaximumRedirection 0
                self.assertEqual(sorted(r["uri"] for r in iwr),
                                 sorted([ctx["a_url"], ctx["s_url"]]))
                self.assertTrue(all(r["maximumRedirection"] == 0 for r in iwr))
                # default dir через LOCALAPPDATA
                ctx2 = self.build()
                p = self.ps_run(ctx2, "", engine=engine)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertEqual(
                    fx.file_bytes(os.path.join(self.area.path, "appdata",
                                               "Programs", "tor-socks5",
                                               "tor-socks5.exe")), fx.MARKER)

    def test_backup_cleanup_and_replace(self):
        for engine in self.for_each_engine():
            with self.subTest(engine=engine):
                ctx = self.build()
                dest_dir = self.area.subdir("dest")
                exe = os.path.join(dest_dir, "tor-socks5.exe")
                with open(exe, "wb") as f:
                    f.write(fx.MARKER_OLD)
                old_backup = os.path.join(dest_dir,
                                          "tor-socks5.exe.old." + "a" * 32)
                with open(old_backup, "wb") as f:
                    f.write(b"stale backup")
                foreign_backup = os.path.join(dest_dir, "tor-socks5.exe.old.zzz")
                with open(foreign_backup, "wb") as f:
                    f.write(b"not ours")
                other = os.path.join(dest_dir, "readme.txt")
                with open(other, "wb") as f:
                    f.write(b"docs")
                p = self.ps_run(ctx, dest_dir, engine=engine)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertEqual(fx.file_bytes(exe), fx.MARKER)
                self.assertFalse(os.path.exists(old_backup))
                self.assertTrue(os.path.exists(foreign_backup))
                self.assertEqual(fx.file_bytes(other), b"docs")

    # --- arch detection --------------------------------------------------

    def test_arch_detection(self):
        for engine in self.for_each_engine():
            with self.subTest(engine=engine):
                ctx = self.build()
                p = self.ps_run(ctx, self.area.subdir("d1"),
                                env_extra=fx.ps_arch_env("AMD64"), engine=engine)
                self.assertEqual(p.returncode, 0, p.stdout)
                # native WOW64: 32-битный процесс на 64-битной ОС
                ctx2 = self.build()
                p = self.ps_run(ctx2, self.area.subdir("d2"),
                                env_extra=fx.ps_arch_env("x86", wow64="AMD64"),
                                engine=engine)
                self.assertEqual(p.returncode, 0, p.stdout)
                # unsupported ARM / пустая arch: fail ДО любых обращений
                for extra in (fx.ps_arch_env("ARM64"),
                              {"PROCESSOR_ARCHITECTURE": ""}):
                    ctx3 = self.build()
                    p = self.ps_run(ctx3, self.area.subdir("d3"),
                                    env_extra=extra, engine=engine)
                    self.assertNotEqual(p.returncode, 0)
                    self.assertEqual(self.ps_log(ctx3), [])

    def test_fail_api_no_downloads(self):
        for engine in self.for_each_engine():
            with self.subTest(engine=engine):
                ctx = self.build(fail_api=True)
                p = self.ps_run(ctx, self.area.subdir("d"), engine=engine)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(
                    [r for r in self.ps_log(ctx)
                     if r["fn"] == "Invoke-WebRequest"], [])

    # --- выбор ассета и URL ----------------------------------------------

    def test_asset_selection_negatives(self):
        a_url, s_url = self.asset_urls()
        dup = {"tag_name": fx.MOCK_TAG, "draft": False, "prerelease": False,
               "assets": [{"name": self.ARCHIVE_NAME, "browser_download_url": a_url},
                          {"name": self.ARCHIVE_NAME, "browser_download_url": a_url}]}
        missing = {"tag_name": fx.MOCK_TAG, "draft": False, "prerelease": False,
                   "assets": [{"name": self.ARCHIVE_NAME,
                               "browser_download_url": a_url}]}
        bad_tag = {"tag_name": "v1.2.3/x? ../", "draft": False,
                   "prerelease": False,
                   "assets": [{"name": self.ARCHIVE_NAME,
                               "browser_download_url": a_url}]}
        bad_url = {"tag_name": fx.MOCK_TAG, "draft": False, "prerelease": False,
                   "assets": [
                       {"name": self.ARCHIVE_NAME,
                        "browser_download_url": "http://github.com/x"},
                       {"name": self.ARCHIVE_NAME + ".sha256",
                        "browser_download_url": s_url}]}
        query_url = {"tag_name": fx.MOCK_TAG, "draft": False, "prerelease": False,
                     "assets": [
                         {"name": self.ARCHIVE_NAME,
                          "browser_download_url": a_url + "?X-Amz=1"},
                         {"name": self.ARCHIVE_NAME + ".sha256",
                          "browser_download_url": s_url}]}
        for label, release in (("duplicate", dup), ("missing-checksum", missing),
                               ("unsafe-tag", bad_tag), ("non-https", bad_url),
                               ("query-in-url", query_url)):
            for engine in self.for_each_engine():
                with self.subTest(case=label, engine=engine):
                    ctx = self.build(release=release)
                    dest = self.area.subdir("d")
                    exe = os.path.join(dest, "tor-socks5.exe")
                    with open(exe, "wb") as f:
                        f.write(fx.MARKER_OLD)
                    conf = os.path.join(dest, "tor-socks5.conf")
                    with open(conf, "wb") as f:
                        f.write(b"key=value\n")
                    p = self.ps_run(ctx, dest, engine=engine)
                    self.assertNotEqual(p.returncode, 0)
                    # latest API ДОСТИГНУТ, downloads НЕТ; старые файлы целы
                    log = self.ps_log(ctx)
                    irm = [r for r in log if r["fn"] == "Invoke-RestMethod"]
                    self.assertEqual(len(irm), 1)
                    self.assertEqual(irm[0]["uri"],
                                     "https://api.github.com/repos/%s/%s/releases/latest"
                                     % (fx.OWNER, fx.REPO))
                    self.assertEqual(
                        [r for r in log if r["fn"] == "Invoke-WebRequest"], [])
                    self.assertEqual(fx.file_bytes(exe), fx.MARKER_OLD)
                    self.assertEqual(fx.file_bytes(conf), b"key=value\n")

    # --- ручные redirects -------------------------------------------------

    def cdn(self, suffix="a"):
        return ("https://release-assets.githubusercontent.com/"
                "repos/x/y/%s?X-Amz-Signature=abc" % suffix)

    def test_redirects_positive_both_shapes(self):
        for engine in self.for_each_engine():
            with self.subTest(engine=engine):
                a_url, s_url = self.asset_urls()
                archive_path = self.area.file("dl/" + self.ARCHIVE_NAME, fx.MARKER)
                fx.make_zip(archive_path, [{"name": "tor-socks5.exe"}])
                # хеш от РЕАЛЬНЫХ байт zip-файла (сжат), не от маркера
                archive_digest = fx.sha256_hex(fx.file_bytes(archive_path))
                sum_path = self.area.file(
                    "dl/%s.sha256" % self.ARCHIVE_NAME,
                    fx.checksum_text(archive_digest,
                                     self.ARCHIVE_NAME).encode("ascii"))
                downloads = {
                    a_url: {"file": archive_path, "redirects": [
                        {"status": 302, "location": self.cdn("archive"),
                         "shape": "ps51"}]},
                    s_url: {"file": sum_path, "redirects": [
                        {"status": 302, "location": self.cdn("checksum"),
                         "shape": "ps7"}]},
                    # терминальные CDN hop'ы тоже обслуживаются mock'ом (2xx)
                    self.cdn("archive"): {"file": archive_path, "redirects": []},
                    self.cdn("checksum"): {"file": sum_path, "redirects": []},
                }
                ctx = self.build(downloads=downloads)
                dest = self.area.subdir("dest")
                p = self.ps_run(ctx, dest, engine=engine)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertEqual(fx.file_bytes(
                    os.path.join(dest, "tor-socks5.exe")), fx.MARKER)
                # каждый redirect-hop сделан реальным вызовом mock (журнал)
                hops = [r["uri"] for r in self.ps_log(ctx)
                        if r["fn"] == "Invoke-WebRequest"]
                self.assertIn(self.cdn("archive"), hops)
                self.assertIn(self.cdn("checksum"), hops)

    def test_redirects_negatives(self):
        a_url, s_url = self.asset_urls()
        github_next = "https://github.com/%s/%s/releases/download/%s/%s" % (
            fx.OWNER, fx.REPO, fx.MOCK_TAG, self.ARCHIVE_NAME)
        cases = {
            "non-https": "http://release-assets.githubusercontent.com/a",
            "userinfo": "https://user:pw@release-assets.githubusercontent.com/a",
            "port": "https://release-assets.githubusercontent.com:8443/a",
            "foreign-host": "https://evil.example/a",
            "changed-github-path": github_next.replace(self.ARCHIVE_NAME, "other"),
            "loop-10-plus": None,      # особый случай ниже
            "missing-location": None,  # особый случай ниже
        }
        for label, location in cases.items():
            for engine in self.for_each_engine():
                with self.subTest(case=label, engine=engine):
                    if label == "missing-location":
                        redirects = [{"status": 302, "location": None,
                                      "shape": "ps51"}]
                    elif label == "loop-10-plus":
                        redirects = [{"status": 302, "location": github_next,
                                      "shape": "ps51"}] * 12
                    else:
                        redirects = [{"status": 302, "location": location,
                                      "shape": "ps51"}]
                    downloads = {a_url: {"file": self.area.file(
                                             "dl/x" + label, b""),
                                         "redirects": redirects},
                                 s_url: {"file": self.area.file(
                                     "dl/y" + label, b""), "redirects": []}}
                    ctx = self.build(downloads=downloads)
                    dest = self.area.subdir("dest")
                    p = self.ps_run(ctx, dest, engine=engine)
                    self.assertNotEqual(p.returncode, 0)
                    uris = [r["uri"] for r in self.ps_log(ctx)
                            if r["fn"] == "Invoke-WebRequest"]
                    if label == "loop-10-plus":
                        # граница: максимум начальный вызов + 10 hop'ов
                        # (hop>10 — Fail); вся цепочка — легальный URL,
                        # checksum не качается
                        self.assertEqual(len(uris), 11)
                        self.assertTrue(all(u == a_url for u in uris))
                        self.assertNotIn(s_url, uris)
                        continue
                    # РОВНО ожидаемый достигнутый префикс: единственный вызов —
                    # начальный download URL; forbidden hop mock'ом НЕ вызван
                    # (install.ps1 отвергает Location до вызова; журнал пишется
                    # mock'ом ДО его собственной ошибки, так что «не вызван»
                    # здесь — факт, а не молчание лога)
                    self.assertEqual(uris, [a_url])
                    forbidden = location if location else None
                    if forbidden:
                        self.assertNotIn(forbidden, uris)
                # missing-location: первый request зафиксирован в журнале —
                # ассерт выше (uris == [a_url]) это и проверяет

    # --- checksum-файл (PS-парсер) ----------------------------------------

    def test_checksum_positive_forms(self):
        # Windows-формы: '  ' (2 пробела), ' *', uppercase hex,
        # LF / CRLF / без финального LF — все ДОПУСТИМЫ; digest — от реального zip
        ctx0 = self.build()
        digest = fx.sha256_hex(fx.file_bytes(ctx0["archive_path"]))
        forms = [
            fx.checksum_text(digest, self.ARCHIVE_NAME),                       # '  ' + LF
            fx.checksum_text(digest, self.ARCHIVE_NAME, eol=""),               # '  ' без LF
            fx.checksum_text(digest, self.ARCHIVE_NAME, sep=" *"),             # ' *' + LF
            fx.checksum_text(digest, self.ARCHIVE_NAME, sep=" *", eol=""),     # ' *' без LF
            fx.checksum_text(digest, self.ARCHIVE_NAME, upper=True),           # HEX
            fx.checksum_text(digest, self.ARCHIVE_NAME, sep=" *", eol="\r\n"),# CRLF
        ]
        for i, data in enumerate(forms):
            for engine in self.for_each_engine():
                with self.subTest(form=i, engine=engine):
                    ctx = self.build(checksum=data.encode("ascii"))
                    dest = self.area.subdir("cf%d-%s" % (i, engine))
                    p = self.ps_run(ctx, dest, engine=engine)
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                    self.assertEqual(fx.file_bytes(
                        os.path.join(dest, "tor-socks5.exe")), fx.MARKER)

    def test_checksum_variants(self):
        # digest — от реального zip, который собирает build()
        ctx0 = self.build()
        digest = fx.sha256_hex(fx.file_bytes(ctx0["archive_path"]))
        good = fx.checksum_text(digest, self.ARCHIVE_NAME)
        bad = [
            b"",
            fx.checksum_text("0" * 64, self.ARCHIVE_NAME).encode(),   # wronghash
            fx.checksum_text(digest, "other.zip").encode(),
            (good.rstrip("\n") + "\r").encode(),                       # bare CR
            (good + "\n").encode(),                                    # blankline
            ("z" * 64 + "  " + self.ARCHIVE_NAME + "\n").encode(),     # not hex
        ]
        for i, data in enumerate([good.encode()] + bad):
            ok = i == 0
            for engine in self.for_each_engine():
                with self.subTest(variant=i, engine=engine):
                    ctx = self.build(checksum=data)
                    dest = self.area.subdir("dest%d-%s" % (i, engine))
                    exe = os.path.join(dest, "tor-socks5.exe")
                    with open(exe, "wb") as f:
                        f.write(fx.MARKER_OLD)
                    p = self.ps_run(ctx, dest, engine=engine)
                    self.assertEqual(p.returncode, 0 if ok else 1, p.stdout)
                    if not ok:
                        self.assertEqual(fx.file_bytes(exe), fx.MARKER_OLD)

    # --- zip-контейнер -----------------------------------------------------

    def test_zip_entries(self):
        # sentinel ПОД НАШИМ tempRoot: traversal/absolute entry указывает сюда;
        # ассерт — именно этот путь не изменён
        esc = self.area.subdir("zip-escape-sentinel")
        abs_name = os.path.join(esc, "evil.exe")
        cases = [
            ("windows-type0-0600-valid",
             [{"name": "tor-socks5.exe", "external_attr": 0o600 << 16}], True),
            ("missing-expected-name",
             [{"name": "other.exe"}], False),
            ("traversal-escape",
             [{"name": "../zip-escape-sentinel/evil.exe"}], False),
            ("absolute-path",
             [{"name": abs_name}], False),
            ("duplicate-entry",
             [{"name": "tor-socks5.exe"}, {"name": "tor-socks5.exe"}], False),
            ("extra-entry",
             [{"name": "tor-socks5.exe"}, {"name": "notes.txt"}], False),
            ("dos-dir-entry",
             [{"name": "tor-socks5.exe", "external_attr": 0x10}], False),
            ("symlink-entry",
             [{"name": "tor-socks5.exe", "external_attr": 0o120777 << 16}], False),
            ("empty-payload",
             [{"name": "tor-socks5.exe", "data": b""}], False),
        ]
        for i, (label, entries, ok) in enumerate(cases):
            for engine in self.for_each_engine():
                with self.subTest(case=label, engine=engine):
                    archive = self.area.file("z%d.zip" % i, b"")
                    fx.make_zip(archive, entries)
                    a_url, s_url = self.asset_urls()
                    sum_path = self.area.file(
                        "z%d.sha256" % i,
                        fx.checksum_text(fx.sha256_hex(fx.file_bytes(archive)),
                                         self.ARCHIVE_NAME).encode("ascii"))
                    downloads = {a_url: {"file": archive, "redirects": []},
                                 s_url: {"file": sum_path, "redirects": []}}
                    ctx = self.build(downloads=downloads)
                    dest = self.area.subdir("d%d-%s" % (i, engine))
                    exe = os.path.join(dest, "tor-socks5.exe")
                    with open(exe, "wb") as f:
                        f.write(fx.MARKER_OLD)
                    p = self.ps_run(ctx, dest, engine=engine)
                    self.assertEqual(p.returncode, 0 if ok else 1, p.stdout)
                    # traversal/absolute цель — под НАШИМ tempRoot: не изменена
                    self.assertEqual(os.listdir(esc), [])
                    if ok:
                        self.assertEqual(fx.file_bytes(exe), fx.MARKER)
                    else:
                        # старый файл не тронут, staging удалён
                        self.assertEqual(fx.file_bytes(exe), fx.MARKER_OLD)
                        self.assertEqual(
                            [n for n in os.listdir(dest)
                             if ".tmp-" in n], [])

    # --- файловые отказы: collision / rollback -----------------------------

    def test_temp_dir_collision_new_item_fails_foreign_kept(self):
        # НАСТОЯЩАЯ temp-коллизия: Join-Path mock возвращает СУЩЕСТВУЮЩИЙ
        # чужой каталог для child 'tor-socks5-<GUID>' — настоящий New-Item
        # без -Force обязан отказаться; finally НЕ удаляет чужое содержимое
        for engine in self.for_each_engine():
            with self.subTest(engine=engine):
                ctx = self.build()
                foreign = self.area.subdir("foreign-temp-" + engine)
                keep = os.path.join(foreign, "keep-marker.txt")
                with open(keep, "wb") as f:
                    f.write(b"foreign temp")
                pre = os.path.join(foreign, "pre-existing.txt")
                with open(pre, "wb") as f:
                    f.write(b"was here")
                ctx2 = self.build(joinpath_mode="temp-collision",
                                  joinpath_path=foreign)
                p = self.ps_run(ctx2, self.area.subdir("dest"), engine=engine)
                self.assertNotEqual(p.returncode, 0)
                # чужое содержимое НЕ тронуто, новых записей не появилось
                self.assertEqual(fx.file_bytes(keep), b"foreign temp")
                self.assertEqual(fx.file_bytes(pre), b"was here")
                self.assertEqual(sorted(os.listdir(foreign)),
                                 ["keep-marker.txt", "pre-existing.txt"])
                # загрузки не было: latest API достигнут, downloads НЕТ
                log = self.ps_log(ctx2)
                self.assertEqual(
                    len([r for r in log if r["fn"] == "Invoke-RestMethod"]), 1)
                self.assertEqual(
                    [r for r in log if r["fn"] == "Invoke-WebRequest"], [])

    def test_candidate_collision_foreign_file_kept(self):
        for engine in self.for_each_engine():
            with self.subTest(engine=engine):
                ctx = self.build()
                dest = self.area.subdir("dest")
                collision = os.path.join(dest, "foreign.tmp-file")
                with open(collision, "wb") as f:
                    f.write(b"foreign data")
                ctx2 = self.build(joinpath_mode="collision",
                                  joinpath_path=collision)
                p = self.ps_run(ctx2, dest, engine=engine)
                self.assertNotEqual(p.returncode, 0)
                # чужой pre-existing файл НЕ удалён cleanup'ом
                self.assertEqual(fx.file_bytes(collision), b"foreign data")

    def test_failed_final_move_rollback_restores_old(self):
        for engine in self.for_each_engine():
            with self.subTest(engine=engine, mode="delete-candidate"):
                ctx = self.build(joinpath_mode="delete-candidate")
                dest = self.area.subdir("dest")
                exe = os.path.join(dest, "tor-socks5.exe")
                with open(exe, "wb") as f:
                    f.write(fx.MARKER_OLD)
                p = self.ps_run(ctx, dest, engine=engine)
                self.assertNotEqual(p.returncode, 0)
                # rollback: старый бинарник восстановлен byte-identical,
                # backup и staging не остались
                self.assertEqual(fx.file_bytes(exe), fx.MARKER_OLD)
                self.assertEqual([n for n in os.listdir(dest)
                                  if ".old." in n or ".tmp-" in n], [])
            with self.subTest(engine=engine, mode="fail-backup"):
                ctx = self.build(joinpath_mode="fail-backup")
                dest = self.area.subdir("dest2")
                exe = os.path.join(dest, "tor-socks5.exe")
                with open(exe, "wb") as f:
                    f.write(fx.MARKER_OLD)
                p = self.ps_run(ctx, dest, engine=engine)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(fx.file_bytes(exe), fx.MARKER_OLD)

    def test_reparse_point_old_backup_skipped(self):
        # reparse point (junction) в НАШЕМ reserved namespace
        # (tor-socks5.exe.old.<32 hex>) НЕ удаляется как обычный файл —
        # installation обязана завершиться успешно, junction и его цель целы.
        # Создание junction не требует привилегий — сбой создания = ошибка теста.
        import _winapi
        for engine in self.for_each_engine():
            with self.subTest(engine=engine):
                ctx = self.build()
                dest = self.area.subdir("dest-" + engine)
                sentinel_dir = self.area.subdir("reparse-target-" + engine)
                keep = os.path.join(sentinel_dir, "keep.txt")
                with open(keep, "wb") as f:
                    f.write(b"keep")
                junction = os.path.join(
                    dest, "tor-socks5.exe.old." + "b" * 32)
                _winapi.CreateJunction(sentinel_dir, junction)
                p = self.ps_run(ctx, dest, engine=engine)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertTrue(os.path.exists(junction))
                self.assertEqual(fx.file_bytes(keep), b"keep")
                self.assertEqual(fx.file_bytes(
                    os.path.join(dest, "tor-socks5.exe")), fx.MARKER)

    def test_file_symlink_old_backup_skipped(self):
        # НАСТОЯЩИЙ ФАЙЛОВЫЙ reparse point (symlink, не junction) в reserved
        # namespace tor-socks5.exe.old.<32hex>: EnumerateFiles его ВИДИТ, и
        # ветка FileAttributes.ReparsePoint обязана сработать для ФАЙЛА.
        # Fixture создаёт python (os.symlink), это право CI-windows-runner
        # (админ), а не installer ACL: сбой создания = ошибка теста (не skip).
        targets = ("c1" * 16, "c2" * 16)   # уникальные hex на каждый движок
        for idx, engine in enumerate(self.for_each_engine()):
            with self.subTest(engine=engine):
                ctx = self.build()
                dest = self.area.subdir("dest-fs-" + engine)
                target = self.area.file("symlink-target-" + engine,
                                        b"link-target-data")
                link = os.path.join(dest,
                                    "tor-socks5.exe.old." + targets[idx])
                os.symlink(target, link)
                p = self.ps_run(ctx, dest, engine=engine)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                # link не удалён, данные по цели не изменены, установка ок
                self.assertTrue(os.path.islink(link))
                self.assertEqual(fx.file_bytes(target), b"link-target-data")
                self.assertEqual(fx.file_bytes(
                    os.path.join(dest, "tor-socks5.exe")), fx.MARKER)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + sys.argv[1:], verbosity=2)
