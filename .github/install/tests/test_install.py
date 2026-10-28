# -*- coding: utf-8 -*-
"""Offline-тесты НАСТОЯЩИХ установщиков (.github/install/install.sh и
install.ps1) как дочерних процессов.

Транспорт подменяется ТОЛЬКО в harness:
  - sh: stub'ы curl/uname/sysctl в начале PATH (curl_mock.py), урезанный
    PATH с реальными системными утилитами и выбранными hash-утилитами;
  - PowerShell: powershell_mock.ps1 определяет mock Invoke-RestMethod /
    Invoke-WebRequest (и в узких сценариях Join-Path) и ПОЛНОСТЬЮ вызывает
    настоящий install.ps1.

Запуск (Python -I, изоляция sys.path, helpers подключаются явно):
  python3 -I .github/install/tests/test_install.py ShInstallTests      # ubuntu/macos
  python  -I .github/install/tests/test_install.py PowerShellInstallTests  # windows

Тег latest в mock (v9.8.7) заведомо не совпадает с Cargo-тегами проекта.
Payload-байты — маркеры, НИКОГДА не исполняются. Все subprocess — с таймаутом.
"""

import json
import os
import shutil
import stat
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixtures as fx

SH = shutil.which("sh")
PS_ENGINES = [e for e in ("powershell", "pwsh") if shutil.which(e)]
PS_WRAPPER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "powershell_mock.ps1")


def read_log(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8-sig") as f:
        return [json.loads(line) for line in f if line.strip()]


class ShInstallTests(unittest.TestCase):
    """install.sh: POSIX sh, ubuntu-latest и macos-latest."""

    def setUp(self):
        self.area = fx.TempArea(self)
        self.tmp_root = self.area.subdir("tmp")   # TMPDIR дочернего процесса
        self._build_n = 0                          # счётчик уникальных namespace

    # --- helpers -------------------------------------------------------

    def build(self, os_name="Linux", machine="x86_64", sysctl_arm="0",
              hash_tools=None, member=None, checksum=None,
              scenario_kw=None, archive_kw=None, libc="gnu"):
        if hash_tools is None:
            # macOS runners не имеют coreutils: берём то, что реально есть
            hash_tools = (("sha256sum",) if shutil.which("sha256sum")
                          else ("shasum",))
        # Неизвестная ОС (SunOS и т.п.): ассет-placeholder — валидный Linux,
        # платформу отвергает САМ installer (stub uname) ДО сети. Ошибку
        # placeholder-выбора в Python НЕ маскируем.
        target = {"Linux": "%s-unknown-linux-musl" %
                  ("aarch64" if machine in ("aarch64", "arm64") else "x86_64"),
                  "Darwin": "aarch64-apple-darwin" if
                  (machine in ("arm64", "aarch64") or sysctl_arm == "1")
                  else "x86_64-apple-darwin"}.get(os_name) \
            or "x86_64-unknown-linux-gnu"
        scenario_kw = scenario_kw or {}
        latest_url = scenario_kw.get("latest_final_url", "https://github.com/%s/%s/releases/tag/%s" %
                                    (fx.OWNER, fx.REPO, fx.MOCK_TAG))
        tag = latest_url.rsplit("/", 1)[-1]
        legacy = (os_name == "Linux" and machine in ("x86_64", "amd64")
                  and libc == "gnu" and tag == "v0.2.0")
        if legacy:
            target = "x86_64-unknown-linux-gnu"
        archive_name = "tor-socks5-%s-%s.tar.gz" % (tag, target)
        # Каждый build — НОВЫЙ уникальный namespace (bin/bin-data/dl/home/log):
        # symlinks и fixture files/логи не переиспользуются между сценариями.
        self._build_n += 1
        ns = self.area.subarea("build-%d" % self._build_n)
        dl = ns.subdir("dl")
        archive_path = os.path.join(dl, archive_name)
        if member is None:
            fx.make_tar_gz(archive_path, "tor-socks5", **(archive_kw or {}))
        else:
            fx.make_tar_gz_members(archive_path, member)
        with open(archive_path, "rb") as f:
            archive_bytes = f.read()
        if checksum is None:
            checksum = fx.checksum_text(fx.sha256_hex(archive_bytes),
                                        archive_name).encode("ascii")
        sum_path = ns.file("dl/%s.sha256" % archive_name,
                           checksum if isinstance(checksum, bytes)
                           else checksum.encode("utf-8"))
        bin_dir, scen, log = fx.make_fakebin(
            ns, "bin", os_name=os_name, machine=machine,
            sysctl_arm=sysctl_arm, hash_tools=hash_tools, libc=libc)
        kw = {"files": {archive_name: archive_path,
                        archive_name + ".sha256": sum_path}}
        kw.update(scenario_kw or {})
        fx.update_curl_scenario(scen, **kw)
        home = ns.subdir("home")
        # curl_mock требует ОБЕ переменные — wiring явный, без KeyError-молчаний
        env = fx.restricted_env(bin_dir, {"TMPDIR": self.tmp_root, "HOME": home,
                                          "TORSOCKS_CURL_SCENARIO": scen,
                                          "TORSOCKS_CURL_LOG": log})
        return {"bin_dir": bin_dir, "log": log, "env": env, "home": home,
                "archive_name": archive_name, "target": target,
                "archive_bytes": archive_bytes}

    def install(self, ctx, *args, cwd=None):
        return fx.run_cmd([SH, fx.INSTALL_SH] + list(args), env=ctx["env"],
                          cwd=cwd or fx.REPO_ROOT)

    def curl_urls(self, ctx):
        return [r["url"] for r in fx.curl_log(ctx["log"])]

    def assert_installed(self, path, data=fx.MARKER, mode=0o755):
        self.assertEqual(fx.file_bytes(path), data)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), mode)

    # --- транспорт и happy path ----------------------------------------

    def test_happy_default_dir_and_real_requests(self):
        ctx = self.build()
        p = self.install(ctx)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        dest = os.path.join(ctx["home"], ".local", "bin", "tor-socks5")
        self.assert_installed(dest)
        # фактические запросы: ровно 3, правильные URI и proto-флаги
        recs = fx.curl_log(ctx["log"])
        self.assertEqual(len(recs), 3)
        base = "https://github.com/%s/%s/releases" % (fx.OWNER, fx.REPO)
        self.assertEqual(recs[0]["url"], base + "/latest")
        self.assertEqual(recs[1]["url"],
                         base + "/download/%s/%s" % (fx.MOCK_TAG, ctx["archive_name"]))
        self.assertEqual(recs[2]["url"], recs[1]["url"] + ".sha256")
        self.assertTrue(all(r["proto_ok"] for r in recs))
        # temp-каталоги установщика удалены из нашего TMPDIR
        self.assertEqual([n for n in os.listdir(self.tmp_root)
                          if n.startswith("tor-socks5.")], [])
        self.assertEqual([n for n in os.listdir(os.path.dirname(dest))
                          if n.startswith(".tor-socks5.")], [])

    def test_foreign_tmpdir_entry_preserved(self):
        # cleanup install.sh удаляет ТОЛЬКО СВОЙ mktemp-каталог; чужие записи
        # в TMPDIR (в т.ч. с похожим префиксом) не затрагиваются.
        # ВАЖНО: это НЕ actual collision — mktemp создаёт СВОЙ каталог;
        # реальная коллизия на sh невозможна без сломанного контракта ОС.
        ctx = self.build()
        foreign = os.path.join(self.tmp_root, "tor-socks5.foreign-collision")
        os.makedirs(foreign)
        with open(os.path.join(foreign, "keep"), "wb") as f:
            f.write(b"foreign")
        p = self.install(ctx)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        self.assertEqual(fx.file_bytes(os.path.join(foreign, "keep")),
                         b"foreign")

    def test_tmpdir_is_file_real_mktemp_fails(self):
        # TMPDIR-файл мешает mktemp после получения latest, но до скачивания assets.
        ctx = self.build()
        blocker = self.area.file("tmpdir-blocker", b"not a directory")
        ctx["env"]["TMPDIR"] = blocker
        p = self.install(ctx)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.curl_urls(ctx), [
            "https://github.com/%s/%s/releases/latest" % (fx.OWNER, fx.REPO)])
        self.assertEqual(fx.file_bytes(blocker), b"not a directory")

    def test_override_dir_with_spaces_and_brackets(self):
        ctx = self.build()
        dest_dir = os.path.join(self.area.path, "my dir[0]x")
        p = self.install(ctx, "--install-dir", dest_dir)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assert_installed(os.path.join(dest_dir, "tor-socks5"))

    def test_relative_and_leading_dash_dir(self):
        ctx = self.build()
        workdir = self.area.subdir("work")
        p = self.install(ctx, "--install-dir", "reldir", cwd=workdir)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assert_installed(os.path.join(workdir, "reldir", "tor-socks5"))
        ctx2 = self.build()
        p = self.install(ctx2, "--install-dir", "-dashdir", cwd=workdir)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assert_installed(os.path.join(workdir, "-dashdir", "tor-socks5"))

    def test_existing_inactive_binary_replaced_unrelated_kept(self):
        ctx = self.build()
        dest_dir = self.area.subdir("dest")
        old = os.path.join(dest_dir, "tor-socks5")
        with open(old, "wb") as f:
            f.write(fx.MARKER_OLD)
        os.chmod(old, 0o600)
        conf = os.path.join(dest_dir, "tor-socks5.conf")
        with open(conf, "wb") as f:
            f.write(b"key=value\n")
        p = self.install(ctx, "--install-dir", dest_dir)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assert_installed(old)
        self.assertEqual(fx.file_bytes(conf), b"key=value\n")

    # --- платформа/arch: fail ДО скачивания ----------------------------

    def test_wrong_platform_fails_before_download(self):
        for os_name, machine in (("SunOS", "x86_64"), ("Linux", "i686"),
                                 ("Darwin", "i386")):
            with self.subTest(platform="%s/%s" % (os_name, machine)):
                ctx = self.build(os_name=os_name, machine=machine)
                p = self.install(ctx)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(self.curl_urls(ctx), [])

    def test_target_selection(self):
        cases = [
            # (os, machine, sysctl, libc, expected archive target)
            ("Linux", "x86_64", "0", "gnu", "x86_64-unknown-linux-musl"),
            ("Linux", "amd64", "0", "musl", "x86_64-unknown-linux-musl"),
            ("Linux", "aarch64", "0", "gnu", "aarch64-unknown-linux-musl"),
            ("Linux", "arm64", "0", "musl", "aarch64-unknown-linux-musl"),
            ("Darwin", "x86_64", "0", "gnu", "x86_64-apple-darwin"),
            ("Darwin", "x86_64", "1", "gnu", "aarch64-apple-darwin"),
            ("Darwin", "arm64", "0", "gnu", "aarch64-apple-darwin"),
        ]
        for os_name, machine, sysctl, libc, target in cases:
            with self.subTest(target=target):
                ctx = self.build(os_name=os_name, machine=machine,
                                 sysctl_arm=sysctl, libc=libc)
                p = self.install(ctx)
                self.assertEqual(p.returncode, 0, p.stderr)
                urls = self.curl_urls(ctx)
                self.assertEqual(len(urls), 3)
                self.assertEqual(urls[1], "https://github.com/%s/%s/releases/download/%s/tor-socks5-%s-%s.tar.gz" %
                                 (fx.OWNER, fx.REPO, fx.MOCK_TAG, fx.MOCK_TAG, target))
                self.assertEqual(urls[2], urls[1] + ".sha256")
                # tar-архив под каждый target собирается с именем члена
                # 'tor-socks5', поэтому установка успешна
                self.assert_installed(
                    os.path.join(ctx["home"], ".local", "bin", "tor-socks5"))

        cases = [
            ("Linux", "x86_64", "gnu", "x86_64-unknown-linux-musl"),
            ("Linux", "x86_64", "musl", "x86_64-unknown-linux-musl"),
            ("Linux", "amd64", "musl", "x86_64-unknown-linux-musl"),
            ("Linux", "aarch64", "gnu", "aarch64-unknown-linux-musl"),
            ("Linux", "aarch64", "musl", "aarch64-unknown-linux-musl"),
            ("Linux", "arm64", "musl", "aarch64-unknown-linux-musl"),
        ]
        for os_name, machine, libc, target in cases:
            with self.subTest(platform=(machine, libc)):
                ctx = self.build(os_name=os_name, machine=machine, libc=libc)
                p = self.install(ctx)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(self.curl_urls(ctx)[1],
                                 "https://github.com/%s/%s/releases/download/%s/tor-socks5-%s-%s.tar.gz" %
                                 (fx.OWNER, fx.REPO, fx.MOCK_TAG, fx.MOCK_TAG, target))

        for machine, libc in (("x86_64", "unknown"), ("aarch64", "unknown")):
            ctx = self.build(machine=machine, libc=libc)
            p = self.install(ctx)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("-unknown-linux-musl", self.curl_urls(ctx)[1])

    def test_linux_conflicting_libc_prefers_musl(self):
        ctx = self.build(machine="aarch64", libc="mixed",
                         member=[fx.tar_member("tor-socks5", b"aarch64-musl-payload")])
        p = self.install(ctx)
        self.assertEqual(p.returncode, 0, p.stderr)
        expected_name = "tor-socks5-%s-aarch64-unknown-linux-musl.tar.gz" % fx.MOCK_TAG
        self.assertEqual(ctx["target"], "aarch64-unknown-linux-musl")
        self.assertEqual(ctx["archive_name"], expected_name)
        self.assertEqual(self.curl_urls(ctx)[1],
                         "https://github.com/%s/%s/releases/download/%s/%s" %
                         (fx.OWNER, fx.REPO, fx.MOCK_TAG, expected_name))
        dest = os.path.join(ctx["home"], ".local", "bin", "tor-socks5")
        self.assert_installed(dest, b"aarch64-musl-payload")

    def test_legacy_exact_tag_gnu_asset(self):
        tag_url = "https://github.com/%s/%s/releases/tag/v0.2.0" % (fx.OWNER, fx.REPO)
        ctx = self.build(machine="x86_64", libc="gnu",
                         scenario_kw={"latest_final_url": tag_url})
        p = self.install(ctx)
        self.assertEqual(p.returncode, 0, p.stderr)
        archive = "tor-socks5-v0.2.0-x86_64-unknown-linux-gnu.tar.gz"
        urls = self.curl_urls(ctx)
        base = "https://github.com/%s/%s/releases/download/v0.2.0/" % (fx.OWNER, fx.REPO)
        self.assertEqual(urls[1:], [base + archive, base + archive + ".sha256"])
        self.assert_installed(os.path.join(ctx["home"], ".local", "bin", "tor-socks5"))

    def test_legacy_rejects_unconfirmed_libc_and_arm_preserving_destination(self):
        tag_url = "https://github.com/%s/%s/releases/tag/v0.2.0" % (fx.OWNER, fx.REPO)
        for machine, libc in (("x86_64", "musl"), ("x86_64", "unknown"),
                              ("aarch64", "gnu"), ("aarch64", "unknown")):
            with self.subTest(machine=machine, libc=libc):
                ctx = self.build(machine=machine, libc=libc,
                                 scenario_kw={"latest_final_url": tag_url})
                dest_dir = self.area.subdir("legacy-%s-%s" % (machine, libc))
                old = os.path.join(dest_dir, "tor-socks5")
                with open(old, "wb") as f:
                    f.write(fx.MARKER_OLD)
                p = self.install(ctx, "--install-dir", dest_dir)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(fx.file_bytes(old), fx.MARKER_OLD)
                self.assertEqual(len(self.curl_urls(ctx)), 1)
                self.assertEqual(self.curl_urls(ctx)[0],
                                 "https://github.com/%s/%s/releases/latest" %
                                 (fx.OWNER, fx.REPO))
                self.assertIn("v0.2.0", p.stderr.decode("utf-8", "replace"))

    # --- latest tag: негативы -------------------------------------------

    def test_latest_url_negatives(self):
        good = "https://github.com/%s/%s/releases/tag/%s" % (fx.OWNER, fx.REPO,
                                                             fx.MOCK_TAG)
        bad_tag = "https://github.com/%s/%s/releases/tag/v0.2.0%%2Fbad" % (fx.OWNER, fx.REPO)
        for kw in ({"latest_final_url": "https://evil.example/somewhere"},
                   {"latest_final_url": good.replace(fx.MOCK_TAG, "..%2Fx")},
                   {"latest_final_url": bad_tag},
                   {"latest_exit": 7}):
            with self.subTest(kw=kw):
                ctx = self.build(scenario_kw=kw)
                p = self.install(ctx)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(len(fx.curl_log(ctx["log"])), 1)
                self.assertEqual(self.curl_urls(ctx), [
                    "https://github.com/%s/%s/releases/latest" % (fx.OWNER, fx.REPO)])

    def test_legacy_download_failures_do_not_fallback_or_replace(self):
        tag_url = "https://github.com/%s/%s/releases/tag/v0.2.0" % (fx.OWNER, fx.REPO)
        archive = "tor-socks5-v0.2.0-x86_64-unknown-linux-gnu.tar.gz"
        for failure in ({"fail_download": archive},
                        {"fail_status": {archive: 404}},
                        {"fail_status": {archive + ".sha256": 404}},
                        {"fail_exit": {archive + ".sha256": 35}}):
            with self.subTest(failure=failure):
                ctx = self.build(machine="x86_64", libc="gnu",
                                 scenario_kw={"latest_final_url": tag_url, **failure})
                dest_dir = self.area.subdir("legacy-failure-%d" % self._build_n)
                old = os.path.join(dest_dir, "tor-socks5")
                with open(old, "wb") as f:
                    f.write(fx.MARKER_OLD)
                p = self.install(ctx, "--install-dir", dest_dir)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(fx.file_bytes(old), fx.MARKER_OLD)
                urls = self.curl_urls(ctx)
                expected_calls = 2 if (failure.get("fail_download") == archive or
                                        failure.get("fail_status", {}).get(archive) or
                                        failure.get("fail_exit", {}).get(archive)) else 3
                self.assertEqual(len(urls), expected_calls)
                self.assertEqual(urls[1], "https://github.com/%s/%s/releases/download/v0.2.0/%s" %
                                 (fx.OWNER, fx.REPO, archive))
                if expected_calls == 3:
                    self.assertEqual(urls[2], urls[1] + ".sha256")
                self.assertEqual(urls[0], "https://github.com/%s/%s/releases/latest" %
                                 (fx.OWNER, fx.REPO))
                self.assertTrue(all(r["proto_ok"] for r in fx.curl_log(ctx["log"])))

    def test_legacy_checksum_malformed_or_mismatched_preserves_target(self):
        tag_url = "https://github.com/%s/%s/releases/tag/v0.2.0" % (fx.OWNER, fx.REPO)
        for checksum in (b"not-a-checksum\n",
                         b"0" * 64 + b"  wrong-name\n",
                         b"0" * 64 + b"  " + b"tor-socks5-v0.2.0-x86_64-unknown-linux-gnu.tar.gz\n"):
            with self.subTest(checksum=checksum):
                ctx = self.build(machine="x86_64", libc="gnu", checksum=checksum,
                                 scenario_kw={"latest_final_url": tag_url})
                dest_dir = self.area.subdir("legacy-bad-sum-%d" % self._build_n)
                old = os.path.join(dest_dir, "tor-socks5")
                with open(old, "wb") as f:
                    f.write(fx.MARKER_OLD)
                p = self.install(ctx, "--install-dir", dest_dir)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(fx.file_bytes(old), fx.MARKER_OLD)
                urls = self.curl_urls(ctx)
                self.assertEqual(len(urls), 3)
                self.assertEqual(urls[1], "https://github.com/%s/%s/releases/download/v0.2.0/%s" %
                                 (fx.OWNER, fx.REPO, ctx["archive_name"]))
                self.assertEqual(urls[2], urls[1] + ".sha256")
                self.assertTrue(all(r["proto_ok"] for r in fx.curl_log(ctx["log"])))

    def test_latest_transport_failure_preserves_existing_target(self):
        for scenario in ({"latest_exit": 35},
                         {"latest_final_url": "https://github.com/%s/%s/releases/tag/v0.2.0" %
                          (fx.OWNER, fx.REPO),
                          "fail_download": "tor-socks5-v0.2.0-x86_64-unknown-linux-gnu.tar.gz"}):
            ctx = self.build(machine="x86_64", libc="gnu", scenario_kw=scenario)
            dest_dir = self.area.subdir("transport-failure-%d" % self._build_n)
            old = os.path.join(dest_dir, "tor-socks5")
            with open(old, "wb") as f:
                f.write(fx.MARKER_OLD)
            p = self.install(ctx, "--install-dir", dest_dir)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(fx.file_bytes(old), fx.MARKER_OLD)
            self.assertTrue(all(r["proto_ok"] for r in fx.curl_log(ctx["log"])))

    # --- checksum-файл: все допустимые и недопустимые формы -------------

    def test_checksum_valid_variants(self):
        ctx0 = self.build()
        digest = fx.sha256_hex(ctx0["archive_bytes"])
        variants = [
            fx.checksum_text(digest, ctx0["archive_name"]),                       # '  ' + LF
            fx.checksum_text(digest, ctx0["archive_name"], eol=""),               # без LF
            fx.checksum_text(digest, ctx0["archive_name"], sep=" *"),             # ' *' + LF
            fx.checksum_text(digest, ctx0["archive_name"], sep=" *", eol=""),
            fx.checksum_text(digest, ctx0["archive_name"], upper=True),           # HEX
            fx.checksum_text(digest, ctx0["archive_name"], sep=" *",
                             eol="\r\n"),                                          # CRLF
        ]
        for i, data in enumerate(variants):
            with self.subTest(variant=i):
                ctx = self.build(checksum=data.encode("ascii"))
                p = self.install(ctx, "--install-dir",
                                 os.path.join(self.area.path, "dest%d" % i))
                self.assertEqual(p.returncode, 0, p.stderr)

    def test_checksum_invalid_variants(self):
        ctx0 = self.build()
        digest = fx.sha256_hex(ctx0["archive_bytes"])
        name = ctx0["archive_name"]
        wrong = "0" * 64
        bad = [
            b"",                                                  # empty
            fx.checksum_text(wrong, name).encode(),               # wronghash
            (fx.checksum_text(digest, "other.tar.gz").encode()),
            fx.checksum_text("0" * 64, name).encode(),
            (digest + "  " + name + "\r").encode(),               # bare CR
            (digest + "  " + name + "\n\n").encode(),             # extra blankline
            (digest + "  " + name + "\n" + digest + "  x\n").encode(),  # вторая строка
            (digest[:63] + "  " + name + "\n").encode(),          # malformed hex
            ("z" * 64 + "  " + name + "\n").encode(),             # не hex
            (digest + "\t " + name + "\n").encode(),              # не те разделители
        ]
        for i, data in enumerate(bad):
            with self.subTest(variant=i):
                dest_dir = self.area.subdir("dest%d" % i)
                old = os.path.join(dest_dir, "tor-socks5")
                with open(old, "wb") as f:
                    f.write(fx.MARKER_OLD)
                ctx = self.build(checksum=data)
                p = self.install(ctx, "--install-dir", dest_dir)
                self.assertNotEqual(p.returncode, 0)
                # старый бинарник byte-identical, staging/temp удалены
                self.assertEqual(fx.file_bytes(old), fx.MARKER_OLD)
                self.assertEqual([n for n in os.listdir(dest_dir)
                                  if n.startswith(".tor-socks5.")], [])
                self.assertEqual([n for n in os.listdir(self.tmp_root)
                                  if n.startswith("tor-socks5.")], [])

    def test_sha_fallback_tools(self):
        for tools, ok in ((("sha256sum",), True), (("shasum",), True),
                          (("openssl",), True), ((), False)):
            # утилита отсутствует на этой ОС — комбинация неприменима
            if tools and shutil.which(tools[0]) is None:
                continue
            with self.subTest(tools=tools):
                ctx = self.build(hash_tools=tools)
                dest_dir = self.area.subdir("dest-" + "-".join(tools or ["none"]))
                p = self.install(ctx, "--install-dir", dest_dir)
                self.assertEqual(p.returncode, 0 if ok else 1,
                                 p.stderr + p.stdout)
                if ok:
                    self.assert_installed(os.path.join(dest_dir, "tor-socks5"))

    # --- безопасный архив -----------------------------------------------

    def test_safe_archive_members(self):
        import tarfile as tf
        symlink = [fx.tar_member("tor-socks5", ttype=tf.SYMTYPE,
                                 linkname="/etc/passwd")]
        hardlink = [fx.tar_member("tor-socks5", ttype=tf.LNKTYPE,
                                  linkname="/etc/passwd")]
        # chardev: devmajor/devminor выставляются на готовом TarInfo
        # (tar_member их не принимает)
        _dev_ti = fx.tar_member("tor-socks5", ttype=tf.CHRTYPE)[0]
        _dev_ti.devmajor, _dev_ti.devminor = 1, 3
        chardev = [(_dev_ti, None)]
        # sentinel ПОД НАШИМ tempRoot: traversal/absolute member указывает
        # сюда, ассерт — что именно этот путь не изменён
        esc = self.area.subdir("tar-escape-sentinel")
        cases = [
            ("positive-control", [fx.tar_member("tor-socks5")], True),
            ("duplicate-member", [fx.tar_member("tor-socks5"),
                                  fx.tar_member("tor-socks5")], False),
            ("extra-entry", [fx.tar_member("tor-socks5"),
                             fx.tar_member("README")], False),
            ("traversal", [fx.tar_member("../tar-escape-sentinel/evil")], False),
            ("absolute-path", [fx.tar_member(os.path.join(esc, "evil"))], False),
            ("symlink-member", symlink, False),
            ("hardlink-member", hardlink, False),
            ("chardev-member", chardev, False),
            ("wrong-name", [fx.tar_member("tor-socks5d")], False),
            ("dir-member", [fx.tar_member("tor-socks5", ttype=tf.DIRTYPE)], False),
            ("empty-payload", [fx.tar_member("tor-socks5", data=b"")], False),
        ]
        for i, (label, members, ok) in enumerate(cases):
            with self.subTest(case=label):
                ctx = self.build(member=members)
                sentinel_parent = self.area.subdir("sentinel%d" % i)
                sentinel = os.path.join(sentinel_parent, "keep.txt")
                with open(sentinel, "wb") as f:
                    f.write(b"keep")
                dest_dir = self.area.subdir("dest%d" % i)
                p = self.install(ctx, "--install-dir", dest_dir)
                self.assertEqual(p.returncode, 0 if ok else 1, p.stderr)
                # вне контролируемой зоны ничего не создано/не изменено
                self.assertEqual(os.listdir(sentinel_parent), ["keep.txt"])
                self.assertEqual(fx.file_bytes(sentinel), b"keep")
                self.assertEqual(os.listdir(esc), [])
                if ok:
                    self.assert_installed(os.path.join(dest_dir, "tor-socks5"))
                else:
                    self.assertEqual([n for n in os.listdir(dest_dir)
                                      if n.startswith(".tor-socks5.")], [])

    # --- отказы файловой системы ----------------------------------------

    def test_install_dir_is_file_fails_after_download(self):
        # валидация «существует и не каталог» выполняется только ПОСЛЕ
        # скачивания: curl для archive и .sha256 уже выполнен, temp-каталог
        # удалён trap'ом
        ctx = self.build()
        notdir = self.area.file("notadir", b"x")
        p = self.install(ctx, "--install-dir", notdir)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(len(self.curl_urls(ctx)), 3)
        self.assertEqual([n for n in os.listdir(self.tmp_root)
                          if n.startswith("tor-socks5.")], [])

    def test_destination_is_directory_fails_after_download(self):
        ctx = self.build()
        dest_dir = self.area.subdir("dest")
        os.makedirs(os.path.join(dest_dir, "tor-socks5"))
        p = self.install(ctx, "--install-dir", dest_dir)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(len(self.curl_urls(ctx)), 3)
        self.assertEqual([n for n in os.listdir(self.tmp_root)
                          if n.startswith("tor-socks5.")], [])

    def test_unwritable_destination_keeps_old(self):
        ctx = self.build()
        parent = self.area.subdir("ro")
        os.chmod(parent, 0o555)
        self.addCleanup(os.chmod, parent, 0o755)
        p = self.install(ctx, "--install-dir", os.path.join(parent, "bin"))
        self.assertNotEqual(p.returncode, 0)
        # скачивание состоялось, но установка не задела чужие области
        self.assertEqual(len(self.curl_urls(ctx)), 3)
        self.assertEqual([n for n in os.listdir(self.tmp_root)
                          if n.startswith("tor-socks5.")], [])


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
