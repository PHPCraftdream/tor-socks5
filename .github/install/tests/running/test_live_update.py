# -*- coding: utf-8 -*-
"""Live-update тесты НАСТОЯЩИХ установщиков с РЕАЛЬНО компилируемыми
фикстурами блокирующего процесса (running/blocking_app.c / .cs).

Отличие от test_install.py: payload — исполняемая фикстура, которая
РЕАЛЬНО запускается и отвечает по ASCII-протоколу READY/VERSION/version/exit.
Это позволяет проверить главные инварианты live-update:
  - Unix: установщик заменяет бинарник работающего процесса (rename поверх
    живого inode): PID и код старой версии сохраняются, canonical — новая.
  - Windows: работающий PE удерживает файл; install.ps1 переименовывает его
    в backup и кладёт candidate на canonical; backup живого процесса
    переживает установку и удаляется только после освобождения.

Компиляция происходит ТОЛЬКО здесь (setUpClass, только в CI):
  - Unix: системный cc/clang/gcc, C99, подстановка маркера версии;
  - Windows: Windows PowerShell 5.1 + running/compile_windows.ps1
    (Add-Type -> .NET Framework PE), отдельный child-хост на каждую
    компиляцию (кэш типов Add-Type в одном процессе не переиспользуется).

Мьютекс install.ps1 проверяется существующей фикстурой running/hold_mutex.ps1
(точное production-имя Global\\tor-socks5-install-<sha256>).

Запуск (Python -I, изоляция sys.path):
  python3 -I .github/install/tests/running/test_live_update.py ShLiveUpdateTests
  python  -I .github/install/tests/running/test_live_update.py WindowsLiveUpdateTests

Все subprocess — с таймаутом; сеть/GitHub не используются (transport mock'и
из tests/). Процессы останавливаются ТОЛЬКО через их собственный stdin
(exit/EOF) и известный Popen-PID; никакие образы/чужие PID не kill'ятся.
"""

import json
import os
import queue
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fixtures as fx

RUN_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCKING_C = os.path.join(RUN_DIR, "blocking_app.c")
BLOCKING_CS = os.path.join(RUN_DIR, "blocking_app.cs")
COMPILE_PS1 = os.path.join(RUN_DIR, "compile_windows.ps1")
HOLD_MUTEX_PS1 = os.path.join(RUN_DIR, "hold_mutex.ps1")
PS_WRAPPER = os.path.join(os.path.dirname(RUN_DIR), "powershell_mock.ps1")

# Маркеры версий фикстур: ASCII [A-Za-z0-9._-] (валидация compile_windows.ps1)
VERSION_OLD = "0.9.8-old"
VERSION_NEW = "0.9.9-new"

# Реальная платформа CI-раннера для fakebin (curl_mock scenario)
SH_OS_NAME = "Darwin" if sys.platform == "darwin" else "Linux"

WINDOWS_ARCHIVE = "tor-socks5-%s-x86_64-pc-windows-msvc.zip" % fx.MOCK_TAG


def strip_psmodulepath_env(extra=None):
    """Env для дочернего PS: БЕЗ унаследованного PSModulePath (case-insensitive),
    иначе PS 5.1 не видит свои нативные модули. Как в базовом ps_run."""
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    env.pop("PROCESSOR_ARCHITEW6432", None)
    if extra:
        env.update(extra)
    return env


def require(condition, message):
    """Failure (не skip): отсутствие компилятора/движка — ошибка окружения CI."""
    if not condition:
        raise AssertionError(message)


def replace_marker(text, version):
    marker = "__FIXTURE_VERSION__"
    require(marker in text, "плейсхолдер %s не найден в фикстуре" % marker)
    return text.replace(marker, version)


class ProcessProbe:
    """Запуск нашей фикстуры с pipe-stdin/stdout, reader-поток -> Queue.

    cleanup регистрируется СРАЗУ после Popen: при падении ассертов сначала
    останавливаются НАШИ процессы (exit -> terminate -> kill по известному
    PID), потом join reader'а, и лишь затем внешние rmtree каталогов.
    """

    def __init__(self, test_case, argv, cwd=None, env=None):
        self._case = test_case
        self._stopped = False
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd=cwd, env=env)
        test_case.addCleanup(self.stop)
        self.lines = queue.Queue()
        self._reader = threading.Thread(target=self._read_stdout)
        self._reader.start()

    def _read_stdout(self):
        for raw in self.proc.stdout:
            raw = raw.strip()
            if raw:
                self.lines.put(raw.decode("utf-8", "replace"))
        self.lines.put(None)  # sentinel EOF

    def _next_line(self, timeout):
        try:
            return self.lines.get(timeout=timeout)
        except queue.Empty:
            self.fail_alive("фикстура не вывела строку за %ss" % timeout)

    def fail_alive(self, message):
        extra = ""
        if self.proc.poll() is None:
            extra = " (процесс ещё жив, PID %d)" % self.proc.pid
        raise AssertionError(message + extra)

    def expect_line(self, prefix, timeout=20):
        line = self._next_line(timeout)
        if line is None:
            raise AssertionError(
                "EOF от фикстуры до строки %r, rc=%s" % (prefix, self.proc.poll()))
        if not line.startswith(prefix):
            raise AssertionError("ожидалась строка %r, получена %r" % (prefix, line))
        return line

    def request(self, command, prefix, timeout=10):
        self.proc.stdin.write((command + "\n").encode("ascii"))
        self.proc.stdin.flush()
        return self.expect_line(prefix, timeout=timeout)

    def request_version(self, version, timeout=10):
        self.request("version", "VERSION:" + version, timeout=timeout)

    def stop(self):
        """Graceful exit -> terminate -> kill; ТОЛЬКО наш известный PID."""
        if self._stopped:
            return
        self._stopped = True
        try:
            if self.proc.poll() is None:
                try:
                    self.proc.stdin.write(b"exit\n")
                    self.proc.stdin.flush()
                except OSError:
                    pass
                try:
                    self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.proc.terminate()
                    try:
                        self.proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.proc.kill()
                        self.proc.wait(timeout=5)
        finally:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
            reader = getattr(self, "_reader", None)
            if reader is not None and reader.ident is not None:
                reader.join(timeout=10)
                if reader.is_alive():
                    raise AssertionError("Поток чтения фикстуры не завершился")
            self.proc.stdout.close()


class ShLiveUpdateTests(unittest.TestCase):
    """install.sh: live-update работающего процесса (ubuntu/macos)."""

    @classmethod
    def setUpClass(cls):
        cls.fresh_dir = tempfile.mkdtemp(prefix="tors5-live-sh-")
        cls.addClassCleanup(shutil.rmtree, cls.fresh_dir, ignore_errors=True)
        cls.old_exe = cls._compile(VERSION_OLD, "old")
        cls.new_exe = cls._compile(VERSION_NEW, "new")

    @classmethod
    def _compile(cls, version, label):
        compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        require(compiler, "C-компилятор не найден (cc/clang/gcc) — CI-окружение сломано")
        out_path = os.path.join(cls.fresh_dir, "blocking-%s" % label)
        src_path = out_path + ".c"
        with open(BLOCKING_C, "r", encoding="utf-8") as f:
            src = replace_marker(f.read(), version)
        with open(src_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(src)
        p = fx.run_cmd([compiler, "-std=c99", "-O0", "-o", out_path, src_path],
                       timeout=300)
        require(p.returncode == 0,
                "компиляция фикстуры %s не удалась: %s" % (label, p.stderr))
        require(os.path.exists(out_path), "компилятор не создал %s" % out_path)
        return out_path

    def setUp(self):
        self.area = fx.TempArea(self)
        self._build_n = 0

    # --- harness --------------------------------------------------------

    def build(self):
        """Окружение install.sh с РЕАЛЬНЫМИ байтами NEW-фикстуры в архиве."""
        self._build_n += 1
        ns = self.area.subarea("build-%d" % self._build_n)
        dl = ns.subdir("dl")
        # fakebin по умолчанию: x86_64 + sysctl_arm=0 => на Darwin target
        # x86_64-apple-darwin; имя архива строго совпадает с ключом scenario
        target = ("x86_64-apple-darwin" if SH_OS_NAME == "Darwin"
                  else "x86_64-unknown-linux-musl")
        archive_name = "tor-socks5-%s-%s.tar.gz" % (fx.MOCK_TAG, target)
        archive_path = os.path.join(dl, archive_name)
        with open(self.new_exe, "rb") as f:
            new_bytes = f.read()
        fx.make_tar_gz(archive_path, "tor-socks5", data=new_bytes, mode=0o755)
        with open(archive_path, "rb") as f:
            archive_bytes = f.read()
        sum_path = ns.file("dl/%s.sha256" % archive_name,
                           fx.checksum_text(fx.sha256_hex(archive_bytes),
                                            archive_name).encode("ascii"))
        hash_tools = ("sha256sum",) if shutil.which("sha256sum") else ("shasum",)
        bin_dir, scen, log = fx.make_fakebin(ns, "bin", os_name=SH_OS_NAME,
                                           hash_tools=hash_tools)
        fx.update_curl_scenario(scen, files={archive_name: archive_path,
                                             archive_name + ".sha256": sum_path})
        home = ns.subdir("home")
        env = fx.restricted_env(bin_dir, {"TMPDIR": ns.subdir("tmp"),
                                          "HOME": home,
                                          "TORSOCKS_CURL_SCENARIO": scen,
                                          "TORSOCKS_CURL_LOG": log})
        return {"env": env, "home": home, "new_bytes": new_bytes}

    def install(self, ctx, *args):
        return fx.run_cmd([shutil.which("sh"), fx.INSTALL_SH] + list(args),
                          env=ctx["env"], cwd=fx.REPO_ROOT, timeout=300)

    def prepare_install_dir(self, name):
        dest_dir = os.path.join(self.area.path, name)
        os.makedirs(dest_dir)
        exe = os.path.join(dest_dir, "tor-socks5")
        shutil.copyfile(self.old_exe, exe)
        os.chmod(exe, 0o755)
        return dest_dir, exe

    def assert_canonical_new(self, exe, ctx):
        self.assertEqual(fx.file_bytes(exe), ctx["new_bytes"])
        self.assertEqual(stat.S_IMODE(os.stat(exe).st_mode), 0o755)

    # --- tests ----------------------------------------------------------

    def test_running_process_keeps_old_code_canonical_is_new(self):
        # каталог с пробелами и скобками — как в базовом suite
        dest_dir, exe = self.prepare_install_dir("my dir[0]x")
        conf = os.path.join(dest_dir, "tor-socks5.conf")
        with open(conf, "wb") as f:
            f.write(b"key=value\n")
        foreign = os.path.join(dest_dir, "foreign-sentinel.txt")
        with open(foreign, "wb") as f:
            f.write(b"do-not-touch")

        probe = ProcessProbe(self, [exe])
        probe.expect_line("READY:" + VERSION_OLD)
        old_pid = probe.proc.pid

        ctx = self.build()
        p = self.install(ctx, "--install-dir", dest_dir)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        # установщик НЕ запускал приложение (нет READY-строки в его выводе)
        self.assertNotIn(b"READY:", p.stdout)

        # старый процесс продолжает работать со СТАРЫМ кодом
        self.assertIsNone(probe.proc.poll())
        self.assertEqual(probe.proc.pid, old_pid)
        probe.request_version(VERSION_OLD)

        # canonical заменён на НОВУЮ фикстуру, mode 755
        self.assert_canonical_new(exe, ctx)
        self.assertEqual(fx.file_bytes(conf), b"key=value\n")
        self.assertEqual(fx.file_bytes(foreign), b"do-not-touch")

        probe.stop()
        # после stop процесс завершается сам (exit-протокол), не kill
        self.assertEqual(probe.proc.returncode, 0)


class WindowsLiveUpdateTests(unittest.TestCase):
    """install.ps1: live-update под ОБОИМИ движками (powershell 5.1 + pwsh 7).

    Фикстуры компилируются ОДИН раз на класс (.NET Framework PE, движко-
    независимый); каждый сценарий — свежий install root, тесты в классе
    сериализованы (unicontest), движки перебираются через subTest.
    """

    ARCHIVE = WINDOWS_ARCHIVE

    @classmethod
    def setUpClass(cls):
        cls.fresh_dir = tempfile.mkdtemp(prefix="tors5-live-ps-")
        cls.addClassCleanup(shutil.rmtree, cls.fresh_dir, ignore_errors=True)
        exe51 = shutil.which("powershell")
        require(exe51, "Windows PowerShell 5.1 не найден — CI-окружение сломано")
        cls.old_exe = cls._compile(exe51, VERSION_OLD, "old")
        cls.new_exe = cls._compile(exe51, VERSION_NEW, "new")

    @classmethod
    def _compile(cls, exe51, version, label):
        # Отдельный child-хост на каждую компиляцию: нет кэша типов Add-Type
        out_path = os.path.join(cls.fresh_dir, "blocking-%s.exe" % label)
        p = fx.run_cmd([exe51, "-NoProfile", "-NonInteractive",
                        "-ExecutionPolicy", "Bypass", "-File", COMPILE_PS1,
                        "-SourcePath", BLOCKING_CS,
                        "-OutputPath", out_path,
                        "-VersionMarker", version],
                       env=strip_psmodulepath_env(), timeout=300)
        require(p.returncode == 0,
                "компиляция фикстуры %s не удалась: %s" % (label, p.stdout + p.stderr))
        require(os.path.exists(out_path), "компилятор не создал %s" % out_path)
        return out_path

    def setUp(self):
        self.area = fx.TempArea(self)
        self._build_n = 0
        # обе версии ОБЯЗАТЕЛЬНЫ: отсутствие любого движка — failure (не skip)
        missing = [e for e in ("powershell", "pwsh") if shutil.which(e) is None]
        require(not missing,
                "на windows-latest отсутствуют PS-движки: %s" % missing)

    # --- harness --------------------------------------------------------

    def for_each_engine(self):
        return ["powershell", "pwsh"]

    def exe_bytes(self, path):
        data = fx.file_bytes(path)
        require(len(data) > 2 and data[:2] == b"MZ",
                "payload не является реальным PE: %s" % path)
        return data

    def build_ctx(self, joinpath_mode=None, joinpath_path=None):
        """JSON-release (official URL shape) + zip с РЕАЛЬНЫМ NEW-PE + checksum
        (' *' без финального LF). Каждая сборка — уникальный payload/log path."""
        self._build_n += 1
        uid = "%d" % self._build_n
        payload_dir = self.area.subdir("payload-" + uid)
        archive_path = os.path.join(payload_dir, self.ARCHIVE)
        new_bytes = self.exe_bytes(self.new_exe)
        fx.make_zip(archive_path, [{"name": "tor-socks5.exe",
                                    "data": new_bytes}])
        archive_digest = fx.sha256_hex(fx.file_bytes(archive_path))
        sum_path = os.path.join(payload_dir, self.ARCHIVE + ".sha256")
        with open(sum_path, "wb") as f:
            f.write(fx.checksum_text(archive_digest, self.ARCHIVE,
                                     sep=" *", eol="").encode("ascii"))
        base = "https://github.com/%s/%s/releases/download/%s" % (
            fx.OWNER, fx.REPO, fx.MOCK_TAG)
        a_url, s_url = base + "/" + self.ARCHIVE, base + "/" + self.ARCHIVE + ".sha256"
        release = {"tag_name": fx.MOCK_TAG, "draft": False, "prerelease": False,
                   "assets": [
                       {"name": self.ARCHIVE, "browser_download_url": a_url},
                       {"name": self.ARCHIVE + ".sha256",
                        "browser_download_url": s_url}]}
        scen = {"release": release,
                "downloads": {a_url: {"file": archive_path, "redirects": []},
                              s_url: {"file": sum_path, "redirects": []}},
                "fail_api": False,
                "joinpath_mode": joinpath_mode or "none",
                "joinpath_path": joinpath_path,
                "log": os.path.join(self.area.path, "ps-log-%s.jsonl" % uid)}
        scen_path = self.area.file("scenario-%s.json" % uid,
                                   json.dumps(scen, ensure_ascii=False)
                                   .encode("utf-8"))
        return {"scen": scen_path, "log": scen["log"], "new_bytes": new_bytes}

    def ps_run(self, ctx, install_dir, engine):
        env = strip_psmodulepath_env({"LOCALAPPDATA": self.area.subdir("appdata")})
        return fx.run_cmd([shutil.which(engine), "-NoProfile", "-NonInteractive",
                           "-ExecutionPolicy", "Bypass", "-File", PS_WRAPPER,
                           "-ScenarioPath", ctx["scen"],
                           "-ScriptPath", fx.INSTALL_PS1,
                           "-InstallDir", install_dir], env=env, timeout=300)

    def prepare_install_dir(self, name):
        dest_dir = self.area.subdir(name)
        exe = os.path.join(dest_dir, "tor-socks5.exe")
        shutil.copyfile(self.old_exe, exe)
        return dest_dir, exe

    def backups(self, dest_dir):
        return sorted(n for n in os.listdir(dest_dir) if ".old." in n)

    def stage_leftovers(self, dest_dir):
        return [n for n in os.listdir(dest_dir) if ".tmp-" in n]

    def write_keepers(self, dest_dir):
        conf = os.path.join(dest_dir, "tor-socks5.conf")
        with open(conf, "wb") as f:
            f.write(b"key=value\n")
        foreign = os.path.join(dest_dir, "foreign-sentinel.txt")
        with open(foreign, "wb") as f:
            f.write(b"do-not-touch")
        return conf, foreign

    def assert_keepers(self, conf, foreign):
        self.assertEqual(fx.file_bytes(conf), b"key=value\n")
        self.assertEqual(fx.file_bytes(foreign), b"do-not-touch")

    # --- tests ----------------------------------------------------------

    def test_live_update_running_process_keeps_old_code_and_backup(self):
        for engine in self.for_each_engine():
            with self.subTest(engine=engine):
                dest_dir, exe = self.prepare_install_dir("live-" + engine)
                conf, foreign = self.write_keepers(dest_dir)
                probe = ProcessProbe(self, [exe])
                probe.expect_line("READY:" + VERSION_OLD)
                old_pid = probe.proc.pid

                ctx = self.build_ctx()
                p = self.ps_run(ctx, dest_dir, engine)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

                # работающий OLD не остановлен и не перезапущен
                self.assertIsNone(probe.proc.poll())
                self.assertEqual(probe.proc.pid, old_pid)
                probe.request_version(VERSION_OLD)
                # canonical уже НОВЫЙ; живой OLD удерживает ровно один backup
                self.assertEqual(fx.file_bytes(exe), ctx["new_bytes"])
                self.assertEqual(len(self.backups(dest_dir)), 1)
                self.assertEqual(fx.file_bytes(
                    os.path.join(dest_dir, self.backups(dest_dir)[0])),
                    self.exe_bytes(self.old_exe))
                self.assert_keepers(conf, foreign)
                probe.stop()

    def test_lifecycle_backup_of_live_process_freed_then_cleaned(self):
        for engine in self.for_each_engine():
            with self.subTest(engine=engine):
                dest_dir, exe = self.prepare_install_dir("lc-" + engine)
                conf, foreign = self.write_keepers(dest_dir)

                # установка NEW при живом OLD
                probe_old = ProcessProbe(self, [exe])
                probe_old.expect_line("READY:" + VERSION_OLD)
                ctx = self.build_ctx()
                p = self.ps_run(ctx, dest_dir, engine)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                # стабильный список при фиксации состояния
                self.assertEqual(len(self.backups(dest_dir)), 1)
                old_backup = self.backups(dest_dir)[0]

                # запускаем УЖЕ УСТАНОВЛЕННЫЙ NEW (второй известный PID)
                probe_new = ProcessProbe(self, [exe])
                probe_new.expect_line("READY:" + VERSION_NEW)

                # OLD завершился штатно -> его backup освобождён
                probe_old.stop()

                # следующая установка удаляет освободившийся OLD-backup,
                # но backup живого NEW переживает установку
                ctx2 = self.build_ctx()
                p2 = self.ps_run(ctx2, dest_dir, engine)
                self.assertEqual(p2.returncode, 0, p2.stdout + p2.stderr)
                self.assertFalse(os.path.exists(
                    os.path.join(dest_dir, old_backup)))
                self.assertEqual(len(self.backups(dest_dir)), 1)
                self.assertEqual(fx.file_bytes(
                    os.path.join(dest_dir, self.backups(dest_dir)[0])),
                    ctx["new_bytes"])
                self.assertIsNone(probe_new.proc.poll())
                probe_new.request_version(VERSION_NEW)

                # после exit NEW очередная установка чистит ВСЕ old-backups
                probe_new.stop()
                ctx3 = self.build_ctx()
                p3 = self.ps_run(ctx3, dest_dir, engine)
                self.assertEqual(p3.returncode, 0, p3.stdout + p3.stderr)
                self.assertEqual(self.backups(dest_dir), [])
                self.assertEqual(self.stage_leftovers(dest_dir), [])
                self.assert_keepers(conf, foreign)

    def test_live_rollback_failure_keeps_running_old_intact(self):
        # wrapper joinpath_mode=delete-candidate: candidate удаляется НЕПОСРЕДСТВЕННО
        # перед final move -> реальный rename OLD->backup, неудача, rollback
        for engine in self.for_each_engine():
            with self.subTest(engine=engine):
                dest_dir, exe = self.prepare_install_dir("rb-" + engine)
                conf, foreign = self.write_keepers(dest_dir)
                probe = ProcessProbe(self, [exe])
                probe.expect_line("READY:" + VERSION_OLD)
                old_pid = probe.proc.pid

                ctx = self.build_ctx(joinpath_mode="delete-candidate")
                p = self.ps_run(ctx, dest_dir, engine)
                self.assertNotEqual(p.returncode, 0)

                # транзакция откатилась: canonical — СТАРЫЕ байты, процесс жив
                # и отвечает СТАРЫМ кодом; лишних backup/stage нет
                self.assertEqual(fx.file_bytes(exe),
                                 self.exe_bytes(self.old_exe))
                self.assertIsNone(probe.proc.poll())
                self.assertEqual(probe.proc.pid, old_pid)
                probe.request_version(VERSION_OLD)
                self.assertEqual(self.backups(dest_dir), [])
                self.assertEqual(self.stage_leftovers(dest_dir), [])
                self.assert_keepers(conf, foreign)
                probe.stop()

    def test_mutex_blocks_installer_until_holder_releases(self):
        # hold_mutex.ps1 держит ТОЧНОЕ production-имя mutex'а; установщик
        # обязан отказаться, пока lock занят, и пройти после release
        for engine in self.for_each_engine():
            with self.subTest(engine=engine):
                dest_dir, exe = self.prepare_install_dir("mx-" + engine)
                probe_old = ProcessProbe(self, [exe])
                probe_old.expect_line("READY:" + VERSION_OLD)

                holder = ProcessProbe(
                    self, [shutil.which(engine), "-NoProfile", "-NonInteractive",
                           "-ExecutionPolicy", "Bypass", "-File",
                           HOLD_MUTEX_PS1, "-InstallDir", dest_dir],
                    env=strip_psmodulepath_env())
                holder.expect_line("READY", timeout=30)

                ctx = self.build_ctx()
                p = self.ps_run(ctx, dest_dir, engine)
                self.assertNotEqual(p.returncode, 0)
                # старый бинарник/процесс не тронуты во время отказа
                self.assertEqual(fx.file_bytes(exe),
                                 self.exe_bytes(self.old_exe))
                self.assertIsNone(probe_old.proc.poll())
                probe_old.request_version(VERSION_OLD)

                # holder завершается graceful по протоколу, lock освобождён
                holder.stop()
                ctx2 = self.build_ctx()
                p2 = self.ps_run(ctx2, dest_dir, engine)
                self.assertEqual(p2.returncode, 0, p2.stdout + p2.stderr)
                self.assertEqual(fx.file_bytes(exe), ctx2["new_bytes"])
                probe_old.stop()


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + sys.argv[1:], verbosity=2)
