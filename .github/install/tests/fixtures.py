# -*- coding: utf-8 -*-
"""Общие фикстуры offline-тестов установщиков и release-хелперов.

Принципы:
  - Сеть не используется: curl/gh подменяются stub-исполняемыми файлами
    (curl_mock.py / gh_mock.py из этого каталога), которые пишут журнал argv
    и JSON-состояние. Подмена ТОЛЬКО через PATH/env в harness, production
    скрипты не переписываются.
  - tar.gz/zip собираются из marker-байтов стандартными модулями tarfile/zipfile;
    payload НИКОГДА не исполняется.
  - Все временные каталоги свежие (tempfile), владение у теста, очистка через
    addCleanup.
  - Тесты запускаются с `python -I <этот файл>`: isolation убирает каталог
    скрипта из sys.path, поэтому здесь он добавляется явно (каталог доверенный —
    это содержимое checkout).
"""

import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

_TRUSTED_DIR = os.path.dirname(os.path.abspath(__file__))
if _TRUSTED_DIR not in sys.path:
    sys.path.insert(0, _TRUSTED_DIR)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_TRUSTED_DIR)))
INSTALL_SH = os.path.join(REPO_ROOT, ".github", "install", "install.sh")
INSTALL_PS1 = os.path.join(REPO_ROOT, ".github", "install", "install.ps1")
VALIDATE_TAG_SH = os.path.join(REPO_ROOT, ".github", "release", "validate-tag.sh")
PUBLISH_SH = os.path.join(REPO_ROOT, ".github", "release", "publish.sh")
RELEASE_YML = os.path.join(REPO_ROOT, ".github", "workflows", "release.yml")

OWNER = "PHPCraftdream"
REPO = "tor-socks5"
# Тег latest в mock ЗАВЕДОМО отличается от любого Cargo-тега проекта.
MOCK_TAG = "v9.8.7"

MARKER = b"TOR-SOCKS5-MARKER-BINARY\x00\x01payload-is-never-executed\n"
MARKER_OLD = b"TOR-SOCKS5-OLD-INACTIVE-BINARY\x00\n"

# Реальные системные утилиты, которые нужны install.sh при урезанном PATH
# (всё остальное — stub'ы в fakebin).
SH_REAL_TOOLS = [
    "tar", "gzip", "awk", "od", "tr", "tail", "cut", "wc", "grep",
    "mktemp", "rm", "mkdir", "mv", "chmod", "cat", "sed", "sort",
]


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def checksum_text(hexdigest, name, sep="  ", eol="\n", upper=False):
    """Строка checksum-файла: '  ' (unix) или ' *' (zip), опциональный eol."""
    h = hexdigest.upper() if upper else hexdigest
    return "%s%s%s%s" % (h, sep, name, eol)


class TempArea:
    """Свежий каталог фикстур с гарантированной очисткой (unittest.addCleanup)."""

    def __init__(self, test_case):
        self._case = test_case
        self.path = tempfile.mkdtemp(prefix="tors5-tests-")
        test_case.addCleanup(shutil.rmtree, self.path, ignore_errors=True)

    def subdir(self, name):
        p = os.path.join(self.path, name)
        os.makedirs(p, exist_ok=True)
        return p

    def file(self, name, data):
        p = os.path.join(self.path, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def subarea(self, name):
        """Новый уникальный вложенный namespace (bin/data/dl/home/log),
        чтобы ПОВТОРНЫЙ build в одном TempArea не переиспользовал каталоги
        и не пересоздавал symlinks поверх существующих (SameFileError)."""
        return _SubArea(self.subdir(name))


class _SubArea:
    """Каталог-namespace с тем же интерфеймом subdir/file, что у TempArea."""

    def __init__(self, path):
        self.path = path

    def subdir(self, name):
        p = os.path.join(self.path, name)
        os.makedirs(p, exist_ok=True)
        return p

    def file(self, name, data):
        p = os.path.join(self.path, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p


def make_tar_gz(path, member_name, data=MARKER, mode=0o755):
    """Одночленный tar.gz с regular-файлом (байтовый marker, не исполняется)."""
    with open(path, "wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as t:
                ti = tarfile.TarInfo(member_name)
                ti.size = len(data)
                ti.mode = mode
                ti.mtime = 0
                t.addfile(ti, io.BytesIO(data))
    return path


def make_tar_gz_members(path, members):
    """tar.gz из списка (TarInfo, bytes); для негативных сценариев архива."""
    with open(path, "wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as t:
                for ti, data in members:
                    ti.mtime = 0
                    t.addfile(ti, io.BytesIO(data) if data is not None else None)
    return path


def tar_member(name, data=MARKER, mode=0o755, ttype=tarfile.REGTYPE, linkname=""):
    ti = tarfile.TarInfo(name)
    ti.type = ttype
    ti.linkname = linkname
    ti.mode = mode
    ti.size = len(data) if ttype in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
    return ti, (data if ttype in (tarfile.REGTYPE, tarfile.AREGTYPE) else None)


def make_zip(path, entries):
    """zip из списка словарей: {name, data, external_attr}.

    external_attr — полное 32-битное поле: unix mode << 16 (+ DOS-флаги).
    DOS-каталог: external_attr = 0x10. Windows zip без unix-типа с правами
    0600: (0o600 << 16). symlink: (0o120777 << 16).
    """
    with zipfile.ZipFile(path, "w") as z:
        for e in entries:
            zi = zipfile.ZipInfo(e["name"], date_time=(2026, 1, 1, 0, 0, 0))
            zi.external_attr = e.get("external_attr", 0o100644 << 16)
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, e.get("data", MARKER))
    return path


def write_executable(bin_dir, name, body, interpreter=None):
    """Stub-исполняемый файл: shebang подставляется на СИСТЕМНЫЙ интерпретатор,
    чтобы работал урезанный PATH (env в нём недоступен)."""
    p = os.path.join(bin_dir, name)
    if interpreter is None:
        interpreter = sys.executable
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write("#!" + interpreter + body)
    os.chmod(p, 0o755)
    return p


def _stub_source(module_filename):
    """Текст stub-модуля из trusted-каталога тестов (без её shebang-строки)."""
    with open(os.path.join(_TRUSTED_DIR, module_filename), "r", encoding="utf-8") as f:
        lines = f.read().splitlines(True)
    assert lines[0].startswith("#!")
    return "".join(lines[1:])


def make_fakebin(area, name, os_name="Linux", machine="x86_64",
                 sysctl_arm="0", hash_tools=("sha256sum",)):
    """Урезанный PATH-каталог: stub'ы uname/sysctl/curl + выбранные реальные
    hash-утилиты (symlink на настоящие бинарники — не fake hash output)."""
    bin_dir = area.subdir(name)
    scen_dir = area.subdir(name + "-data")
    scen_path = os.path.join(scen_dir, "curl-scenario.json")
    log_path = os.path.join(scen_dir, "curl-log.jsonl")
    with open(scen_path, "w", encoding="utf-8") as f:
        json.dump({"owner": OWNER, "repo": REPO, "tag": MOCK_TAG,
                   "latest_final_url": "https://github.com/%s/%s/releases/tag/%s"
                                       % (OWNER, REPO, MOCK_TAG),
                   "files": {}}, f)
    write_executable(bin_dir, "curl", "\n" + _stub_source("curl_mock.py"))
    # uname: только -s/-m, как вызывает install.sh
    write_executable(bin_dir, "uname",
                     '\nimport sys\n'
                     'if sys.argv[-1] == "-s": print(%r)\n'
                     'elif sys.argv[-1] == "-m": print(%r)\n'
                     'else: sys.exit(1)\n' % (os_name, machine))
    # sysctl: install.sh зовёт `sysctl -n hw.optional.arm64`, т.е.
    # sys.argv[1:] == ['-n', 'hw.optional.arm64'] (len 2, ключ в индексе 2)
    sysctl_body = ('\nimport sys\n'
                   'if len(sys.argv) > 2 and sys.argv[2] == "hw.optional.arm64":\n')
    if sysctl_arm is None:
        sysctl_body += '    sys.exit(1)\n'
    else:
        sysctl_body += '    print(%r)\n' % str(sysctl_arm)
    write_executable(bin_dir, "sysctl", sysctl_body + 'else: sys.exit(1)\n')
    def link_real(target, link):
        try:
            os.symlink(target, link)
        except OSError:
            # Защита от повторного build в том же каталоге: существующий
            # link/file убираем ПЕРЕД созданием, никогда не copy2 поверх
            # symlink на тот же файл (SameFileError).
            if os.path.lexists(link):
                os.remove(link)
            shutil.copy2(target, link)
            os.chmod(link, 0o755)

    for tool in SH_REAL_TOOLS:
        real = shutil.which(tool)
        if real is None:
            raise RuntimeError("нет системной утилиты %r" % tool)
        link_real(real, os.path.join(bin_dir, tool))
    for tool in hash_tools:
        real = shutil.which(tool)
        if real is None:
            raise RuntimeError("нет hash-утилиты %r" % tool)
        link_real(real, os.path.join(bin_dir, tool))
    return bin_dir, scen_path, log_path


def update_curl_scenario(scen_path, **kw):
    with open(scen_path, "r", encoding="utf-8") as f:
        scen = json.load(f)
    scen.update(kw)
    with open(scen_path, "w", encoding="utf-8") as f:
        json.dump(scen, f)
    return scen


def curl_log(log_path):
    if not os.path.exists(log_path):
        return []
    with open(log_path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def restricted_env(bin_dir, extra=None):
    """env с PATH = ТОЛЬКО fakebin (+ TMPDIR внутри фикстур)."""
    env = {
        "PATH": bin_dir,
        "HOME": os.environ.get("HOME", bin_dir),
        "TMPDIR": None,  # заполняет вызывающий
        "LANG": "C",
    }
    env = {k: v for k, v in env.items() if v is not None}
    if extra:
        env.update(extra)
    return env


def run_cmd(cmd, env=None, cwd=None, timeout=300):
    """Дочерний процесс с ОБЯЗАТЕЛЬНЫМ таймаутом (никаких sleep-надежд)."""
    return subprocess.run(cmd, env=env, cwd=cwd, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def ps_arch_env(arch="AMD64", wow64=None):
    """Значения PROCESSOR_ARCHITECTURE / PROCESSOR_ARCHITEW6432 для дочернего PS."""
    e = {"PROCESSOR_ARCHITECTURE": arch}
    e.pop("PROCESSOR_ARCHITEW6432", None)
    if wow64:
        e["PROCESSOR_ARCHITEW6432"] = wow64
    return e


def file_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def is_executable(path):
    return bool(os.stat(path).st_mode & stat.S_IXUSR)
