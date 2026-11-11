#!/usr/bin/env python3
"""Check the vendored Arti crates against their pristine crates.io archives.

The baseline (crate, version, SHA-256 of the archive) and the delivered license
files (Git blob ids) are read from the tables in ``vendor/PROVENANCE.md``. For
every vendored crate the check proves, mechanically and only for that baseline:

* the archive matches its recorded SHA-256;
* every notice line of the pristine package (copyright, license, holder and
  author lines) is still present, unchanged, in the vendored copy of the file;
* every vendored file that is new or differs from the archive carries a
  prominent change notice (Apache-2.0 section 4(b)), except the delivered
  license files and Cargo's own ``.cargo-ok``;
* ``LICENSE-MIT`` and ``LICENSE-APACHE`` have the recorded blob ids.

It does not decide which notices apply, whether the notices are complete, or
whether any license obligation is met; that is not legal advice.
"""
import argparse
import hashlib
import io
import os
import re
import sys
import tarfile
import tempfile
import time
import urllib.request

CRATES_URL = "https://static.crates.io/crates/{name}/{name}-{version}.crate"
BASELINE_HEADING = "Current baseline"
BASELINE_ROW = re.compile(r"\| `([^`]+)` \| (\d+\.\d+\.\d+[^ |]*) \| `[^`]+` \| `([0-9a-f]{64})` \|")
LICENSE_ROW = re.compile(r"\| `(LICENSE-[A-Z]+)` \| (\d+) \| `([0-9a-f]{40})` \| `([0-9a-f]{64})` \|")
# Lines that carry copyright, license, holder or author information.
NOTICE_RE = re.compile(
    r"copyright|\(c\)\s*\d{4}|©|spdx|licen[cs]|the tor project|authors\s*=|<[^<>\s]+@[^<>\s]+>",
    re.IGNORECASE,
)
# A prominent change notice in a modified or added file.
CHANGE_NOTICE_RE = re.compile(r"tor-socks5 local patch|PROVENANCE\.md")
# Files that are not edited upstream source: delivered license texts and Cargo's marker.
CHANGE_NOTICE_EXEMPT = frozenset({"LICENSE-MIT", "LICENSE-APACHE", ".cargo-ok"})
LICENSE_FILES = ("LICENSE-MIT", "LICENSE-APACHE")


class CheckError(Exception):
    pass


def git_blob_id(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def parse_provenance(text):
    """Return ({crate: (version, sha256)}, {license file: (bytes, blob id, sha256)})."""
    if BASELINE_HEADING not in text:
        raise CheckError("PROVENANCE.md has no 'Current baseline' table")
    section = text.split(BASELINE_HEADING, 1)[1].split("Previous baseline", 1)[0]
    crates = {name: (version, sha) for name, version, sha in BASELINE_ROW.findall(section)}
    if not crates:
        raise CheckError("PROVENANCE.md baseline table has no crate rows")
    licenses = {name: (int(size), blob, sha) for name, size, blob, sha in LICENSE_ROW.findall(text)}
    for name in LICENSE_FILES:
        if name not in licenses:
            raise CheckError("PROVENANCE.md has no row for " + name)
    return crates, licenses


def read_archive(data, expected_sha256, label):
    """Return {relative path: bytes} of an archive after checking its SHA-256."""
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise CheckError("%s: archive SHA-256 %s differs from the recorded %s" % (label, actual, expected_sha256))
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            parts = member.name.split("/")
            if member.isdir():
                continue
            if not member.isreg() or member.name.startswith("/") or ".." in parts or len(parts) < 2:
                raise CheckError("%s: unsafe or non-regular archive member %r" % (label, member.name))
            files["/".join(parts[1:])] = archive.extractfile(member).read()
    return files


def fetch_archive(name, version, cache_dir):
    path = os.path.join(cache_dir, "%s-%s.crate" % (name, version))
    if os.path.isfile(path):
        with open(path, "rb") as handle:
            return handle.read()
    last_error = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(CRATES_URL.format(name=name, version=version), timeout=60) as response:
                data = response.read()
            with open(path, "wb") as handle:
                handle.write(data)
            return data
        except OSError as error:
            last_error = error
            time.sleep(2 * (attempt + 1))
    raise CheckError("%s %s: download failed: %s" % (name, version, last_error))


def read_vendor_tree(root):
    files = {}
    for current, _dirs, names in os.walk(root):
        for name in names:
            path = os.path.join(current, name)
            if os.path.islink(path):
                raise CheckError("vendor tree contains a symlink: " + path)
            with open(path, "rb") as handle:
                files[os.path.relpath(path, root).replace(os.sep, "/")] = handle.read()
    return files


def notice_lines(data):
    try:
        text = data.decode("utf8")
    except UnicodeDecodeError:
        return None
    return [line.rstrip() for line in text.split("\n") if NOTICE_RE.search(line)]


def check_crate(label, pristine, vendor, licenses):
    """Problems found for one crate; both arguments map relative paths to bytes."""
    problems = []
    for path, original in sorted(pristine.items()):
        lines = notice_lines(original)
        if not lines:
            continue
        ours = vendor.get(path)
        if ours is None:
            problems.append("%s: %s carries notice lines upstream but is missing from vendor/" % (label, path))
            continue
        present = {}
        for line in (notice_lines(ours) or []):
            present[line] = present.get(line, 0) + 1
        for line in lines:
            if present.get(line, 0) == 0:
                problems.append("%s: %s: notice line removed or changed: %r" % (label, path, line))
            else:
                present[line] -= 1
    for path, ours in sorted(vendor.items()):
        name = path.rsplit("/", 1)[-1]
        if path in pristine and pristine[path] == ours:
            continue
        if path in CHANGE_NOTICE_EXEMPT or (name in CHANGE_NOTICE_EXEMPT and "/" not in path):
            continue
        try:
            text = ours.decode("utf8")
        except UnicodeDecodeError:
            problems.append("%s: %s is modified or added but is not a text file that can carry a notice" % (label, path))
            continue
        if not CHANGE_NOTICE_RE.search(text):
            problems.append("%s: %s is modified or added without a change notice" % (label, path))
    for name in LICENSE_FILES:
        size, blob, _sha = licenses[name]
        data = vendor.get(name)
        if data is None:
            problems.append("%s: %s is missing" % (label, name))
        elif len(data) != size or git_blob_id(data) != blob:
            problems.append("%s: %s does not match the recorded blob id %s" % (label, name, blob))
    return problems


def run(repo_root, cache_dir):
    with open(os.path.join(repo_root, "vendor", "PROVENANCE.md"), encoding="utf8") as handle:
        crates, licenses = parse_provenance(handle.read())
    problems = []
    for name, (version, sha) in sorted(crates.items()):
        label = "%s %s" % (name, version)
        vendor_dir = os.path.join(repo_root, "vendor", name)
        if not os.path.isdir(vendor_dir):
            problems.append("%s: vendor/%s is missing" % (label, name))
            continue
        pristine = read_archive(fetch_archive(name, version, cache_dir), sha, label)
        found = check_crate(label, pristine, read_vendor_tree(vendor_dir), licenses)
        problems.extend(found)
        print("%s: %d archive files, %s" % (label, len(pristine), "ok" if not found else "%d problem(s)" % len(found)))
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--archives", help="directory for downloaded archives (default: a temporary one)")
    args = parser.parse_args(argv)
    try:
        if args.archives:
            os.makedirs(args.archives, exist_ok=True)
            problems = run(args.repo_root, args.archives)
        else:
            with tempfile.TemporaryDirectory() as cache:
                problems = run(args.repo_root, cache)
    except CheckError as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    for problem in problems:
        print("PROBLEM: " + problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
