#!/usr/bin/env python3
"""Collect verified crates.io archives and license candidates, not notices."""
import gzip
import hashlib
import json
import re
import sys
import tarfile
import tomllib
import zlib
from pathlib import Path

SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
NAME = re.compile(r"^[A-Za-z0-9_-]+$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")
CHECKSUM = re.compile(r"^[0-9a-f]{64}$")
LICENSE = re.compile(r"^(license|licence|copying|notice|copyright|unlicense|mpl|lgpl|gpl|apache|mit)(?:$|[-._])", re.I)
MAX_ARCHIVE = 100 * 1024 * 1024
MAX_FILE = 10 * 1024 * 1024
MAX_TOTAL = 500 * 1024 * 1024  # uncompressed bytes per archive
MAX_ENTRIES = 100000  # across all archives
MAX_ALL_CONTENT = 4 * 1024 * 1024 * 1024
MAX_ALL_ARCHIVES = 2 * 1024 * 1024 * 1024
MAX_PACKAGES = 10000
MAX_TAR_STREAM = 128 * 1024 * 1024  # includes tar headers, extensions and padding
MAX_PATH_LENGTH = 4096
MAX_PATH_DEPTH = 128


def safe_parts(path):
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_LENGTH or path.count("/") + 1 > MAX_PATH_DEPTH:
        raise ValueError("invalid or oversized path")
    parts = path.split("/")
    if (path.startswith("/") or "\\" in path or
            any(p in ("", ".", "..") or ":" in p or
                any(ord(c) < 32 or ord(c) == 127 for c in p) for p in parts)):
        raise ValueError("unsafe path")
    return parts


def digest(data):
    return hashlib.sha256(data).hexdigest()


class LimitedStream:
    """Bound all decompressed bytes before tarfile can parse extension headers."""
    def __init__(self, stream, limit):
        self.stream = stream
        self.remaining = limit

    def read(self, size=-1):
        if size < 0:
            size = self.remaining + 1
        data = self.stream.read(min(size, self.remaining + 1))
        if len(data) > self.remaining:
            raise ValueError("decompressed tar stream too large")
        self.remaining -= len(data)
        return data


def collect(lock, cache, output):
    lock_bytes = lock.read_bytes()
    packages = tomllib.loads(lock_bytes.decode("utf-8"))["package"]
    output.mkdir()  # Never reuse an existing directory, even an empty one.
    archives = output / "archives"
    files = output / "files"
    archives.mkdir()
    files.mkdir()
    (output / "Cargo.lock").write_bytes(lock_bytes)
    records, seen = [], set()
    if len(packages) > MAX_PACKAGES:
        raise ValueError("too many packages")
    entry_count = all_content = all_archives = 0
    for package in packages:
        source = package.get("source")
        if not source:
            records.append({"name": package["name"], "version": package["version"],
                            "source": None, "status": "path-unverified"})
            continue
        if source != SOURCE:
            # Preserve unsupported source identities rather than implying coverage.
            records.append({"name": package["name"], "version": package["version"],
                            "source": source, "status": "unsupported"})
            continue
        name, version, checksum = package["name"], package["version"], package.get("checksum", "")
        if not NAME.fullmatch(name) or not VERSION.fullmatch(version) or not CHECKSUM.fullmatch(checksum):
            raise ValueError("invalid registry identity or checksum")
        stem = f"{name}-{version}"
        if stem in seen:
            raise ValueError(f"duplicate archive identity: {stem}")
        seen.add(stem)
        matches = list(cache.glob(f"*/{stem}.crate"))
        if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file() or matches[0].parent.is_symlink():
            raise ValueError(f"missing or ambiguous archive: {stem}")
        if matches[0].stat().st_size > MAX_ARCHIVE:
            raise ValueError(f"archive too large: {stem}")
        data = matches[0].read_bytes()
        all_archives += len(data)
        if all_archives > MAX_ALL_ARCHIVES:
            raise ValueError("total archive size exceeded")
        if digest(data) != checksum:
            raise ValueError(f"checksum mismatch: {stem}")
        (archives / (stem + ".crate")).write_bytes(data)
        selected, paths, file_paths, parent_paths, total = [], set(), set(), set(), 0
        regular_paths = set()
        manifest_content = None
        with gzip.open(archives / (stem + ".crate"), "rb") as compressed:
            bounded = LimitedStream(compressed, MAX_TAR_STREAM)
            with tarfile.open(fileobj=bounded, mode="r|") as tar:
                for member in tar:
                    path = member.name
                    entry_count += 1
                    if entry_count > MAX_ENTRIES:
                        raise ValueError("too many archive entries")
                    parts = safe_parts(path)
                    if parts[0] != stem or not (member.isfile() or member.isdir()):
                        raise ValueError(f"unsafe archive member: {path}")
                    # Reject case-insensitive collisions and file/directory conflicts, even
                    # when a directory is implicit or appears after its children.
                    key = path.casefold()
                    parents = ["/".join(parts[:i]).casefold() for i in range(1, len(parts))]
                    if (key in paths or any(p in file_paths for p in parents) or
                            (member.isfile() and key in parent_paths)):
                        raise ValueError(f"colliding archive member: {path}")
                    paths.add(key)
                    parent_paths.update(parents)
                    if member.isfile():
                        file_paths.add(key)
                        regular_paths.add(path)
                        total += member.size
                        all_content += member.size
                        if total > MAX_TOTAL or all_content > MAX_ALL_CONTENT:
                            raise ValueError(f"archive content too large: {stem}")
                        if path == f"{stem}/Cargo.toml":
                            if member.size > MAX_FILE:
                                raise ValueError(f"archive content too large: {stem}")
                            manifest_content = tar.extractfile(member).read()
                            if len(manifest_content) != member.size:
                                raise ValueError(f"truncated member: {path}")
                        if len(parts) >= 2 and LICENSE.match(parts[-1]):
                            if member.size > MAX_FILE:
                                raise ValueError(f"archive content too large: {stem}")
                            content = tar.extractfile(member).read()
                            if len(content) != member.size:
                                raise ValueError(f"truncated member: {path}")
                            destination = files / stem
                            destination.mkdir(exist_ok=True)
                            # Numeric output names avoid interpreting untrusted path components.
                            relative = f"files/{stem}/{len(selected):06d}"
                            (output / relative).write_bytes(content)
                            selected.append({"archive_path": path, "path": relative, "sha256": digest(content)})
            # tarfile stops at end-of-archive markers; count trailing and concatenated
            # gzip data too, and force CRC/truncation verification.
            while bounded.read(65536):
                pass
        if manifest_content is not None:
            manifest = tomllib.loads(manifest_content.decode("utf-8"))
            package_meta = manifest.get("package", {})
            if not isinstance(package_meta, dict):
                raise ValueError("invalid Cargo.toml package")
            if "license-file" in package_meta:
                license_file = package_meta["license-file"]
                safe_parts(license_file)
                target = f"{stem}/{license_file}"
                safe_parts(target)
                if target not in regular_paths:
                    raise ValueError(f"missing license-file: {target}")
                if not any(candidate["archive_path"] == target for candidate in selected):
                    with gzip.open(archives / (stem + ".crate"), "rb") as compressed:
                        with tarfile.open(fileobj=LimitedStream(compressed, MAX_TAR_STREAM), mode="r|") as tar:
                            for member in tar:
                                if member.name == target:
                                    if member.size > MAX_FILE:
                                        raise ValueError(f"archive content too large: {stem}")
                                    content = tar.extractfile(member).read()
                                    if len(content) != member.size:
                                        raise ValueError(f"truncated member: {target}")
                                    destination = files / stem
                                    destination.mkdir(exist_ok=True)
                                    relative = f"files/{stem}/{len(selected):06d}"
                                    (output / relative).write_bytes(content)
                                    selected.append({"archive_path": target, "path": relative, "sha256": digest(content)})
                                    break
        records.append({"name": name, "version": version, "source": source,
                        "checksum": checksum, "archive": f"archives/{stem}.crate",
                        "status": "candidates-found" if selected else "no-candidates",
                        "license_candidates": selected})
    (output / "manifest.json").write_text(json.dumps({"schema": 1, "lock_sha256": digest(lock_bytes),
        "packages": records}, indent=2) + "\n", encoding="utf-8")


def main():
    if len(sys.argv) != 4:
        print("usage: cargo_evidence.py Cargo.lock CACHE_DIR NEW_OUTPUT_DIR", file=sys.stderr)
        return 2
    try:
        collect(*(Path(x) for x in sys.argv[1:]))
    except (OSError, EOFError, ValueError, KeyError, TypeError, tarfile.TarError, zlib.error) as exc:
        print(f"Cargo evidence failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
