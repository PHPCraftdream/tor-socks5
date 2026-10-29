#!/usr/bin/env python3
"""Read-only comparison of selected evidence members; Python 3.11+."""
import hashlib
import io
import json
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
TARGETS = {
    ("colored", "2.2.0"): ["LICENSE"],
    ("option-ext", "0.2.0"): ["LICENSE.txt"],
    ("priority-queue", "2.7.0"): ["LGPL-3.0-or-later.txt", "MPL-2.0.txt"],
    ("webpki-roots", "0.26.11"): ["LICENSE"],
    ("webpki-roots", "1.0.7"): ["LICENSE"],
    ("xxhash-rust", "0.8.18"): ["LICENSE"],
    ("async_executors", "0.7.0"): ["LICENSE"],
    ("notify", "8.2.0"): ["LICENSE-CC0"],
}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def unique(items):
    if len(items) != 1:
        raise ValueError(f"expected one entry, got {len(items)}")
    return items[0]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def main():
    path = Path(sys.argv[1])
    require(path.stat().st_size == 119775652, "unexpected evidence ZIP size")
    data = path.read_bytes()
    require(sha(data) == "2d0c6fa6b16fe96610bd9f9b63b2387bc255ad5f86c6a735911233a3b835c7c4", "unexpected evidence ZIP digest")
    print("ZIP sha256:", sha(data))
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        def read(name):
            info = unique([i for i in z.infolist() if i.filename == name])
            require(not info.is_dir(), f"not a file: {name}")
            return z.read(info)
        lock_bytes = read("Cargo.lock")
        manifest_bytes = read("manifest.json")
        lock = tomllib.loads(lock_bytes.decode("utf-8"))
        manifest = json.loads(manifest_bytes)
        require(manifest["schema"] == 1, "unknown manifest schema")
        print("manifest sha256:", sha(manifest_bytes))
        print("Cargo.lock sha256:", sha(lock_bytes))
        print("manifest lock_sha256:", manifest["lock_sha256"])
        require(sha(lock_bytes) == manifest["lock_sha256"], "lock digest mismatch")
        for (name, version), filenames in TARGETS.items():
            stem = f"{name}-{version}"
            lp = unique([p for p in lock["package"] if p.get("name") == name and p.get("version") == version and p.get("source") == SOURCE])
            mp = unique([p for p in manifest["packages"] if p.get("name") == name and p.get("version") == version and p.get("source") == SOURCE])
            archive = f"archives/{stem}.crate"
            require(mp["archive"] == archive and mp["status"] == "candidates-found", f"manifest archive/status: {stem}")
            raw = read(archive)
            actual = sha(raw)
            print(f"\n{stem} source={SOURCE}")
            print(f"  {archive} sha256={actual}")
            print(f"  lock checksum={lp['checksum']}; manifest checksum={mp['checksum']}")
            require(actual == lp["checksum"] == mp["checksum"], f"checksum mismatch: {stem}")
            print("  identity/source/checksum lock=manifest=archive: OK")
            candidates = mp["license_candidates"]
            require(len(candidates) == len(filenames), f"unexpected candidate count: {stem}")
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
                members = tar.getmembers()
                for filename in filenames:
                    member_name = f"{stem}/{filename}"
                    candidate = unique([c for c in candidates if c["archive_path"] == member_name])
                    member = unique([m for m in members if m.name == member_name])
                    require(member.isfile(), f"not a regular file: {member_name}")
                    original = tar.extractfile(member).read()
                    copy = read(candidate["path"])
                    h = sha(copy)
                    print(f"  copy={candidate['path']} member={member_name}")
                    print(f"  copy sha256={h}; member sha256={sha(original)}; manifest sha256={candidate['sha256']}")
                    require(copy == original and h == candidate["sha256"], f"copy mismatch: {member_name}")
                    print("  byte equality and manifest hash: OK")
    print("\nRESULT: 8 archives and 9 license copies OK")

if __name__ == "__main__":
    main()
