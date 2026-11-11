#!/usr/bin/env python3
"""Verify and prepare the Arti 0.48.0 upstream-patch bundle; never edits vendor/ or base/."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
from collections import Counter
from pathlib import Path, PurePosixPath

VERSION = "0.48.0"
PATCH_REL = Path("packages/arti-wrapper/upstream-patches/arti-0.48.0")
# Explicit, crate/stem-qualified ordering edges: patch identity -> prerequisite identities.
PATCH_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "tor-dirclient/02-content-length": ("tor-dirclient/01-idle-body",),
    "tor-guardmgr/02-descriptorless-data": ("tor-guardmgr/01-bridge-recovery",),
}
HUNK_SEARCH_RADIUS = 200
NOTICE_RE = re.compile(rb"(?i)(copyright|\blicense\b|spdx|\bnotice\b|licensed under|local patch|attribution)")
FORBIDDEN_ADDITION = re.compile(
    rb"(?i)(initial[_-]connect[_-]timeout|\breadiness\b|"
    rb"\bpub\s+(?:async\s+)?fn\s+\w*reset\w*|"
    rb"\bpublic\b.{0,48}\breset\b|\breset\b.{0,48}\bpublic\b)"
)
HUNK_RE = re.compile(rb"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
DIFF_RE = re.compile(rb"^diff --git a/(\S+) b/(\S+)$")
SUBJECT_RE = re.compile(r"^Subject: \[PATCH(?: [1-9][0-9]*/[1-9][0-9]*)?\] ([^\r\n]+)$")


class VerifyError(Exception):
    pass


def fail(message: str) -> None:
    raise VerifyError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_provenance(path: Path) -> tuple[str, dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    url_match = re.search(r"`(https://static\.crates\.io/crates/<name>/<name>-<version>\.crate)`", text)
    if not url_match:
        fail("PROVENANCE.md has no recognized crates.io archive URL template")
    current = text.split("Current baseline (synced", 1)
    if len(current) != 2:
        fail("PROVENANCE.md has no current baseline table")
    table = current[1].split("Previous baseline", 1)[0]
    rows = re.findall(r"^\| `([a-z0-9-]+)` \| ([0-9.]+) \| [^|]+ \| `([0-9a-f]{64})` \|$", table, re.M)
    hashes = {crate: digest for crate, version, digest in rows if version == VERSION}
    if len(hashes) != sum(version == VERSION for _, version, _ in rows) or not hashes:
        fail("PROVENANCE.md current 0.48.0 archive table is missing or ambiguous")
    return url_match.group(1), hashes


def archive_for(archives: Path, crate: str, version: str) -> Path:
    candidates = [p for suffix in (".crate.gz", ".crate")
                  if (p := archives / f"{crate}-{version}{suffix}").is_file()]
    if len(candidates) != 1:
        fail(f"expected one archive for {crate}-{version} in target/arti-pristine/archives (found {len(candidates)})")
    return candidates[0]


def safe_member_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        fail(f"unsafe archive member path: {name!r}")
    if ":" in path.parts[0] or "\\" in name:
        fail(f"unsafe archive member path: {name!r}")
    return path


def archive_files(archive: Path, crate: str, version: str) -> dict[str, bytes]:
    expected_root = f"{crate}-{version}"
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(archive, "r:*") as tar:
            for member in tar.getmembers():
                name = safe_member_name(member.name)
                if name.parts[0] != expected_root:
                    fail(f"unexpected archive root {name.parts[0]!r} in {archive.name}")
                if member.isdir():
                    continue
                if not member.isfile():
                    fail(f"archive contains non-regular member {member.name!r}")
                if len(name.parts) == 1:
                    fail(f"archive file is at package root: {member.name!r}")
                rel = PurePosixPath(*name.parts[1:]).as_posix()
                if rel in files:
                    fail(f"duplicate archive member {member.name!r}")
                stream = tar.extractfile(member)
                if stream is None:
                    fail(f"cannot read archive member {member.name!r}")
                files[rel] = stream.read()
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot read archive {archive.name}: {exc}")
    if not files:
        fail(f"archive is empty: {archive.name}")
    return files


def compare_base_tree(base: Path, files: dict[str, bytes], label: str) -> None:
    if not base.is_dir() or base.is_symlink():
        fail(f"verified base tree missing: {label}")
    actual: dict[str, bytes] = {}
    for path in base.rglob("*"):
        if path.is_symlink():
            fail(f"base tree contains symlink: {label}/{path.relative_to(base).as_posix()}")
        if path.is_file():
            actual[path.relative_to(base).as_posix()] = path.read_bytes()
        elif not path.is_dir():
            fail(f"base tree contains unsupported entry: {label}")
    if actual.keys() != files.keys():
        missing = sorted(files.keys() - actual.keys())
        extra = sorted(actual.keys() - files.keys())
        fail(f"base tree differs from archive {label} (missing={missing[:3]}, extra={extra[:3]})")
    for name, data in files.items():
        if actual[name] != data:
            fail(f"base tree differs from archive {label}/{name}")


def verify_baselines(root: Path, crates: set[str], report: dict) -> dict[str, dict[str, bytes]]:
    template, hashes = read_provenance(root / "vendor/PROVENANCE.md")
    report["archive_url_template"] = template
    archives = root / "target/arti-pristine/archives"
    contents: dict[str, dict[str, bytes]] = {}
    for crate in sorted(crates):
        if crate not in hashes:
            fail(f"patch crate has no {VERSION} hash in vendor/PROVENANCE.md: {crate}")
        archive = archive_for(archives, crate, VERSION)
        actual_hash = sha256(archive)
        if actual_hash != hashes[crate]:
            fail(f"archive SHA-256 mismatch for {crate}-{VERSION}: expected {hashes[crate]}, got {actual_hash}")
        files = archive_files(archive, crate, VERSION)
        base_rel = f"target/arti-pristine/base/{crate}-{VERSION}"
        compare_base_tree(root / base_rel, files, base_rel)
        contents[crate] = files
        report.setdefault("baselines", []).append({"crate": crate, "archive": archive.relative_to(root).as_posix(),
                                                   "sha256": actual_hash, "base_tree": base_rel,
                                                   "archive_members": len(files)})
    # Validate any additional recognized baseline archives already present, without requiring unused ones.
    if archives.is_dir():
        for path in sorted(archives.iterdir()):
            match = re.fullmatch(r"([a-z0-9-]+)-([0-9.]+)\.crate(?:\.gz)?", path.name)
            if not path.is_file() or not match or match.group(2) != VERSION or match.group(1) in crates:
                continue
            crate = match.group(1)
            if crate not in hashes:
                fail(f"archive has no provenance hash: {path.name}")
            actual_hash = sha256(path)
            if actual_hash != hashes[crate]:
                fail(f"archive SHA-256 mismatch for {path.name}")
            files = archive_files(path, crate, VERSION)
            base_rel = f"target/arti-pristine/base/{crate}-{VERSION}"
            compare_base_tree(root / base_rel, files, base_rel)
            report.setdefault("baselines", []).append({"crate": crate, "archive": path.relative_to(root).as_posix(),
                                                       "sha256": actual_hash, "base_tree": base_rel,
                                                       "archive_members": len(files)})
    return contents


def parse_patch(path: Path, crate: str, vendor: Path) -> list[dict]:
    raw = path.read_bytes().replace(b"\r\n", b"\n")
    lines = raw.splitlines(keepends=True)
    try:
        first_diff = next(i for i, line in enumerate(lines) if line.startswith(b"diff --git "))
    except StopIteration:
        fail(f"patch has no unified diff: {path.name}")
    headers = [line.decode("utf-8", "strict").rstrip("\n") for line in lines[:first_diff]]
    if not headers or not re.fullmatch(r"From [0-9a-f]{7,64} .+", headers[0]):
        fail(f"patch is not a strict mbox message: {path.name}")
    subjects = [SUBJECT_RE.fullmatch(line) for line in headers if line.startswith("Subject:")]
    if len(subjects) != 1 or subjects[0] is None or not subjects[0].group(1).startswith(crate):
        fail(f"mbox Subject must identify [PATCH] {crate}: {path.name}")
    subject = subjects[0].group(1)
    if subject != crate and not subject.startswith(crate + ":") and not subject.startswith(crate + " "):
        fail(f"mbox Subject must identify [PATCH] {crate}: {path.name}")

    blocks: list[list[bytes]] = []
    starts = [i for i, line in enumerate(lines) if line.startswith(b"diff --git ")]
    for pos, start in enumerate(starts):
        end = starts[pos + 1] if pos + 1 < len(starts) else len(lines)
        blocks.append(lines[start:end])
    result = []
    for block in blocks:
        match = DIFF_RE.fullmatch(block[0].rstrip(b"\n"))
        if not match:
            fail(f"malformed diff header in {path.name}")
        old_path, new_path = (value.decode("utf-8", "strict") for value in match.groups())
        if old_path != new_path or "\\" in old_path or ":" in old_path or not old_path.startswith("src/") or not old_path.endswith(".rs"):
            fail(f"forbidden patch scope {old_path!r} in {path.name}")
        rel = PurePosixPath(old_path)
        raw_parts = old_path.split("/")
        if rel.is_absolute() or any(part in ("", ".", "..") for part in raw_parts):
            fail(f"unsafe patch path {old_path!r}")
        marker_lines = [line.rstrip(b"\n") for line in block]
        is_new_file = b"new file mode 100644" in marker_lines
        if any(line.startswith((b"deleted file mode ", b"old mode ", b"new mode ",
                               b"rename from ", b"rename to ", b"copy from ", b"copy to ", b"Binary files "))
               for line in marker_lines) or any(line.startswith(b"new file mode ") and line != b"new file mode 100644"
                                                 for line in marker_lines):
            fail(f"non-source or mode-changing patch metadata in {path.name}")
        old_marker = b"--- /dev/null" if is_new_file else b"--- a/" + old_path.encode()
        new_marker = b"+++ b/" + new_path.encode()
        if is_new_file != (old_marker == b"--- /dev/null") or old_marker not in marker_lines or new_marker not in marker_lines:
            fail(f"unified file headers missing for {old_path} in {path.name}")
        vendor_path = vendor / crate / Path(*rel.parts)
        crate_vendor = vendor / crate
        if not crate_vendor.is_dir() or crate_vendor.is_symlink():
            fail(f"vendor crate absent for patch path vendor/{crate}/{old_path}")
        if is_new_file:
            if not old_path.startswith("src/") or not old_path.endswith(".rs"):
                fail(f"new file is outside Rust source scope in {path.name}: {old_path}")
            if vendor_path.is_symlink() or (vendor_path.exists() and not vendor_path.is_file()):
                fail(f"unsafe new-file vendor target for {old_path}")
            parent = vendor_path.parent
            while parent != crate_vendor:
                if not parent.is_dir() or parent.is_symlink():
                    fail(f"unsafe or absent vendor source directory for {old_path}")
                parent = parent.parent
            if not vendor_path.is_file() or vendor_path.is_symlink():
                fail(f"vendor source absent for new-file patch path vendor/{crate}/{old_path}")
            vendor_data = vendor_path.read_bytes().replace(b"\r\n", b"\n")
            vendor_sequence_parts = vendor_data.split(b"\n")
            vendor_sequence = [part + b"\n" for part in vendor_sequence_parts[:-1]]
            if vendor_sequence_parts[-1]:
                vendor_sequence.append(vendor_sequence_parts[-1])
            vendor_lines = set()
        else:
            if not vendor_path.is_file() or vendor_path.is_symlink():
                fail(f"vendor source absent for patch path vendor/{crate}/{old_path}")
            vendor_lines = set(vendor_path.read_bytes().replace(b"\r\n", b"\n").splitlines(keepends=True))
            vendor_sequence = []
        hunks = []
        new_file_additions = []
        index = 0
        while index < len(block):
            hmatch = HUNK_RE.match(block[index])
            if not hmatch:
                index += 1
                continue
            old_start = int(hmatch.group(1)); old_count = int(hmatch.group(2) or b"1")
            new_start = int(hmatch.group(3)); new_count = int(hmatch.group(4) or b"1")
            index += 1
            body = []
            old_seen = new_seen = 0
            while old_seen < old_count or new_seen < new_count:
                if index >= len(block):
                    fail(f"truncated hunk in {path.name}")
                line = block[index]
                if not line or line[:1] not in (b" ", b"+", b"-"):
                    fail(f"malformed hunk line in {path.name}")
                if line.startswith(b"\\ No newline"):
                    fail(f"no-newline hunk is not accepted: {path.name}")
                body.append(line)
                if line[:1] in (b" ", b"-"):
                    old_seen += 1
                if line[:1] in (b" ", b"+"):
                    new_seen += 1
                index += 1
            if old_seen != old_count or new_seen != new_count:
                fail(f"hunk line counts do not match in {path.name}")
            additions = [line[1:] for line in body if line.startswith(b"+")]
            if is_new_file:
                new_file_additions.extend(additions)
            if any(FORBIDDEN_ADDITION.search(line) for line in additions):
                fail(f"forbidden added API/behavior in {path.name}:{old_path}")
            if is_new_file and not (old_count == 0 and new_count == len(additions)):
                fail(f"new-file patch must contain additions only: {path.name}:{old_path}")
            if not is_new_file and any(line not in vendor_lines for line in additions):
                fail(f"added source line is not byte-identical to vendor/{crate}/{old_path}")
            if any(NOTICE_RE.search(line[1:]) for line in body if line.startswith(b"-")):
                fail(f"patch removes or changes an attribution/license notice in {path.name}")
            hunks.append({"old_start": old_start, "old_count": old_count,
                          "new_start": new_start, "new_count": new_count, "body": body})
        if not hunks:
            fail(f"source diff has no hunks in {path.name}")
        if is_new_file:
            vendor_index = 0
            for added_line in new_file_additions:
                while vendor_index < len(vendor_sequence) and vendor_sequence[vendor_index] != added_line:
                    vendor_index += 1
                if vendor_index == len(vendor_sequence):
                    fail(f"new-file additions are not an ordered byte-identical subsequence of vendor/{crate}/{old_path}")
                vendor_index += 1
        result.append({"path": old_path, "new_file": is_new_file, "hunks": hunks})
    return result


def patch_id(patch: dict) -> str:
    return f"{patch['crate']}/{patch['stem']}"


def ordered_patches(crate: str, patches: list[dict]) -> list[dict]:
    by_id = {patch_id(patch): patch for patch in patches}
    if len(by_id) != len(patches):
        fail(f"patch filename stems must be unique within {crate}")
    ordered, remaining = [], set(by_id)
    while remaining:
        ready = sorted(identity for identity in remaining
                       if set(PATCH_DEPENDENCIES.get(identity, ())) <= set(by_id) - remaining)
        if not ready:
            fail(f"patch dependency mapping is missing a prerequisite or contains a cycle ({crate})")
        for identity in ready:
            ordered.append(by_id[identity])
            remaining.remove(identity)
    return ordered


def dependency_closure(patch: dict, by_id: dict[str, dict]) -> list[dict]:
    result: list[dict] = []
    seen: set[str] = set()

    def visit(identity: str) -> None:
        if identity in seen:
            return
        dependency = by_id.get(identity)
        if dependency is None:
            fail(f"missing prerequisite patch {identity} for {patch_id(patch)}")
        for parent in PATCH_DEPENDENCIES.get(identity, ()):
            visit(parent)
        seen.add(identity)
        result.append(dependency)

    for identity in PATCH_DEPENDENCIES.get(patch_id(patch), ()):
        visit(identity)
    return result


def materialize(files: dict[str, bytes], dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for name, data in files.items():
        rel = safe_member_name(name)
        target = dest.joinpath(*rel.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def apply_hunks(tree: Path, parsed: list[dict]) -> None:
    for file_patch in parsed:
        rel = PurePosixPath(file_patch["path"])
        target = tree.joinpath(*rel.parts)
        if file_patch.get("new_file"):
            if target.exists() or target.is_symlink():
                fail(f"new-file patch target already exists: {file_patch['path']}")
            parent = target.parent
            while parent != tree:
                if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
                    fail(f"unsafe new-file patch parent: {file_patch['path']}")
                parent = parent.parent
            lines: list[bytes] = []
        else:
            if not target.is_file() or target.is_symlink():
                fail(f"patch target is not a regular file: {file_patch['path']}")
            lines = target.read_bytes().replace(b"\r\n", b"\n").splitlines(keepends=True)
        offset = 0
        for hunk in file_patch["hunks"]:
            old_start, old_count = hunk["old_start"], hunk["old_count"]
            expected = (old_start - 1 if old_count else old_start) + offset
            old_lines = [line[1:] for line in hunk["body"] if line[:1] in (b" ", b"-")]
            new_lines = [line[1:] for line in hunk["body"] if line[:1] in (b" ", b"+")]
            if file_patch.get("new_file") and old_lines:
                fail(f"new-file patch has context or deletions: {file_patch['path']}")
            if old_lines:
                low = max(0, expected - HUNK_SEARCH_RADIUS)
                high = min(len(lines) - len(old_lines), expected + HUNK_SEARCH_RADIUS)
                candidates = [pos for pos in range(low, high + 1)
                              if lines[pos:pos + len(old_lines)] == old_lines]
                if len(candidates) != 1:
                    reason = "no exact" if not candidates else "ambiguous exact"
                    fail(f"{reason} hunk context within {HUNK_SEARCH_RADIUS} lines at "
                         f"{file_patch['path']}:{old_start}")
                at = candidates[0]
            else:
                at = expected
                if at < 0 or at > len(lines):
                    fail(f"hunk insertion point out of range at {file_patch['path']}:{old_start}")
            if at < 0 or lines[at:at + len(old_lines)] != old_lines:
                fail(f"exact hunk context mismatch at {file_patch['path']}:{old_start}")
            lines[at:at + len(old_lines)] = new_lines
            offset += at - expected + len(new_lines) - len(old_lines)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"".join(lines))


def validate_notices(base_files: dict[str, bytes], tree: Path, paths: set[str]) -> None:
    for name in paths:
        before = base_files.get(name, b"").replace(b"\r\n", b"\n").splitlines()
        target = tree / Path(*PurePosixPath(name).parts)
        after = target.read_bytes().replace(b"\r\n", b"\n").splitlines()
        required = Counter(line for line in before if NOTICE_RE.search(line))
        present = Counter(line for line in after if NOTICE_RE.search(line))
        if required - present:
            fail(f"source attribution/license notice was not preserved: {name}")


def relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def run_checked(root: Path, args: list[str], log: Path, report: dict,
                added_lines: int | None = None) -> None:
    proc = subprocess.run(args, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    redactions = {str(root): ".", str(root).replace("\\", "/"): "."}
    def clean(data: bytes) -> bytes:
        text = data.decode("utf-8", "replace")
        for secret_path, replacement in sorted(redactions.items(), key=lambda item: -len(item[0])):
            text = text.replace(secret_path, replacement)
        text = re.sub(r"(?<![A-Za-z0-9])(?:[A-Za-z]:[\\/][^\s\"'<>|]+|/(?:[^\s/]+/)*[^\s/]+)", "<absolute-path>", text)
        return text.encode("utf-8")
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_bytes((f"PATCH_ADDED_LINES {added_lines}\n" if added_lines is not None else "").encode()
                    + b"STDOUT\n" + clean(proc.stdout) + b"\nSTDERR\n" + clean(proc.stderr))
    report.setdefault("commands", []).append({"argv": args, "cwd": ".", "log": relative(root, log),
                                              "exit_code": proc.returncode, "added_lines": added_lines})
    if proc.returncode:
        fail(f"command failed ({proc.returncode}); see {relative(root, log)}")


def git_check(root: Path, scratch: Path, patch_path: Path, log: Path, report: dict,
              parsed: list[dict]) -> None:
    scratch_rel = relative(root, scratch)
    patch_rel = relative(root, patch_path)
    args = ["git", "apply", "--check", f"--directory={scratch_rel}", "--", patch_rel]
    run_checked(root, args, log, report, added_line_total({"parsed": parsed}))


def added_line_total(patch: dict) -> int:
    return sum(line.startswith(b"+") for file_patch in patch["parsed"]
               for hunk in file_patch["hunks"] for line in hunk["body"])


def prepare_checks(root: Path, crate: str, base_files: dict[str, bytes], patches: list[dict],
                   patch_root: Path, report: dict, independent: bool) -> None:
    checks = root / "target/arti-pristine/checks" / crate
    by_id = {patch_id(patch): patch for patch in patches}
    for patch in patches:
        patch["added_line_total"] = added_line_total(patch)
        dependencies = dependency_closure(patch, by_id)
        patch_path = patch_root / patch["relative"]
        scratch = checks / patch["stem"]
        materialize(base_files, scratch)
        for dependency in dependencies:
            apply_hunks(scratch, dependency["parsed"])
        git_check(root, scratch, patch_path, scratch / "verify.log", report, patch["parsed"])
        apply_hunks(scratch, patch["parsed"])
        validate_notices(base_files, scratch, set(patch["source_paths"]))
        patch["scratch"] = scratch
        if independent:
            individual = checks / (patch["stem"] + "-individual")
            materialize(base_files, individual)
            for dependency in dependencies:
                apply_hunks(individual, dependency["parsed"])
            git_check(root, individual, patch_path, individual / "verify.log", report, patch["parsed"])
            apply_hunks(individual, patch["parsed"])
            validate_notices(base_files, individual, set(patch["source_paths"]))
            patch["individual_scratch"] = individual


def make_combined_workspace(root: Path, patch_root: Path, patches_by_crate: dict[str, list[dict]],
                            contents: dict[str, dict[str, bytes]], report: dict) -> Path:
    combined = root / "target/arti-pristine/combined"
    if combined.exists():
        shutil.rmtree(combined)
    combined.mkdir(parents=True)
    crates = sorted(patches_by_crate)
    members = []
    patch_lines = []
    for crate in crates:
        members.append(f'    "{crate}",')
        patch_lines.extend([f'"{crate}" = {{ path = "{crate}" }}'])
        files = contents[crate]
        crate_dir = combined / crate
        materialize(files, crate_dir)
        for patch in patches_by_crate[crate]:
            apply_hunks(crate_dir, patch["parsed"])
        paths = {path for patch in patches_by_crate[crate] for path in patch["source_paths"]}
        validate_notices(files, crate_dir, paths)
    manifest = "[workspace]\nresolver = \"2\"\nmembers = [\n" + "\n".join(members) + "\n]\n\n[patch.crates-io]\n" + "\n".join(patch_lines) + "\n"
    (combined / "Cargo.toml").write_text(manifest, encoding="utf-8", newline="\n")
    # Retain an archive lockfile if one is present; normal registry archives generally have none.
    lockfiles = [combined / crate / "Cargo.lock" for crate in crates if (combined / crate / "Cargo.lock").is_file()]
    if lockfiles:
        shutil.copy2(lockfiles[0], combined / "Cargo.lock")
    report["combined_workspace"] = {"path": relative(root, combined), "members": crates,
                                     "manifest": relative(root, combined / "Cargo.toml")}
    return combined


def cargo_checks(root: Path, combined: Path, patches_by_crate: dict[str, list[dict]], report: dict) -> None:
    target_dir = root / "target/arti-pristine/cargo-target"
    features = {
        "tor-dirmgr": ["bridge-client", "static"],
        "tor-guardmgr": ["bridge-client", "pt-client"],
        "tor-chanmgr": ["pt-client"],
        "tor-dirclient": ["hs-client", "hs-service"],
    }
    for crate in sorted(patches_by_crate):
        args = ["cargo", "check", "--tests", "--manifest-path", relative(root, combined / "Cargo.toml"),
                "--package", crate, "--jobs", "2", "--target-dir", relative(root, target_dir)]
        if features.get(crate):
            args.extend(["--features", ",".join(features[crate])])
        run_checked(root, args, combined / f"{crate}.cargo.log", report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--prepare", action="store_true", help="verify and prepare scratch trees (default; no Cargo)")
    modes.add_argument("--cargo-check", action="store_true", help="prepare, then cargo check --tests")
    parser.add_argument("--individual", action="store_true",
                        help="also check each patch with its declared prerequisite chain (dependent patches are not pristine-only)")
    args = parser.parse_args()
    script = Path(__file__).resolve()
    root = script.parents[4]
    patch_root = root / PATCH_REL
    report: dict = {"script": PATCH_REL.as_posix() + "/verify.py", "version": VERSION,
                    "mode": "cargo-check" if args.cargo_check else "prepare", "commands": [], "patches": []}
    report_path = root / "target/arti-pristine/report.json"
    try:
        if not patch_root.is_dir():
            fail(f"patch bundle directory missing: {PATCH_REL.as_posix()}")
        patch_files = sorted(p for p in patch_root.glob("*/*.patch") if p.is_file())
        if not patch_files:
            fail("no crate patch files found")
        discovered: dict[str, list[dict]] = {}
        for path in patch_files:
            crate = path.parent.name
            parsed = parse_patch(path, crate, root / "vendor")
            discovered.setdefault(crate, []).append({"crate": crate, "stem": path.stem, "relative": path.relative_to(patch_root).as_posix(),
                                                       "parsed": parsed,
                                                       "source_paths": sorted({item["path"] for item in parsed})})
        for crate in discovered:
            discovered[crate] = ordered_patches(crate, discovered[crate])
            for patch in discovered[crate]:
                report["patches"].append({"crate": crate, "file": patch["relative"], "source_paths": patch["source_paths"],
                                          "added_lines": added_line_total(patch),
                                          "dependencies": list(PATCH_DEPENDENCIES.get(patch_id(patch), ()))})
        contents = verify_baselines(root, set(discovered), report)
        for crate, patches in discovered.items():
            prepare_checks(root, crate, contents[crate], patches, patch_root, report, args.individual)
        combined = make_combined_workspace(root, patch_root, discovered, contents, report)
        if args.cargo_check:
            cargo_checks(root, combined, discovered, report)
        report["result"] = "passed"
        report["note"] = "Mechanical patch/archive validation only; no claim of Rust tests passing."
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        print(f"PASS: {len(report['patches'])} patch(es); report target/arti-pristine/report.json")
        return 0
    except (VerifyError, OSError, UnicodeError, subprocess.SubprocessError) as exc:
        report["result"] = "failed"
        report["error"] = str(exc)
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        except OSError:
            pass
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
