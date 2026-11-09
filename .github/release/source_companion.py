#!/usr/bin/env python3
import argparse
import hashlib
import io
import json
import os
import posixpath
import re
import stat
import subprocess
import tarfile
import tempfile
import tomllib

TARGETS = (
    "x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
    "aarch64-apple-darwin", "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
)
REQUIRED_PROJECT = ("LICENSE-APACHE", "LICENSE-MIT", "README.md",
                    "Cargo.lock", "vendor/PROVENANCE.md")


class Invalid(Exception):
    pass


def fail(message):
    raise Invalid(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def names(tag, target):
    extension = "zip" if target == "x86_64-pc-windows-msvc" else "tar.gz"
    return ("tor-socks5-%s-%s.%s" % (tag, target, extension),
            "tor-socks5-%s-%s-source.tar.gz" % (tag, target))


def safe_path(path):
    parts = path.split("/")
    return bool(path) and not path.startswith("/") and all(
        part not in ("", ".", "..") for part in parts)


def safe_link(member):
    target = member.linkname
    if not target or target.startswith("/") or "\\" in target or "\x00" in target:
        return False
    resolved = posixpath.normpath(posixpath.join(
        posixpath.dirname(member.name), target))
    return safe_path(resolved) and ":" not in resolved.split("/", 1)[0]


def project_files(data):
    files = {}
    seen = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive.getmembers():
                name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
                if not safe_path(name) or name in seen:
                    fail("unsafe or duplicate project source path: " + member.name)
                seen.add(name)
                if member.isdir():
                    continue
                if member.issym():
                    if not safe_link(member):
                        fail("unsafe project source symlink: " + member.name)
                    continue
                if not member.isfile():
                    fail("unsupported project source entry: " + member.name)
                stream = archive.extractfile(member)
                if stream is None:
                    fail("unreadable project source: " + member.name)
                files[member.name] = stream.read()
    except (OSError, tarfile.TarError) as exc:
        fail("invalid project source archive: %s" % exc)
    for path in REQUIRED_PROJECT:
        if not files.get(path):
            fail("missing or empty project source/material: " + path)
    return files


def lock_data(project):
    files = project_files(project)
    try:
        lock = tomllib.loads(files["Cargo.lock"].decode("utf-8"))
        packages = lock["package"]
    except (UnicodeDecodeError, KeyError, tomllib.TOMLDecodeError) as exc:
        fail("invalid Cargo.lock: %s" % exc)
    if not isinstance(packages, list) or not packages:
        fail("Cargo.lock has no package entries")
    for package in packages:
        if (not isinstance(package, dict) or
                not isinstance(package.get("name"), str) or not package["name"] or
                not isinstance(package.get("version"), str) or not package["version"] or
                ("source" in package and not isinstance(package["source"], str)) or
                ("checksum" in package and not isinstance(package["checksum"], str))):
            fail("invalid Cargo.lock package entry")
    return files, packages


def vendor_files(root):
    result = {}
    modes = {}
    if not os.path.isdir(root):
        fail("Cargo vendor source directory is missing")
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in list(dirs):
            if os.path.islink(os.path.join(current, name)):
                fail("Cargo vendor contains a symlink")
        for name in sorted(files):
            path = os.path.join(current, name)
            if os.path.islink(path) or not os.path.isfile(path):
                fail("Cargo vendor contains a non-regular file")
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            with open(path, "rb") as stream:
                result[rel] = stream.read()
            modes[rel] = stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)
    return result, modes


def supported_external_packages(packages):
    locked = []
    for package in packages:
        source = package.get("source")
        if source is None:
            continue
        if source == "registry+https://github.com/rust-lang/crates.io-index":
            locked.append(package)
        elif source.startswith("git+"):
            fail("git-sourced Cargo.lock packages are not independently supported: " +
                 package["name"])
        else:
            fail("non-crates.io Cargo.lock package source is not independently supported: " +
                 package["name"])
    return locked


def check_vendor(files, packages):
    """Check Cargo-vendor structure and its self-reported hashes, not authenticity."""
    locked = supported_external_packages(packages)
    if not locked:
        fail("Cargo.lock has no external registry source packages")
    expected_roots = set()
    for package in locked:
        root = "%s-%s" % (package["name"], package["version"])
        if not safe_path(root) or "/" in root:
            fail("invalid locked dependency package path: " + root)
        expected_roots.add(root)
    for path in files:
        parts = path.split("/")
        if not safe_path(path) or len(parts) < 2 or parts[0] not in expected_roots:
            fail("Cargo vendor contains an extraneous package root or path: " + path)
    for package in locked:
        root = "%s-%s" % (package["name"], package["version"])
        manifest_path = root + "/Cargo.toml"
        checksum_path = root + "/.cargo-checksum.json"
        if manifest_path not in files or checksum_path not in files:
            fail("locked dependency source missing: " + root)
        try:
            manifest = tomllib.loads(files[manifest_path].decode("utf-8"))
            checksum = json.loads(files[checksum_path].decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
            fail("invalid dependency source metadata for %s: %s" % (root, exc))
        if not isinstance(manifest, dict) or not isinstance(checksum, dict):
            fail("invalid dependency source metadata for " + root)
        package_meta = manifest.get("package", {})
        if not isinstance(package_meta, dict):
            fail("invalid dependency manifest package metadata: " + root)
        license_file = package_meta.get("license-file")
        if license_file is not None:
            if not isinstance(license_file, str) or not license_file:
                fail("invalid declared dependency license file: " + root)
            rel = root + "/" + license_file.replace("\\", "/")
            if not safe_path(rel) or not files.get(rel):
                fail("declared dependency license file missing: " + root)
        if not isinstance(checksum.get("files"), dict):
            fail("invalid Cargo vendor integrity record: " + root)
        if checksum.get("package") != package.get("checksum"):
            fail("Cargo vendor package checksum differs from Cargo.lock: " + root)
        for rel, expected in checksum["files"].items():
            path = root + "/" + rel if isinstance(rel, str) else root + "/"
            data = files.get(path)
            if (not isinstance(rel, str) or not safe_path(rel) or data is None or
                    not isinstance(expected, str) or sha(data) != expected):
                fail("locked dependency source missing or changed: " + path)


def compare_vendor(files, trusted_files):
    """Require byte-for-byte equality with a separately generated Cargo tree."""
    if not trusted_files:
        fail("independent Cargo vendor reference is missing or empty")
    if files != trusted_files:
        missing = sorted(set(trusted_files) - set(files))
        extra = sorted(set(files) - set(trusted_files))
        changed = sorted(path for path in set(files) & set(trusted_files)
                         if files[path] != trusted_files[path])
        details = []
        if missing:
            details.append("missing " + ", ".join(missing[:3]))
        if extra:
            details.append("extra " + ", ".join(extra[:3]))
        if changed:
            details.append("changed " + ", ".join(changed[:3]))
        fail("bundled Cargo vendor differs from independently regenerated reference" +
             (": " + "; ".join(details) if details else ""))


def trusted_vendor(repo_root):
    """Regenerate Cargo's vendor tree using a fresh Cargo home and no bundle config."""
    with tempfile.TemporaryDirectory(prefix="source-companion-") as temporary:
        cargo_home = os.path.join(temporary, "cargo-home")
        os.makedirs(cargo_home)
        vendor_root = os.path.join(temporary, "vendor")
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("CARGO_")}
        env["CARGO_HOME"] = cargo_home
        try:
            subprocess.run(["cargo", "vendor", "--locked", "--versioned-dirs",
                            vendor_root], cwd=repo_root, env=env, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or b"").decode("utf-8", "replace").strip()
            fail("independent cargo vendor failed" + (": " + detail if detail else ""))
        return vendor_files(vendor_root)[0]


def git_project(repo, commit):
    actual = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                            stdout=subprocess.PIPE, text=True).stdout.strip()
    if actual != commit:
        fail("checkout commit does not match requested source commit")
    data = subprocess.run(["git", "archive", "--format=tar", commit], cwd=repo,
                          check=True, stdout=subprocess.PIPE).stdout
    lock_data(data)
    return data


def package(args):
    if not re.fullmatch(r"[0-9a-f]{40,64}", args.commit):
        fail("source commit must be a full hexadecimal object id")
    project = git_project(args.repo_root, args.commit)
    create_companion(args.artifacts_dir, args.tag, args.commit, args.target,
                     project, args.vendor_root)


def create_companion(artifacts_dir, tag, commit, target, project, vendor_root):
    if target not in TARGETS or not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        fail("invalid source companion target or commit")
    files, packages = lock_data(project)
    vendor, vendor_modes = vendor_files(vendor_root)
    check_vendor(vendor, packages)
    binary_name, source_name = names(tag, target)
    binary_path = os.path.join(artifacts_dir, binary_name)
    if not os.path.isfile(binary_path) or os.path.getsize(binary_path) == 0:
        fail("missing or empty binary archive: " + binary_name)
    with open(binary_path, "rb") as stream:
        binary_digest = sha(stream.read())
    metadata = {"schema": 1, "commit": commit, "target": target,
                "lock_sha256": sha(files["Cargo.lock"]),
                "project_archive_sha256": sha(project),
                "binary_archive": binary_name,
                "binary_archive_sha256": binary_digest}
    os.makedirs(artifacts_dir, exist_ok=True)
    output = os.path.join(artifacts_dir, source_name)
    with tarfile.open(output, "w:gz") as archive:
        info = tarfile.TarInfo("project.tar")
        info.size = len(project)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(project))
        for path, data in sorted(vendor.items()):
            info = tarfile.TarInfo("cargo-vendor/" + path)
            info.size = len(data)
            info.mode = vendor_modes[path]
            archive.addfile(info, io.BytesIO(data))
        content = (json.dumps(metadata, sort_keys=True, indent=2) + "\n").encode()
        info = tarfile.TarInfo("SOURCE-MATERIALS.json")
        info.size = len(content)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(content))
    with open(output, "rb") as stream:
        digest = sha(stream.read())
    with open(output + ".sha256", "w", encoding="ascii", newline="\n") as stream:
        stream.write("%s  %s\n" % (digest, source_name))


def verify_bundle(path, tag, target, commit, project, artifacts_dir,
                  trusted_vendor_files):
    binary_name, source_name = names(tag, target)
    with open(path, "rb") as stream:
        digest = sha(stream.read())
    with open(path + ".sha256", "rb") as stream:
        if stream.read() != ("%s  %s\n" % (digest, source_name)).encode("ascii"):
            fail("source companion checksum mismatch: " + source_name)
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = {}
            for member in archive.getmembers():
                if not safe_path(member.name) or member.name in members or not member.isfile():
                    fail("unsafe, duplicate, or unsupported companion entry: " + member.name)
                stream = archive.extractfile(member)
                if stream is None:
                    fail("unreadable companion entry: " + member.name)
                members[member.name] = stream.read()
    except (OSError, tarfile.TarError) as exc:
        fail("invalid source companion archive: %s" % exc)
    if "project.tar" not in members or "SOURCE-MATERIALS.json" not in members:
        fail("source companion lacks project source or metadata")
    for name in members:
        if name not in ("project.tar", "SOURCE-MATERIALS.json"):
            if not name.startswith("cargo-vendor/") or not safe_path(name[len("cargo-vendor/"):]):
                fail("unexpected source companion entry: " + name)
    try:
        metadata = json.loads(members["SOURCE-MATERIALS.json"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail("invalid source companion metadata: %s" % exc)
    if not isinstance(metadata, dict):
        fail("source companion metadata must be a JSON object")
    if metadata.get("schema") != 1 or metadata.get("commit") != commit:
        fail("source companion commit/schema mismatch: " + source_name)
    if metadata.get("target") != target or metadata.get("binary_archive") != binary_name:
        fail("source companion target/binary mismatch: " + source_name)
    source = members["project.tar"]
    files, packages = lock_data(source)
    if source != project or metadata.get("project_archive_sha256") != sha(project):
        fail("source companion project differs from release checkout")
    if metadata.get("lock_sha256") != sha(files["Cargo.lock"]):
        fail("source companion Cargo.lock mismatch")
    vendor = {name[len("cargo-vendor/"):]: content
              for name, content in members.items() if name.startswith("cargo-vendor/")}
    check_vendor(vendor, packages)
    compare_vendor(vendor, trusted_vendor_files)
    with open(os.path.join(artifacts_dir, binary_name), "rb") as stream:
        if sha(stream.read()) != metadata.get("binary_archive_sha256"):
            fail("source companion binary digest mismatch: " + source_name)


def verify(args):
    if not re.fullmatch(r"[0-9a-f]{40,64}", args.commit):
        fail("source commit must be a full hexadecimal object id")
    project = git_project(args.repo_root, args.commit)
    project_files, packages = lock_data(project)
    supported_external_packages(packages)
    lock_path = os.path.join(args.repo_root, "Cargo.lock")
    with open(lock_path, "rb") as stream:
        checkout_lock = stream.read()
    if checkout_lock != project_files["Cargo.lock"]:
        fail("working checkout Cargo.lock differs from the requested Git commit")
    trusted_files = trusted_vendor(args.repo_root)
    if not trusted_files:
        fail("independent Cargo vendor reference is missing or empty")
    check_vendor(trusted_files, packages)
    targets = (args.target,) if args.target else TARGETS
    for target in targets:
        _, source_name = names(args.tag, target)
        path = os.path.join(args.artifacts_dir, source_name)
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            fail("missing or empty source companion: " + source_name)
        verify_bundle(path, args.tag, target, args.commit, project,
                      args.artifacts_dir, trusted_files)


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("package", "verify"):
        item = sub.add_parser(command)
        item.add_argument("--artifacts-dir", required=True)
        item.add_argument("--tag", required=True)
        item.add_argument("--commit", required=True)
        if command == "package":
            item.add_argument("--repo-root", required=True)
            item.add_argument("--vendor-root", required=True)
            item.add_argument("--target", choices=TARGETS, required=True)
        else:
            item.add_argument("--repo-root", required=True)
            item.add_argument("--target", choices=TARGETS)
    args = parser.parse_args(argv)
    try:
        package(args) if args.command == "package" else verify(args)
    except (Invalid, OSError, subprocess.CalledProcessError) as exc:
        parser.exit(1, "source companion: %s\n" % exc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
