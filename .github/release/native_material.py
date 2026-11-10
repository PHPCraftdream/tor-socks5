"""Collect and validate installed Rust native build material.

Callers run rustc --print sysroot, rustc -vV, and
rustc --print target-libdir --target <target>, then pass their stdout to
collect(). The returned payload maps archive paths to exact bytes. validate()
checks bundle structure and self-reported hashes only; compare() additionally
compares the payload byte-for-byte with a separately collected installation.
"""
import hashlib
import json
import os
import re
import stat
import subprocess

ROOT = "native-material/"
DOC_ROOT = ROOT + "share/doc/rust/"
MANIFEST_ROOT = ROOT + "lib/rustlib/"
REQUIRED_DOCS = ("licenses/Apache-2.0.txt", "licenses/MIT.txt",
                 "COPYRIGHT.html", "COPYRIGHT-library.html")
INPUT_SUFFIXES = (".rlib", ".a", ".o", ".lib", ".obj", ".so",
                  ".dylib", ".dll")
REQUIRED_RLIBS = ("libstd", "libcompiler_builtins")
STARTUP_OBJECTS = ("crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o")
TARGET_INPUT_SCOPE = (
    "Hash inventory of regular rlib, native archive, shared-library, and "
    "object files under the selected target libdir; not a linker trace.")
UNESTABLISHED_SCOPE = (
    "The installed Rust material is preserved as distributed; this helper "
    "does not establish which legal text applies to each hashed input or "
    "that the collected material exhausts all applicable terms.")
MUSL_UNESTABLISHED_SCOPE = (
    "Applicable terms for the Rust-distributed self-contained musl libc.a "
    "and startup objects are not established here; host musl-tools/apt "
    "copyright material is not evidence for those inputs.")
PROVENANCE = ROOT + "provenance.json"


def unestablished_scope(target):
    scope = [UNESTABLISHED_SCOPE]
    if target.endswith("-musl"):
        scope.append(MUSL_UNESTABLISHED_SCOPE)
    return scope


class Invalid(ValueError):
    """Installed material or a native-material payload is incomplete/invalid."""


def _fail(message):
    raise Invalid(message)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _safe_relative(path):
    if (not isinstance(path, str) or not path or path.startswith("/") or
            "\\" in path or "\x00" in path or ":" in path):
        return False
    parts = path.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def _read_regular(path, label):
    try:
        mode = os.stat(path, follow_symlinks=False).st_mode
    except OSError as exc:
        _fail("missing installed Rust material %s: %s" % (label, exc))
    if not stat.S_ISREG(mode):
        _fail("installed Rust material is not a regular file: " + label)
    try:
        with open(path, "rb") as stream:
            data = stream.read()
    except OSError as exc:
        _fail("cannot read installed Rust material %s: %s" % (label, exc))
    if not data:
        _fail("installed Rust material is empty: " + label)
    return data


def _rustc_fields(rustc_vv):
    if not isinstance(rustc_vv, str):
        _fail("rustc -vV output must be text")
    fields = {}
    for line in rustc_vv.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in ("release", "commit-hash", "host"):
            if key in fields or not value.strip():
                _fail("invalid rustc -vV field: " + key)
            fields[key] = value.strip()
    for key in ("release", "commit-hash", "host"):
        if key not in fields:
            _fail("rustc -vV lacks required field: " + key)
    if not re.fullmatch(r"[0-9a-f]{40}", fields["commit-hash"]):
        _fail("rustc -vV does not provide an actual 40-digit commit hash")
    return fields


def _target_paths(sysroot, target_libdir, target):
    if (not isinstance(target, str) or "-" not in target or
            not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*[A-Za-z0-9_]", target)):
        _fail("invalid Rust target")
    if not isinstance(sysroot, str) or not sysroot.strip():
        _fail("rustc --print sysroot output is missing")
    if not isinstance(target_libdir, str) or not target_libdir.strip():
        _fail("rustc --print target-libdir output is missing")
    sysroot = os.path.abspath(sysroot.strip())
    expected = os.path.join(sysroot, "lib", "rustlib", target, "lib")
    actual = os.path.abspath(target_libdir.strip())
    try:
        expected_real = os.path.normcase(os.path.realpath(expected))
        actual_real = os.path.normcase(os.path.realpath(actual))
    except OSError as exc:
        _fail("cannot resolve Rust target libdir: %s" % exc)
    if actual_real != expected_real or not os.path.isdir(actual_real):
        _fail("rustc target-libdir does not match selected sysroot/target")
    return sysroot, actual_real, "lib/rustlib/%s/lib" % target


def _manifest_paths(data, target):
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        _fail("Rust standard-library component manifest is not UTF-8: %s" % exc)
    prefix = "lib/rustlib/%s/" % target
    input_files, input_dirs, seen = set(), set(), set()
    for line in lines:
        if not line:
            continue
        kind, separator, path = line.partition(":")
        if kind == "manifest-version":
            if not separator or path != " 2":
                _fail("unsupported Rust component manifest version")
            continue
        if (not separator or kind not in ("file", "dir", "hard-link") or
                not _safe_relative(path) or path in seen):
            _fail("invalid Rust standard-library component manifest entry")
        seen.add(path)
        if not path.startswith(prefix):
            _fail("Rust standard-library manifest does not match target: " + target)
        if path.startswith(prefix + "lib/"):
            if (kind in ("file", "hard-link") and
                    os.path.splitext(path)[1].lower() in INPUT_SUFFIXES):
                input_files.add(path)
            elif kind == "dir":
                input_dirs.add(path.rstrip("/") + "/")
        elif path == prefix + "lib" and kind == "dir":
            input_dirs.add(path + "/")
    if not input_files and not input_dirs:
        _fail("Rust standard-library manifest has no target library inputs")
    return input_files, input_dirs


def _walk_error(exc):
    _fail("cannot enumerate installed Rust material: %s" % exc)


def _input_files(libdir):
    found = {}
    for current, dirs, names in os.walk(libdir, followlinks=False, onerror=_walk_error):
        dirs.sort()
        for name in list(dirs):
            path = os.path.join(current, name)
            if os.path.islink(path):
                _fail("symlink in installed Rust target libdir")
        for name in sorted(names):
            path = os.path.join(current, name)
            suffix = os.path.splitext(name)[1].lower()
            if suffix not in INPUT_SUFFIXES:
                continue
            try:
                mode = os.stat(path, follow_symlinks=False).st_mode
            except OSError as exc:
                _fail("cannot inspect Rust target input %s: %s" % (name, exc))
            if not stat.S_ISREG(mode):
                _fail("Rust target input is not a regular file: " + name)
            rel = os.path.relpath(path, libdir).replace(os.sep, "/")
            if not _safe_relative(rel):
                _fail("unsafe relative Rust target input path")
            try:
                with open(path, "rb") as stream:
                    data = stream.read()
            except OSError as exc:
                _fail("cannot read Rust target input %s: %s" % (rel, exc))
            if not data:
                _fail("Rust target input is empty: " + rel)
            found[rel] = _sha(data)
    return found


def _collect_docs(sysroot):
    docs = {}
    doc_dir = os.path.join(sysroot, "share", "doc", "rust")
    for name in REQUIRED_DOCS:
        rel = DOC_ROOT + name
        docs[rel] = _read_regular(os.path.join(doc_dir, name), rel)

    licenses_dir = os.path.join(doc_dir, "licenses")
    if os.path.lexists(licenses_dir):
        if os.path.islink(licenses_dir) or not os.path.isdir(licenses_dir):
            _fail("installed Rust licenses path is not a regular directory")
        for current, dirs, names in os.walk(licenses_dir, followlinks=False, onerror=_walk_error):
            dirs.sort()
            for name in list(dirs):
                if os.path.islink(os.path.join(current, name)):
                    _fail("symlink in installed Rust licenses tree")
            for name in sorted(names):
                source = os.path.join(current, name)
                relpath = os.path.relpath(source, doc_dir).replace(os.sep, "/")
                if not _safe_relative(relpath) or not relpath.startswith("licenses/"):
                    _fail("unsafe path in installed Rust licenses tree")
                rel = DOC_ROOT + relpath
                docs[rel] = _read_regular(source, rel)
    return docs


def collect(sysroot, rustc_vv, target_libdir, target):
    """Return {archive_path: bytes} for the selected installed Rust target.

    sysroot, rustc_vv, and target_libdir are the respective stdout values from
    the caller's rustc queries. Native inputs are hashed, not copied.
    """
    rustc = _rustc_fields(rustc_vv)
    sysroot, libdir, libdir_rel = _target_paths(sysroot, target_libdir, target)
    manifest_name = "manifest-rust-std-" + target
    manifest_rel = MANIFEST_ROOT + manifest_name
    manifest = _read_regular(
        os.path.join(sysroot, "lib", "rustlib", manifest_name), manifest_rel)
    manifest_files, manifest_dirs = _manifest_paths(manifest, target)
    input_hashes = _input_files(libdir)
    actual_inputs = {libdir_rel + "/" + path for path in input_hashes}
    if any(path not in manifest_files and
           not any(path.startswith(directory) for directory in manifest_dirs)
           for path in actual_inputs):
        _fail("Rust standard-library manifest inputs differ from installed target files")
    if not manifest_dirs and actual_inputs != manifest_files:
        _fail("Rust standard-library manifest inputs differ from installed target files")
    if not manifest_files.issubset(actual_inputs):
        _fail("Rust standard-library manifest lists an absent target input")
    for library in REQUIRED_RLIBS:
        if not any(re.fullmatch(library + r"-[0-9a-f]+\.rlib",
                                path.rsplit("/", 1)[-1])
                   for path in input_hashes):
            _fail("installed Rust target lacks required " + library + " rlib")
    if target.endswith("-musl"):
        if "self-contained/libc.a" not in input_hashes:
            _fail("Rust musl target lacks self-contained libc.a")
        if not any("self-contained/" + name in input_hashes
                   for name in STARTUP_OBJECTS):
            _fail("Rust musl target lacks a self-contained startup object")

    payload = _collect_docs(sysroot)
    payload[manifest_rel] = manifest
    material_hashes = {path: _sha(data) for path, data in sorted(payload.items())}
    inputs = [{"path": libdir_rel + "/" + path, "sha256": digest}
              for path, digest in sorted(input_hashes.items())]
    unresolved = unestablished_scope(target)
    provenance = {
        "schema": 1,
        "rustc": rustc,
        "target": target,
        "target_libdir": libdir_rel,
        "target_input_scope": TARGET_INPUT_SCOPE,
        "target_inputs": inputs,
        "material_sha256": material_hashes,
        "unestablished_scope": unresolved,
    }
    payload[PROVENANCE] = (json.dumps(provenance, sort_keys=True, indent=2) + "\n").encode("utf-8")
    validate(payload, target)
    return payload


def installed(target):
    """Collect native material from the rustc selected by the current PATH."""
    commands = (
        ["rustc", "--print", "sysroot"],
        ["rustc", "-vV"],
        ["rustc", "--print", "target-libdir", "--target", target],
    )
    try:
        outputs = [subprocess.run(command, check=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True).stdout
                   for command in commands]
    except (OSError, subprocess.CalledProcessError) as exc:
        _fail("selected rustc query failed: %s" % exc)
    return collect(outputs[0], outputs[1], outputs[2], target)


def validate(payload, target):
    """Validate payload structure and self-reported hashes, not authenticity."""
    if not isinstance(payload, dict) or not isinstance(target, str):
        _fail("native-material payload must be a path-to-bytes mapping")
    if ("-" not in target or
            not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*[A-Za-z0-9_]", target)):
        _fail("invalid Rust target")
    for path, data in payload.items():
        if (not _safe_relative(path) or not path.startswith(ROOT) or
                not isinstance(data, bytes)):
            _fail("unsafe native-material path or non-byte payload")
    if PROVENANCE not in payload or not payload[PROVENANCE]:
        _fail("native-material provenance is missing or empty")
    for name in REQUIRED_DOCS:
        if not payload.get(DOC_ROOT + name):
            _fail("native-material document is missing or empty: " + name)
    manifest_path = MANIFEST_ROOT + "manifest-rust-std-" + target
    manifest = payload.get(manifest_path)
    if not manifest:
        _fail("native-material target manifest is missing or empty")
    manifest_files, manifest_dirs = _manifest_paths(manifest, target)
    for path in payload:
        if path.startswith(DOC_ROOT + "licenses/") and not payload[path]:
            _fail("native-material license document is empty: " + path)
        if (path.startswith(MANIFEST_ROOT) and path != manifest_path):
            _fail("unexpected native-material component manifest: " + path)
        if (path.startswith(DOC_ROOT) and path not in
                tuple(DOC_ROOT + name for name in REQUIRED_DOCS) and
                not path.startswith(DOC_ROOT + "licenses/")):
            _fail("unexpected native-material Rust document: " + path)
        if (path != PROVENANCE and path != manifest_path and
                not path.startswith(DOC_ROOT)):
            _fail("unexpected native-material payload path: " + path)

    try:
        provenance = json.loads(payload[PROVENANCE].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail("invalid native-material provenance: %s" % exc)
    if not isinstance(provenance, dict) or provenance.get("schema") != 1:
        _fail("unsupported native-material provenance schema")
    if provenance.get("target") != target:
        _fail("native-material provenance target mismatch")
    if provenance.get("target_libdir") != "lib/rustlib/%s/lib" % target:
        _fail("native-material provenance target libdir mismatch")
    rustc = provenance.get("rustc")
    if (not isinstance(rustc, dict) or
            any(not isinstance(rustc.get(key), str) or not rustc[key]
                for key in ("release", "commit-hash", "host")) or
            not re.fullmatch(r"[0-9a-f]{40}", rustc.get("commit-hash", ""))):
        _fail("native-material rustc identity is incomplete")
    if provenance.get("target_input_scope") != TARGET_INPUT_SCOPE:
        _fail("native-material target input scope is missing or invalid")

    expected_materials = {path: _sha(data) for path, data in payload.items()
                          if path != PROVENANCE}
    if provenance.get("material_sha256") != expected_materials:
        _fail("native-material document/manifest integrity mismatch")
    inputs = provenance.get("target_inputs")
    if not isinstance(inputs, list) or not inputs:
        _fail("native-material target input hashes are missing")
    seen = set()
    for item in inputs:
        if not isinstance(item, dict):
            _fail("invalid native-material target input record")
        path, digest = item.get("path"), item.get("sha256")
        prefix = "lib/rustlib/%s/lib/" % target
        if (not _safe_relative(path) or not path.startswith(prefix) or
                os.path.splitext(path)[1].lower() not in INPUT_SUFFIXES or
                path in seen or not isinstance(digest, str) or
                not re.fullmatch(r"[0-9a-f]{64}", digest)):
            _fail("invalid native-material target input hash")
        if (path not in manifest_files and not any(
                path.startswith(directory) for directory in manifest_dirs)):
            _fail("native-material target input is absent from component manifest")
        seen.add(path)
    if not manifest_files.issubset(seen):
        _fail("native-material input hashes omit a manifest-listed target input")
    if any(path not in manifest_files and
           not any(path.startswith(directory) for directory in manifest_dirs)
           for path in seen):
        _fail("native-material input hashes differ from target manifest paths")
    if not manifest_dirs and seen != manifest_files:
        _fail("native-material input hashes differ from target manifest paths")
    for library in REQUIRED_RLIBS:
        if not any(re.fullmatch(library + r"-[0-9a-f]+\.rlib",
                                path.rsplit("/", 1)[-1]) for path in seen):
            _fail("native-material required " + library + " rlib record is missing")
    scope = provenance.get("unestablished_scope")
    if scope != unestablished_scope(target):
        _fail("native-material limits are missing or invalid")
    if target.endswith("-musl"):
        if "lib/rustlib/%s/lib/self-contained/libc.a" % target not in seen:
            _fail("native-material musl libc.a record is missing")
        if not any(path.startswith("lib/rustlib/%s/lib/self-contained/" % target)
                   and path.rsplit("/", 1)[-1] in STARTUP_OBJECTS for path in seen):
            _fail("native-material musl startup-object record is missing")
    return provenance


def compare(payload, reference, target):
    """Validate and require exact equality with an installed build reference."""
    validate(payload, target)
    validate(reference, target)
    if payload != reference:
        _fail("native-material payload differs from installed build reference")
