#!/usr/bin/env python3
"""Collect Git-bound source candidates; this is not release admission or provenance."""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

SDK_COMMIT = 'e754abaa88ce4f9745b4729652789ffc57f8ba4c'
OID = re.compile(r'^[0-9a-f]{40}$')
MAX_FILE = 100 * 1024 * 1024
MAX_ENTRIES = 100000


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


def object_id(kind, data):
    return hashlib.sha1(kind.encode('ascii') + b' ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()


def safe(name):
    if (not isinstance(name, str) or not name or len(name) > 4096 or '\\' in name or
            len(name.split('/')) > 128 or any(not p or p in ('.', '..') or ':' in p or
            any(ord(c) < 32 or ord(c) == 127 for c in p) for p in name.split('/'))):
        raise ValueError('unsafe source path: ' + repr(name))
    return name


def commit_tree(raw, commit):
    if not isinstance(commit, str) or not OID.fullmatch(commit) or object_id('commit', raw) != commit:
        raise ValueError('invalid commit object proof')
    lines = raw.split(b'\n')
    if not lines or not re.fullmatch(b'tree [0-9a-f]{40}', lines[0]):
        raise ValueError('invalid commit tree header')
    return lines[0][5:].decode('ascii')


def snapshot_git(root, expected_commit=None):
    """Return (proof, bytes by relative path); require checkout and index match HEAD."""
    root = Path(root).resolve(strict=True)
    commit = git(root, 'rev-parse', '--verify', 'HEAD^{commit}').strip().decode('ascii')
    if expected_commit is not None and commit != expected_commit:
        raise ValueError('checkout commit mismatch')
    raw_commit = git(root, 'cat-file', 'commit', commit)
    tree = commit_tree(raw_commit, commit)
    index = {}
    for entry in git(root, 'ls-files', '--stage', '-z').split(b'\0'):
        if entry:
            meta, name = entry.split(b'\t', 1)
            mode, oid, stage = meta.split(b' ')
            name = safe(name.decode('utf-8'))
            if stage != b'0' or name in index:
                raise ValueError('unmerged index')
            index[name] = (mode.decode('ascii'), oid.decode('ascii'))
    if git(root, 'ls-files', '--others', '--exclude-standard', '-z'):
        raise ValueError('untracked source inputs')
    records, contents, seen = [], {}, set()
    for entry in git(root, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
        if not entry:
            continue
        meta, raw_name = entry.split(b'\t', 1)
        mode, kind, oid = meta.split(b' ')
        name = safe(raw_name.decode('utf-8'))
        mode, oid = mode.decode('ascii'), oid.decode('ascii')
        if (mode not in ('100644', '100755') or kind != b'blob' or not OID.fullmatch(oid)
                or name.casefold() in seen or index.get(name) != (mode, oid)):
            raise ValueError('unsupported tree, collision, or changed index: ' + name)
        seen.add(name.casefold())
        path = root
        for part in name.split('/'):
            path = path / part
            if path.is_symlink():
                raise ValueError('symlink in source: ' + name)
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            raise ValueError('missing or oversized source: ' + name)
        data = path.read_bytes()
        blob = git(root, 'cat-file', 'blob', oid)
        if data != blob or object_id('blob', blob) != oid:
            raise ValueError('checkout differs from Git blob: ' + name)
        if os.name != 'nt' and bool(path.stat().st_mode & 0o111) != (mode == '100755'):
            raise ValueError('checkout executable mode mismatch: ' + name)
        contents[name] = data
        records.append({'path': name, 'oid': oid, 'mode': mode, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)})
        if len(records) > MAX_ENTRIES:
            raise ValueError('too many source files')
    if set(index) != set(contents):
        raise ValueError('index differs from commit tree')
    proof = {'commit': commit, 'tree': tree, 'commit_object': base64.b64encode(raw_commit).decode('ascii'), 'files': sorted(records, key=lambda x: x['path'])}
    if tree_hash(records) != tree:
        raise ValueError('Git tree reconstruction mismatch')
    return proof, contents


def tree_hash(records):
    root = {}
    seen = set()
    for record in records:
        name = safe(record['path'])
        if name.casefold() in seen:
            raise ValueError('duplicate source path')
        seen.add(name.casefold())
        node = root
        parts = name.split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise ValueError('source file/directory collision')
        if parts[-1] in node:
            raise ValueError('source file/directory collision')
        mode, oid = record['mode'], record['oid']
        if mode not in ('100644', '100755') or not isinstance(oid, str) or not OID.fullmatch(oid):
            raise ValueError('invalid Git tree entry')
        node[parts[-1]] = (mode, oid)
    def encode(node):
        entries = []
        for name, value in node.items():
            raw = name.encode('utf-8')
            if isinstance(value, dict):
                mode, oid, sortkey = '40000', encode(value), raw + b'/'
            else:
                mode, oid = value
                sortkey = raw
            entries.append((sortkey, mode.encode('ascii') + b' ' + raw + b'\0' + bytes.fromhex(oid)))
        return object_id('tree', b''.join(entry for _, entry in sorted(entries)))
    return encode(root)


def verify_sources(payload, tag, expected_project_commit=None, sdk_expected=SDK_COMMIT):
    """Verify source objects; project origin is unanchored unless expected commit is supplied.

    sdk_expected is for synthetic format tests; production callers must use the default.
    Return the authoritative payload-path-to-Git-mode mapping.
    """
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    metadata = json.loads(payload['GIT-SOURCES.json'], object_pairs_hook=pairs)
    if not isinstance(metadata, dict) or set(metadata) != {'schema', 'project', 'sdk'} or metadata['schema'] != 1:
        raise ValueError('invalid Git sources metadata')
    modes = {}
    for name, expected in (('project', expected_project_commit), ('sdk', sdk_expected)):
        proof = metadata[name]
        if not isinstance(proof, dict) or set(proof) != {'commit', 'tree', 'commit_object', 'files'}:
            raise ValueError('invalid source proof')
        commit = proof['commit']
        if expected is not None and commit != expected:
            raise ValueError('source commit mismatch: ' + name)
        raw = base64.b64decode(proof['commit_object'], validate=True)
        if commit_tree(raw, commit) != proof['tree']:
            raise ValueError('commit tree mismatch')
        records = proof['files']
        if not isinstance(records, list) or len(records) > MAX_ENTRIES:
            raise ValueError('invalid source records')
        if tree_hash(records) != proof['tree']:
            raise ValueError('source tree mismatch')
        prefix = 'sources/' + tag + '/' + name + '/'
        for record in records:
            if set(record) != {'path', 'oid', 'mode', 'sha256', 'size'}:
                raise ValueError('invalid source record')
            path = prefix + safe(record['path'])
            data = payload[path]
            if (type(record['size']) is not int or record['size'] != len(data) or
                    record['sha256'] != hashlib.sha256(data).hexdigest() or object_id('blob', data) != record['oid']):
                raise ValueError('source blob mismatch: ' + path)
            modes[path] = record['mode']
        if {p for p in payload if p.startswith(prefix)} != {p for p in modes if p.startswith(prefix)}:
            raise ValueError('source set mismatch: ' + name)
    return modes


def collect(project, sdk, output, project_commit=None):
    project_proof, project_data = snapshot_git(project, project_commit)
    sdk_proof, sdk_data = snapshot_git(sdk, SDK_COMMIT)
    items = [('project/' + n, d, r['mode'] == '100755') for r in project_proof['files'] for n, d in [(r['path'], project_data[r['path']])]]
    items += [('sdk/' + n, d, r['mode'] == '100755') for r in sdk_proof['files'] for n, d in [(r['path'], sdk_data[r['path']])]]
    if not any(n.startswith('project/vendor/') for n, _, _ in items) or not any(n == 'project/Cargo.lock' for n, _, _ in items) or not any(n.startswith('sdk/crates/resocks5-net/') for n, _, _ in items):
        raise ValueError('required source inputs missing')
    records = [{'path': n, 'sha256': hashlib.sha256(d).hexdigest(), 'size': len(d), 'executable': x} for n, d, x in sorted(items)]
    manifest = json.dumps({'schema': 1, 'status': 'SOURCE INVENTORY; NOT A RELEASE BUNDLE', 'sdk_commit': SDK_COMMIT, 'files': records}, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode() + b'\n'
    proof = json.dumps({'schema': 1, 'project': project_proof, 'sdk': sdk_proof}, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode() + b'\n'
    with open(output, 'xb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for name, data, executable in sorted(items + [('INVENTORY.json', manifest, False), ('GIT-SOURCES.json', proof, False)]):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime, info.uid, info.gid = len(data), 0o755 if executable else 0o644, 0, 0, 0
                    info.uname = info.gname = ''
                    tar.addfile(info, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--project-commit')
    args = parser.parse_args()
    try:
        collect(args.project, args.sdk, args.output, args.project_commit)
    except (OSError, ValueError, UnicodeError, subprocess.CalledProcessError) as exc:
        parser.exit(1, 'source inventory failed: ' + str(exc) + '\n')


if __name__ == '__main__':
    main()
