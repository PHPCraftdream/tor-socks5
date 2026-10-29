#!/usr/bin/env python3
"""Prepare and verify a source/review candidate; not a release compliance decision.

Run with python -I. prepare creates a new output directory with candidate.tar.gz
and standalone reports. --reviews is optional JSON:
{"components": {ID: {"source_digest": HEX, "selected_license": LICENSE,
"rationale": TEXT, "obligations": TEXT, "notices": [REF], "evidence": [REF],
"retained_notices": [REF], "corresponding_source": [REF]}}}, where REF is
{"path": PAYLOAD_PATH, "sha256": HEX}. Supported licenses are MIT, Apache-2.0,
BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0 and Zlib, as single licenses or
OR branches composed solely of these licenses. All candidate texts must be
retained. Vendors without candidates using a project root license require an
attribution_review entry for every source file: REF plus a nonempty rationale.
MPL, CDLA, LGPL and other expressions remain blocked pending legal evidence.
Records bind bytes but do not establish legal completeness or human review.
Tracked .github/release/license/reviews/ files remain in the source archive and
manifest but are excluded from the project source digest to avoid a review cycle;
their bytes are separately bound by the manifest. verify reports review blockers
and exits nonzero when any component lacks review.
Registry cache follows Cargo's cache/<registry>/<name>-<version>.crate layout.
"""
import argparse
import gzip
import hashlib
import io
import importlib.util
import json
import re
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

_spec = importlib.util.spec_from_file_location('source_inventory', Path(__file__).with_name('source_inventory.py'))
source_inventory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(source_inventory)
SDK_COMMIT = source_inventory.SDK_COMMIT
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
CANDIDATE = re.compile(r'^(license|licence|copying|notice|copyright|unlicense|mpl|lgpl|gpl|apache|mit)(?:$|[-._])', re.I)
IDENT = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.+\-]*$')
HEX = re.compile(r'^[0-9a-f]{64}$')
MAX_FILE = 100 * 1024 * 1024
MAX_STREAM = 512 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 100000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def encoded(obj):
    return (json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')


def safe(path):
    if not isinstance(path, str) or not path or len(path) > 4096 or '\\' in path:
        raise ValueError('unsafe path: ' + repr(path))
    parts = path.split('/')
    if len(parts) > 128 or any(not p or p in ('.', '..') or ':' in p or any(ord(c) < 32 or ord(c) == 127 for c in p) for p in parts):
        raise ValueError('unsafe path: ' + repr(path))
    return path


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


SUPPORTED = {'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'Unicode-3.0', 'Zlib'}
MODES = {}


def tracked(root, prefix):
    result = {}
    seen = set()
    for entry in git(root, 'ls-files', '--stage', '-z').split(b'\0'):
        if not entry:
            continue
        meta, raw = entry.split(b'\t', 1)
        mode, _, stage = meta.split(b' ')
        if mode not in (b'100644', b'100755') or stage != b'0':
            raise ValueError('unsupported tracked mode or conflict')
        name = safe(raw.decode('utf-8'))
        if name.casefold() in seen:
            raise ValueError('tracked path collision: ' + name)
        seen.add(name.casefold())
        path = root
        for part in name.split('/'):
            path = path / part
            if path.is_symlink():
                raise ValueError('tracked symlink: ' + name)
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            raise ValueError('missing or oversized tracked file: ' + name)
        result[prefix + '/' + name] = path.read_bytes()
        MODES[prefix + '/' + name] = 0o755 if mode == b'100755' else 0o644
    return result


class Limited:
    def __init__(self, stream, limit):
        self.stream, self.left = stream, limit

    def read(self, size=-1):
        if size < 0:
            size = self.left + 1
        data = self.stream.read(min(size, self.left + 1))
        self.left -= len(data)
        if self.left < 0:
            raise ValueError('decompressed stream exceeds limit')
        return data


def read_tar(data, limit=MAX_STREAM, root=None, files_only=False, modes=None, max_member=MAX_FILE):
    if len(data) > MAX_TOTAL:
        raise ValueError('archive too large')
    result, seen, regular, parents = {}, set(), set(), set()
    total = count = 0
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode='rb') as gz:
        stream = Limited(gz, limit)
        with tarfile.open(fileobj=stream, mode='r|') as tar:
            for m in tar:
                count += 1
                if count > MAX_ENTRIES:
                    raise ValueError('too many tar entries')
                name = safe(m.name)
                parts = name.split('/')
                key = name.casefold()
                ancestor = {'/'.join(parts[:i]).casefold() for i in range(1, len(parts))}
                if (key in seen or ancestor & regular or (m.isfile() and key in parents)
                        or not (m.isfile() or (m.isdir() and not files_only))
                        or (root is not None and parts[0] != root)):
                    raise ValueError('unsafe or duplicate tar member: ' + name)
                seen.add(key)
                parents.update(ancestor)
                if m.isfile():
                    regular.add(key)
                    total += m.size
                    if m.size > max_member or total > limit:
                        raise ValueError('tar content exceeds limit')
                    content = tar.extractfile(m).read()
                    if len(content) != m.size:
                        raise ValueError('truncated member: ' + name)
                    result[name] = content
                    if modes is not None:
                        modes[name] = m.mode
        while stream.read(65536):
            pass
    return result


def source_digest(payload, paths):
    return digest(encoded([{'path': p, 'sha256': digest(payload[p]), 'size': len(payload[p])} for p in sorted(paths)]))


def build(project, sdk, cache, tag, project_commit=None):
    project, sdk = project.resolve(strict=True), sdk.resolve(strict=True)
    if not IDENT.fullmatch(tag):
        raise ValueError('invalid tag')
    MODES.clear()
    base = 'sources/' + tag + '/'
    project_proof, project_data = source_inventory.snapshot_git(project, project_commit)
    sdk_proof, sdk_data = source_inventory.snapshot_git(sdk, SDK_COMMIT)
    payload = {}
    for name, proof, data in (('project', project_proof, project_data), ('sdk', sdk_proof, sdk_data)):
        for record in proof['files']:
            path = base + name + '/' + record['path']
            payload[path] = data[record['path']]
            MODES[path] = int(record['mode'][-3:], 8)
    payload['GIT-SOURCES.json'] = encoded({'schema': 1, 'project': project_proof, 'sdk': sdk_proof})
    lock = base + 'project/Cargo.lock'
    if lock not in payload or not any(p.startswith(base + 'project/vendor/') for p in payload) or not any(p.startswith(base + 'sdk/crates/resocks5-net/') for p in payload):
        raise ValueError('missing tracked lock, vendor or SDK net sources')
    for license_name in ('LICENSE-MIT', 'LICENSE-APACHE'):
        if base + 'project/' + license_name not in payload:
            raise ValueError('missing project license: ' + license_name)
    components, inventory, copies = reconstruct(payload, tag, cache)
    payload.update(copies)
    return payload, components, inventory


def reconstruct(payload, tag, cache=None):
    if not isinstance(tag, str) or not IDENT.fullmatch(tag):
        raise ValueError('invalid tag')
    base = 'sources/' + tag + '/'
    lock = base + 'project/Cargo.lock'
    if lock not in payload or not any(p.startswith(base + 'project/vendor/') for p in payload) or not any(p.startswith(base + 'sdk/crates/resocks5-net/') for p in payload):
        raise ValueError('missing tracked lock, vendor or SDK net sources')
    for license_name in ('LICENSE-MIT', 'LICENSE-APACHE'):
        if base + 'project/' + license_name not in payload:
            raise ValueError('missing project license: ' + license_name)
    components = []
    vendor = base + 'project/vendor/'
    root_manifest = base + 'project/Cargo.toml'
    root = tomllib.loads(payload[root_manifest].decode('utf-8'))
    patches = root.get('patch', {}).get('crates-io', {})
    vendor_dirs = set()
    for patch in patches.values():
        if isinstance(patch, dict) and 'path' in patch:
            path = safe(patch['path'])
            parts = path.split('/')
            if len(parts) != 2 or parts[0] != 'vendor' or parts[1] in vendor_dirs:
                raise ValueError('unsupported or duplicate patch path: ' + path)
            vendor_dirs.add(parts[1])
            if vendor + parts[1] + '/Cargo.toml' not in payload:
                raise ValueError('missing patch manifest: ' + path)
    groups = [('project', [p for p in payload if p.startswith(base + 'project/')
                            and not any(p.startswith(vendor + d + '/') for d in vendor_dirs)]),
              ('sdk', [p for p in payload if p.startswith(base + 'sdk/')])]
    groups += [('vendor:' + d, [p for p in payload if p.startswith(vendor + d + '/')]) for d in sorted(vendor_dirs)]
    for kind, paths in groups:
        paths = sorted(paths)
        manifest_path = (root_manifest if kind == 'project' else
                         base + 'sdk/Cargo.toml' if kind == 'sdk' else
                         vendor + kind[7:] + '/Cargo.toml')
        manifest = tomllib.loads(payload[manifest_path].decode('utf-8')) if manifest_path in payload else {}
        license_value = manifest.get('package', {}).get('license')
        if isinstance(license_value, dict) and license_value.get('workspace') is True:
            license_value = root.get('workspace', {}).get('package', {}).get('license') if kind.startswith('vendor:') else manifest.get('workspace', {}).get('package', {}).get('license')
        if kind in ('project', 'sdk'):
            license_value = manifest.get('workspace', {}).get('package', {}).get('license', license_value)
        digest_paths = [p for p in paths if not (kind == 'project' and p.startswith(base + 'project/.github/release/license/reviews/'))]
        components.append({'id': kind, 'source_paths': paths, 'source_digest': source_digest(payload, digest_paths),
                           'declared_license': license_value,
                           'candidates': [p for p in paths if CANDIDATE.match(p.rsplit('/', 1)[-1])]})
    copies = {}
    packages = tomllib.loads(payload[lock].decode('utf-8'))['package']
    if len(packages) > 10000:
        raise ValueError('too many packages')
    identities = set()
    for pkg in packages:
        name, version = pkg['name'], pkg['version']
        if not isinstance(name, str) or not isinstance(version, str) or not IDENT.fullmatch(name) or not IDENT.fullmatch(version):
            raise ValueError('invalid package identity')
        source = pkg.get('source')
        if source is None:
            continue
        if source != REGISTRY:
            raise ValueError('unsupported Cargo source: ' + str(source))
        stem = name + '-' + version
        if stem.casefold() in identities:
            raise ValueError('duplicate package: ' + stem)
        identities.add(stem.casefold())
        checksum = pkg.get('checksum', '')
        if not isinstance(checksum, str) or not HEX.fullmatch(checksum):
            raise ValueError('invalid checksum: ' + stem)
        archive = base + 'registry/' + stem + '.crate'
        if cache is not None:
            matches = list(cache.glob('*/' + stem + '.crate'))
            if len(matches) != 1 or matches[0].is_symlink() or matches[0].parent.is_symlink() or not matches[0].is_file() or matches[0].stat().st_size > MAX_FILE:
                raise ValueError('missing or ambiguous cache archive: ' + stem)
            data = matches[0].read_bytes()
        else:
            data = payload[archive]
        if digest(data) != checksum:
            raise ValueError('checksum mismatch: ' + stem)
        members = read_tar(data, root=stem)
        copies[archive] = data
        selected = {n for n in members if CANDIDATE.match(n.rsplit('/', 1)[-1])}
        manifest_name = stem + '/Cargo.toml'
        if manifest_name not in members:
            raise ValueError('missing crate manifest: ' + stem)
        if manifest_name in members:
            meta = tomllib.loads(members[manifest_name].decode('utf-8')).get('package', {})
            if meta.get('name') != name or meta.get('version') != version:
                raise ValueError('crate identity mismatch: ' + stem)
            if 'license-file' in meta:
                target = stem + '/' + safe(meta['license-file'])
                if target not in members:
                    raise ValueError('missing license-file: ' + target)
                selected.add(target)
        candidates = []
        for n in sorted(selected):
            path = base + 'candidates/' + n
            copies[path] = members[n]
            candidates.append(path)
        components.append({'id': 'registry:' + stem, 'name': name, 'version': version, 'source': source,
                           'checksum': checksum, 'source_paths': [archive], 'declared_license': meta.get('license'),
                           'source_digest': source_digest(copies, [archive]), 'candidates': candidates})
    inventory = [{'name': p['name'], 'version': p['version'], 'source': p.get('source')} for p in packages]
    return components, inventory, copies


def blockers(components, reviews, payload):
    if not isinstance(reviews, dict) or not isinstance(reviews.get('components'), dict):
        raise ValueError('invalid reviews JSON')
    records = reviews['components']
    ids = {c['id'] for c in components}
    if set(records) - ids:
        raise ValueError('unknown reviewed component')
    problems = []
    for c in components:
        ident = c['id']
        if ident.startswith('vendor:') and not c['candidates']:
            problems.append(ident + ': missing attributable notice text')
        r = records.get(ident)
        if not isinstance(r, dict):
            problems.append(ident + ': missing review')
            continue
        if r.get('source_digest') != c['source_digest']:
            problems.append(ident + ': source digest mismatch')
        selected = r.get('selected_license')
        declared = c.get('declared_license')
        branches = declared.split(' OR ') if isinstance(declared, str) else []
        if (not branches or any(branch not in SUPPORTED for branch in branches)
                or len(set(branches)) != len(branches) or selected not in branches):
            problems.append(ident + ': unsupported license selection or declaration; legal evidence pending')
        for field in ('rationale', 'obligations'):
            if not isinstance(r.get(field), str) or not r[field].strip():
                problems.append(ident + ': missing ' + field)
        source = set(c['source_paths'] + c['candidates'])
        notices = set(c['candidates'])
        if ident.startswith('vendor:'):
            entries = r.get('attribution_review')
            covered = set()
            if isinstance(entries, list):
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    path = entry.get('path')
                    if (isinstance(path, str) and path in c['source_paths'] and path not in covered
                            and entry.get('sha256') == digest(payload[path])
                            and isinstance(entry.get('rationale'), str) and entry['rationale'].strip()):
                        covered.add(path)
            if not isinstance(entries, list) or len(entries) != len(covered) or covered != set(c['source_paths']):
                problems.append(ident + ': missing per-file attribution review')
        selected_notices = {e.get('path') for e in r.get('notices', []) if isinstance(e, dict) and isinstance(e.get('path'), str)} if isinstance(r.get('notices'), list) else set()
        if c['candidates'] and (selected_notices != notices or
                not isinstance(r.get('retained_notices'), list) or
                {e.get('path') for e in r['retained_notices'] if isinstance(e, dict)} != notices):
            problems.append(ident + ': all candidate texts must be noticed and retained')
        for field, allowed in (('notices', notices), ('evidence', source),
                               ('retained_notices', notices & selected_notices),
                               ('corresponding_source', set(c['source_paths']))):
            entries = r.get(field)
            if not isinstance(entries, list) or not entries:
                problems.append(ident + ': missing ' + field)
                continue
            seen = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    problems.append(ident + ': invalid ' + field)
                    continue
                path = entry.get('path')
                if not isinstance(path, str) or path not in allowed or path in seen or entry.get('sha256') != digest(payload[path]):
                    problems.append(ident + ': invalid ' + field + ' bytes')
                else:
                    seen.add(path)
    return problems


def pack(payload, output):
    source_modes = strict_json(payload['SOURCE-MODES.json']) if 'SOURCE-MODES.json' in payload else {}
    with open(output, 'xb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for name, data in sorted(payload.items()):
                    safe(name)
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime, info.uid, info.gid = len(data), int(source_modes.get(name, '100644')[-3:], 8), 0, 0, 0
                    info.uname = info.gname = ''
                    tar.addfile(info, io.BytesIO(data))


def canonical_reports(payload, components, tag):
    problems = []
    notices = [b'Candidate source texts; not a completeness or legal determination. Inventory is not evidence of linkage.\n']
    for c in components:
        provenance = (c.get('source', 'SDK pinned commit ' + SDK_COMMIT if c['id'] == 'sdk'
                            else 'tracked source in candidate; origin not independently established'))
        notices.append(('\n=== ' + c['id'] + ' ===\nSource digest: ' + c['source_digest'] +
                        '\nProvenance: ' + provenance + '\n').encode('utf-8'))
        for path in c['candidates']:
            try:
                payload[path].decode('utf-8')
            except UnicodeDecodeError:
                problems.append(c['id'] + ': invalid UTF-8 candidate: ' + path)
                continue
            notices.extend([('\n--- ' + c['id'] + ' ' + path + ' ---\n').encode('utf-8'), payload[path], b'\n'])
    url = 'https://github.com/PHPCraftdream/tor-socks5/releases/download/' + tag + '/tor-socks5-' + tag + '-license-bundle.tar.gz'
    source_info = ('Tag: ' + tag + '\nDownload the tagged bundle: ' + url + '\n'
        'Download its SHA-256 checksum: ' + url + '.sha256\n'
        'Verify the bundle SHA-256 against that checksum, then open targets/<your Rust target>/candidate.tar.gz in the outer bundle.\n'
        'Extract sources/' + tag + '/ from that candidate; SOURCE-MODES.json records tracked source modes.\n'
        'Registry archives correspond to the current Cargo.lock; historical cargo-evidence.zip is not source.\n'
        'Retain sources and notices on redistribution; a link alone is not a guarantee.\n'
        'Inventory is not evidence of linkage; native, platform and build inputs require separate review.\n').encode('utf-8')
    return b''.join(notices), source_info, problems


def prepare(project, sdk, cache, output, tag, reviews, project_commit=None):
    payload, components, inventory = build(project, sdk, cache, tag, project_commit)
    review_data = strict_json(reviews.read_text(encoding='utf-8')) if reviews else {'components': {}}
    problems = blockers(components, review_data, payload)
    notices, source_info, candidate_problems = canonical_reports(payload, components, tag)
    problems.extend(candidate_problems)
    payload['NOTICES.txt'], payload['SOURCE-INFO.txt'] = notices, source_info
    payload['SOURCE-MODES.json'] = encoded({p: '100755' if mode == 0o755 else '100644' for p, mode in sorted(MODES.items()) if p in payload})
    payload['REVIEWS.json'] = encoded(review_data)
    payload['BLOCKERS.json'] = encoded(problems)
    manifest = {'schema': 1, 'tag': tag, 'sdk_commit': SDK_COMMIT, 'packages': inventory, 'components': components,
                'files': [{'path': p, 'size': len(d), 'sha256': digest(d)} for p, d in sorted(payload.items())]}
    payload['MANIFEST.json'] = encoded(manifest)
    if sum(map(len, payload.values())) > MAX_TOTAL:
        raise ValueError('bundle too large')
    output.mkdir()
    pack(payload, output / 'candidate.tar.gz')
    for name in ('NOTICES.txt', 'SOURCE-INFO.txt', 'SOURCE-MODES.json', 'GIT-SOURCES.json', 'MANIFEST.json', 'REVIEWS.json', 'BLOCKERS.json'):
        (output / name).write_bytes(payload[name])
    return problems


def verify_format(path, expected_project_commit, sdk_expected):
    """Check candidate format against explicit source anchors, not provenance."""
    if path.stat().st_size > MAX_TOTAL:
        raise ValueError('bundle too large')
    modes = {}
    payload = read_tar(path.read_bytes(), limit=MAX_TOTAL, files_only=True, modes=modes)
    manifest = strict_json(payload.pop('MANIFEST.json'))
    if manifest['schema'] != 1 or manifest['sdk_commit'] != sdk_expected:
        raise ValueError('unsupported manifest')
    records = manifest['files']
    expected = {}
    for r in records:
        p = safe(r['path'])
        if p in expected or p == 'MANIFEST.json':
            raise ValueError('duplicate manifest path')
        expected[p] = r
    if set(expected) != set(payload):
        raise ValueError('manifest payload set mismatch')
    for p, data in payload.items():
        if expected[p]['size'] != len(data) or expected[p]['sha256'] != digest(data):
            raise ValueError('payload mismatch: ' + p)
    git_modes = source_inventory.verify_sources(payload, manifest['tag'], expected_project_commit, sdk_expected=sdk_expected)
    components, inventory, copies = reconstruct(payload, manifest['tag'])
    if manifest['components'] != components or manifest['packages'] != inventory:
        raise ValueError('component or lock inventory mismatch')
    tracked_paths = {p for c in components if not c['id'].startswith('registry:') for p in c['source_paths']}
    source_modes = strict_json(payload['SOURCE-MODES.json'])
    if (not isinstance(source_modes, dict) or source_modes != git_modes or set(source_modes) != tracked_paths or
            any(value not in ('100644', '100755') or modes[p] != int(value[-3:], 8)
                for p, value in source_modes.items())):
        raise ValueError('source mode mismatch')
    if any(mode != 0o644 for p, mode in modes.items() if p not in tracked_paths):
        raise ValueError('unexpected archive mode')
    base = 'sources/' + manifest['tag'] + '/'
    actual = {p for p in payload if p.startswith(base + 'registry/') or p.startswith(base + 'candidates/')}
    if actual != set(copies) or any(payload[p] != data for p, data in copies.items()):
        raise ValueError('registry or candidate mismatch')
    allowed = set(copies) | {p for c in components for p in c['source_paths']} | {'NOTICES.txt', 'SOURCE-INFO.txt', 'SOURCE-MODES.json', 'GIT-SOURCES.json', 'REVIEWS.json', 'BLOCKERS.json'}
    if set(payload) != allowed:
        raise ValueError('unexpected payload')
    notices, source_info, candidate_problems = canonical_reports(payload, components, manifest['tag'])
    if payload['NOTICES.txt'] != notices or payload['SOURCE-INFO.txt'] != source_info:
        raise ValueError('canonical report mismatch')
    problems = blockers(components, strict_json(payload['REVIEWS.json']), payload)
    problems.extend(candidate_problems)
    if strict_json(payload['BLOCKERS.json']) != problems:
        raise ValueError('blocker report mismatch')
    return problems


def verify(path, expected_project_commit=None):
    return verify_format(path, expected_project_commit, SDK_COMMIT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('prepare')
    for flag in ('project', 'sdk', 'registry-cache', 'output'):
        p.add_argument('--' + flag, type=Path, required=True)
    p.add_argument('--tag', required=True)
    p.add_argument('--reviews', type=Path)
    p.add_argument('--project-commit')
    v = commands.add_parser('verify')
    v.add_argument('--bundle', type=Path, required=True)
    v.add_argument('--project-commit')
    args = parser.parse_args()
    try:
        problems = (prepare(args.project, args.sdk, args.registry_cache, args.output, args.tag, args.reviews, args.project_commit)
                    if args.command == 'prepare' else verify(args.bundle, args.project_commit))
        for problem in problems:
            print('BLOCKER: ' + problem, file=sys.stderr)
        return 1 if problems and args.command == 'verify' else 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, EOFError, tarfile.TarError, subprocess.CalledProcessError) as exc:
        print('bundle failed: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
