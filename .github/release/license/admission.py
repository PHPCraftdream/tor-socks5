#!/usr/bin/env python3
"""Release candidate admission, not a legal guarantee.

Cargo messages do not prove linkage. Reviewed evidence is a human assertion,
not machine-authenticated provenance; reviewers must independently assess it.
Review JSON has source_digest, binary_sha256, target, build_evidence_digest and an evidence object
keyed by the four required types. Each value contains path, sha256,
obligations and reviewer_rationale. Paths are relative to the review file.
"""
import argparse
import gzip
import io
import importlib.util
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location('bundle', Path(__file__).resolve().with_name('bundle.py'))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)

TARGETS = ('x86_64-unknown-linux-gnu', 'x86_64-unknown-linux-musl',
           'aarch64-unknown-linux-gnu', 'aarch64-unknown-linux-musl',
           'x86_64-pc-windows-msvc', 'x86_64-apple-darwin', 'aarch64-apple-darwin')
MAX_BINARY = 1024 * 1024 * 1024
REQUIRED = ('native-link-inputs', 'platform-toolchain-inputs',
            'build-input-correspondence', 'recipient-source-availability')


def read(path, limit=bundle.MAX_FILE):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError('missing, linked or oversized file: ' + str(path))
    return path.read_bytes()


def source_digest(payload):
    paths = [p for p in payload if p.startswith('sources/')]
    if not paths:
        raise ValueError('missing source payload')
    modes = bundle.strict_json(payload['SOURCE-MODES.json'])
    if not isinstance(modes, dict):
        raise ValueError('invalid source modes')
    modes = {p: mode for p, mode in modes.items() if p in paths}
    digest_payload = dict(payload)
    digest_payload['SOURCE-MODES.json'] = bundle.encoded(modes)
    return bundle.source_digest(digest_payload, paths + ['SOURCE-MODES.json', 'GIT-SOURCES.json'])


def cargo(data, binary):
    if not data.endswith(b'\n'):
        raise ValueError('truncated Cargo messages')
    final = None
    finished = False
    for line in data.splitlines():
        obj = bundle.strict_json(line)
        if not isinstance(obj, dict) or finished:
            raise ValueError('malformed or trailing Cargo message')
        if obj.get('reason') == 'compiler-artifact' and obj.get('executable'):
            package = obj.get('package_id', '')
            target = obj.get('target', {})
            # Cargo supports both old and new package-id formats.
            if isinstance(package, str) and (re.search(r'(^|[/# ])socks5-proxy(?:[ @#]|$)', package)) and isinstance(target, dict) and target.get('name') == 'socks5-proxy':
                final = obj['executable']
        if obj.get('reason') == 'build-finished':
            if obj.get('success') is not True:
                raise ValueError('Cargo build failed')
            finished = True
    if not finished or not isinstance(final, str) or Path(final).resolve() != Path(binary).resolve():
        raise ValueError('missing final socks5-proxy artifact or build-finished')


def archive_name(tag, target):
    return 'tor-socks5-' + tag + '-' + target + ('.zip' if 'windows' in target else '.tar.gz')


def checksum(data, name, sidecar):
    expected = bundle.digest(data)
    expected_sidecar = ((expected + ' *' + name) if name.endswith('.zip') else
                        (expected + '  ' + name + '\n')).encode()
    if sidecar != expected_sidecar:
        raise ValueError('invalid checksum: ' + name)


def binary_archive(data, target):
    name = 'tor-socks5.exe' if 'windows' in target else 'tor-socks5'
    if 'windows' not in target:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode='rb') as gz:
            stream = bundle.Limited(gz, MAX_BINARY + 1024 * 1024)
            with tarfile.open(fileobj=stream, mode='r|') as tar:
                result = None
                for count, member in enumerate(tar, 1):
                    if count > 1 or member.name != name or not member.isfile() or member.size > MAX_BINARY:
                        raise ValueError('invalid binary archive members')
                    result = tar.extractfile(member).read(MAX_BINARY + 1)
                    if len(result) != member.size:
                        raise ValueError('invalid binary archive size')
                if result is None:
                    raise ValueError('missing binary archive member')
            while stream.read(65536):
                pass
            return result
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        entries = z.infolist()
        if len(entries) != 1 or entries[0].filename != name or entries[0].is_dir():
            raise ValueError('invalid binary zip members')
        info = entries[0]
        mode = info.external_attr >> 16
        if stat.S_IFMT(mode) not in (0, stat.S_IFREG) or info.file_size > MAX_BINARY:
            raise ValueError('invalid binary zip mode or size')
        return z.read(info)


def candidate(path):
    problems = bundle.verify(path)
    payload = bundle.read_tar(read(path, bundle.MAX_TOTAL), limit=bundle.MAX_TOTAL, files_only=True)
    manifest = bundle.strict_json(payload['MANIFEST.json'])
    return payload, manifest, problems


def review_problems(review, files, receipt):
    problems = []
    if not isinstance(review, dict):
        raise ValueError('invalid review')
    if review and any(review.get(k) != receipt[k] for k in ('source_digest', 'binary_sha256', 'target', 'build_evidence_digest')):
        raise ValueError('review identity mismatch')
    entries = review.get('evidence', {})
    if not isinstance(entries, dict) or set(entries) - set(REQUIRED):
        raise ValueError('invalid review evidence types')
    for kind in REQUIRED:
        entry = entries.get(kind)
        if entry is None:
            problems.append(kind + ': missing reviewed evidence')
            continue
        if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) and entry[k].strip() for k in ('path', 'sha256', 'obligations', 'reviewer_rationale')):
            raise ValueError('invalid review: ' + kind)
        path = bundle.safe(entry['path'])
        if path not in files or entry['sha256'] != bundle.digest(files[path]):
            raise ValueError('review evidence mismatch: ' + kind)
    return problems


def crate_hashes(payload, tag):
    prefix = 'sources/' + tag + '/registry/'
    result = {}
    for path, data in sorted(payload.items()):
        if path.startswith(prefix) and path.endswith('.crate'):
            stem = path[len(prefix):-6]
            if '/' in stem:
                raise ValueError('invalid registry archive path')
            if len(data) > bundle.MAX_FILE:
                raise ValueError('registry crate exceeds size limit: ' + path)
            members = bundle.read_tar(data, root=stem)
            result[stem] = {name[len(stem) + 1:]: bundle.digest(content)
                            for name, content in sorted(members.items())
                            if name[len(stem) + 1:] not in ('.cargo-ok', '.cargo-checksum.json')}
    return result


def expanded_sources(payload, tag, cache):
    expected = crate_hashes(payload, tag)
    root = cache.parent / 'src'
    if root.is_symlink() or not root.is_dir():
        raise ValueError('missing expanded registry sources')
    actual = {}
    for stem in expected:
        matches = list(root.glob('*/' + stem))
        if len(matches) != 1 or matches[0].is_symlink() or matches[0].parent.is_symlink() or not matches[0].is_dir():
            raise ValueError('missing or ambiguous expanded source: ' + stem)
        entries = collect(matches[0], bundle.MAX_FILE)
        for name in ('.cargo-ok', '.cargo-checksum.json'):
            entries.pop(name, None)
        actual[stem] = {name: bundle.digest(data) for name, data in sorted(entries.items())}
        if actual[stem] != expected[stem]:
            raise ValueError('expanded source differs from crate: ' + stem)
    return actual


def build_evidence_digest(files):
    names = ('messages.jsonl', 'features.txt', 'toolchain.txt',
             'native-evidence/linkage.txt', 'native-evidence/build-stderr.txt', 'expanded-sources.json')
    if any(name not in files for name in names):
        raise ValueError('missing build evidence')
    paths = sorted(set(names) | {p for p in files if p.startswith('native-evidence/native/')})
    return bundle.digest(bundle.encoded({p: bundle.digest(files[p]) for p in paths}))


def snapshot(args):
    payload, manifest, _ = candidate(args.prepared / 'candidate.tar.gz')
    args.output.write_bytes(bundle.encoded(expanded_sources(payload, manifest['tag'], args.registry_cache)))
    return []


def add_review(files, review_path, receipt):
    review = bundle.strict_json(read(review_path))
    if not isinstance(review, dict) or not review:
        raise ValueError('missing review')
    if not isinstance(review.get('evidence', {}), dict):
        raise ValueError('invalid review evidence')
    for kind, entry in review.get('evidence', {}).items():
        if kind not in REQUIRED or not isinstance(entry, dict):
            raise ValueError('invalid review evidence')
        relative = bundle.safe(entry['path'])
        source = review_path.parent
        for part in relative.split('/'):
            source = source / part
            if source.is_symlink():
                raise ValueError('linked review evidence')
        dest = 'review-evidence/' + kind
        files[dest] = read(source)
        entry['path'] = dest
    problems = review_problems(review, files, receipt)
    files['review.json'] = bundle.encoded(review)
    return problems


def write_receipt(output, files, receipt):
    receipt['evidence'] = {p: bundle.digest(d) for p, d in sorted(files.items())}
    output.mkdir()
    for name, data in files.items():
        dest = output / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    (output / 'receipt.json').write_bytes(bundle.encoded(receipt))


def record(args):
    if args.target not in TARGETS:
        raise ValueError('unknown target')
    candidate_path = args.prepared / 'candidate.tar.gz'
    payload, manifest, problems = candidate(candidate_path)
    fresh, _, _ = bundle.build(args.project, args.sdk, args.registry_cache, manifest['tag'])
    originals = {p: d for p, d in payload.items() if p.startswith('sources/') or p == 'GIT-SOURCES.json'}
    if fresh != originals:
        raise ValueError('source bytes changed since preparation')
    binary = read(args.binary, MAX_BINARY)
    for name in ('NOTICES.txt', 'SOURCE-INFO.txt'):
        if not payload[name] or payload[name] not in binary:
            raise ValueError('missing embedded ' + name)
    messages = read(args.messages)
    cargo(messages, args.binary)
    files = {'candidate.tar.gz': candidate_path.read_bytes(), 'messages.jsonl': messages,
             'features.txt': read(args.features), 'toolchain.txt': read(args.toolchain)}
    native = args.native_evidence
    if native.is_symlink() or not native.is_dir() or (native / 'native').is_symlink() or not (native / 'native').is_dir():
        raise ValueError('missing native evidence directory')
    for name in ('linkage.txt', 'build-stderr.txt'):
        files['native-evidence/' + name] = read(native / name)
    for path, data in collect(native / 'native', bundle.MAX_FILE).items():
        files['native-evidence/native/' + path] = data
    expanded = expanded_sources(originals, manifest['tag'], args.registry_cache)
    before = bundle.strict_json(read(args.expanded_before))
    if before != expanded:
        raise ValueError('expanded registry sources changed since pre-build snapshot')
    files['expanded-sources.json'] = bundle.encoded(expanded)
    if not files['features.txt'] or not files['toolchain.txt']:
        raise ValueError('empty build evidence')
    receipt = {'schema': 1, 'target': args.target, 'tag': manifest['tag'],
               'sdk_commit': manifest['sdk_commit'], 'source_digest': source_digest(payload),
               'binary_sha256': bundle.digest(binary), 'binary_path': str(args.binary.resolve()),
               'build_evidence_digest': build_evidence_digest(files)}
    if args.review:
        problems += add_review(files, args.review, receipt)
    else:
        files['review.json'] = bundle.encoded({})
        problems += review_problems({}, files, receipt)
    write_receipt(args.output, files, receipt)
    return problems


def finalize_review(args):
    files = collect(args.receipt)
    receipt = bundle.strict_json(files['receipt.json'])
    if not isinstance(receipt, dict) or receipt.get('target') not in TARGETS:
        raise ValueError('invalid receipt identity')
    receipt, problems = check_receipt(files, receipt['target'], receipt['tag'])
    del files['receipt.json']
    del files['review.json']
    files = {p: d for p, d in files.items() if not p.startswith('review-evidence/')}
    problems = [p for p in problems if not p.endswith(': missing reviewed evidence')]
    problems += add_review(files, args.review, receipt)
    write_receipt(args.output, files, receipt)
    return problems


def check_receipt(files, target, tag):
    receipt = bundle.strict_json(files['receipt.json'])
    if receipt.get('schema') != 1 or receipt.get('target') != target or receipt.get('tag') != tag or receipt.get('sdk_commit') != bundle.SDK_COMMIT:
        raise ValueError('receipt identity mismatch')
    evidence = receipt.get('evidence')
    if not isinstance(evidence, dict) or set(evidence) != set(files) - {'receipt.json'}:
        raise ValueError('receipt evidence set mismatch')
    for p, h in evidence.items():
        bundle.safe(p)
        if h != bundle.digest(files[p]):
            raise ValueError('receipt evidence hash mismatch')
    for name in ('candidate.tar.gz', 'messages.jsonl', 'features.txt', 'toolchain.txt', 'review.json'):
        if name not in files or not files[name]:
            raise ValueError('missing receipt evidence: ' + name)
    if receipt.get('build_evidence_digest') != build_evidence_digest(files):
        raise ValueError('build evidence digest mismatch')
    cargo(files['messages.jsonl'], receipt['binary_path'])
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'candidate.tar.gz'
        path.write_bytes(files['candidate.tar.gz'])
        payload, manifest, problems = candidate(path)
    if bundle.strict_json(files['expanded-sources.json']) != crate_hashes(payload, tag):
        raise ValueError('expanded source evidence mismatch')
    if manifest['tag'] != tag or receipt['source_digest'] != source_digest(payload):
        raise ValueError('receipt source mismatch')
    if not isinstance(receipt.get('binary_sha256'), str) or not bundle.HEX.fullmatch(receipt['binary_sha256']):
        raise ValueError('invalid binary digest')
    problems += review_problems(bundle.strict_json(files['review.json']), files, receipt)
    return receipt, problems


def collect(directory, limit=bundle.MAX_TOTAL):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('missing receipt directory')
    result = {}
    for p in directory.rglob('*'):
        if p.is_symlink():
            raise ValueError('linked receipt entry')
        if p.is_file():
            result[bundle.safe(p.relative_to(directory).as_posix())] = read(p, limit)
        elif not p.is_dir():
            raise ValueError('nonregular receipt entry')
    return result


def artifacts_check(artifacts, tag, receipts, complete, candidates):
    expected = set()
    records = {}
    for target in TARGETS:
        name = archive_name(tag, target)
        expected.update((name, name + '.sha256'))
        data = read(artifacts / name, MAX_BINARY)
        checksum(data, name, read(artifacts / (name + '.sha256')))
        binary = binary_archive(data, target)
        if bundle.digest(binary) != receipts[target]['binary_sha256']:
            raise ValueError('binary digest mismatch: ' + target)
        inner = bundle.read_tar(candidates[target], limit=bundle.MAX_TOTAL, files_only=True)
        for required in ('NOTICES.txt', 'SOURCE-INFO.txt'):
            if not inner[required] or inner[required] not in binary:
                raise ValueError('missing embedded ' + required)
        records[target] = {'archive': name, 'archive_sha256': bundle.digest(data), 'binary_sha256': bundle.digest(binary)}
    if complete:
        name = 'tor-socks5-' + tag + '-license-bundle.tar.gz'
        expected.update((name, name + '.sha256'))
    if {p.name for p in artifacts.iterdir()} != expected or any(not p.is_file() or p.is_symlink() for p in artifacts.iterdir()):
        raise ValueError('artifact directory exact set mismatch')
    return records


def tar_size(entries):
    size = 2 * tarfile.BLOCKSIZE
    for name, length in entries:
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime, info.uid, info.gid = length, 0o644, 0, 0, 0
        info.uname = info.gname = ''
        size += len(info.tobuf(format=tarfile.PAX_FORMAT)) + ((length + 511) // 512) * 512
    return ((size + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE


def assemble(args):
    if not bundle.IDENT.fullmatch(args.tag):
        raise ValueError('invalid tag')
    paths = list(args.evidence.rglob('receipt.json'))
    if len(paths) != len(TARGETS):
        raise ValueError('expected exactly seven receipts')
    mapped = {}
    preflight = []
    for path in paths:
        rel = path.relative_to(args.evidence).parts
        if len(rel) != 3 or rel[1:] != ('license-receipt', 'receipt.json') or not rel[0].startswith('license-evidence-'):
            raise ValueError('unexpected receipt layout')
        target = rel[0][len('license-evidence-'):]
        if target not in TARGETS or target in mapped:
            raise ValueError('unexpected or duplicate target')
        mapped[target] = path.parent
        for entry in path.parent.rglob('*'):
            if entry.is_symlink():
                raise ValueError('linked receipt entry')
            if entry.is_file():
                name = bundle.safe(entry.relative_to(path.parent).as_posix())
                size = entry.stat().st_size
                if size > bundle.MAX_TOTAL:
                    raise ValueError('receipt file exceeds size limit: ' + str(entry))
                preflight.append(('targets/' + target + '/' + name, size))
            elif not entry.is_dir():
                raise ValueError('nonregular receipt entry')
        if tar_size(preflight) > bundle.MAX_TOTAL:
            raise ValueError('release payload and tar overhead exceed size limit')
    if set(mapped) != set(TARGETS):
        raise ValueError('missing target receipt')
    mapped = {target: collect(directory) for target, directory in mapped.items()}
    receipts, problems, payload = {}, [], {}
    for target in TARGETS:
        receipt, pending = check_receipt(mapped[target], target, args.tag)
        receipts[target] = receipt
        problems.extend(target + ': ' + p for p in pending)
        payload.update({'targets/' + target + '/' + p: data for p, data in mapped[target].items()})
    if len({receipt['source_digest'] for receipt in receipts.values()}) != 1:
        raise ValueError('receipt source digests differ')
    records = artifacts_check(args.artifacts, args.tag, receipts, False, {t: mapped[t]['candidate.tar.gz'] for t in TARGETS})
    manifest = {'schema': 1, 'tag': args.tag, 'targets': records,
                'files': {p: bundle.digest(d) for p, d in sorted(payload.items())}}
    payload['MANIFEST.json'] = bundle.encoded(manifest)
    if tar_size((p, len(data)) for p, data in payload.items()) > bundle.MAX_TOTAL:
        raise ValueError('release payload and tar overhead exceed size limit')
    bundle.pack(payload, args.output)
    name = args.output.name
    (args.output.parent / (name + '.sha256')).write_bytes((bundle.digest(args.output.read_bytes()) + '  ' + name + '\n').encode())
    (args.output.parent.parent / 'license-blockers.json').write_bytes(bundle.encoded(problems))
    return problems


def verify_format(args):
    """Validate release consistency and reviews, not independent provenance."""
    if not bundle.IDENT.fullmatch(args.tag):
        raise ValueError('invalid tag')
    name = 'tor-socks5-' + args.tag + '-license-bundle.tar.gz'
    data = read(args.artifacts / name, bundle.MAX_TOTAL)
    checksum(data, name, read(args.artifacts / (name + '.sha256')))
    payload = bundle.read_tar(data, limit=bundle.MAX_TOTAL, files_only=True, max_member=bundle.MAX_TOTAL)
    manifest = bundle.strict_json(payload.pop('MANIFEST.json'))
    if manifest.get('schema') != 1 or manifest.get('tag') != args.tag or manifest.get('files') != {p: bundle.digest(d) for p, d in sorted(payload.items())}:
        raise ValueError('outer manifest mismatch')
    receipts, problems, candidates = {}, [], {}
    for target in TARGETS:
        prefix = 'targets/' + target + '/'
        files = {p[len(prefix):]: d for p, d in payload.items() if p.startswith(prefix)}
        receipt, pending = check_receipt(files, target, args.tag)
        receipts[target] = receipt
        candidates[target] = files['candidate.tar.gz']
        problems.extend(target + ': ' + p for p in pending)
    if len({receipt['source_digest'] for receipt in receipts.values()}) != 1:
        raise ValueError('receipt source digests differ')
    if any(not any(p.startswith('targets/' + t + '/') for t in TARGETS) for p in payload):
        raise ValueError('unexpected outer payload')
    if manifest.get('targets') != artifacts_check(args.artifacts, args.tag, receipts, True, candidates):
        raise ValueError('archive manifest mismatch')
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    r = sub.add_parser('record')
    for flag in ('prepared', 'project', 'sdk', 'registry-cache', 'binary', 'messages', 'features', 'toolchain', 'native-evidence', 'expanded-before', 'output'):
        r.add_argument('--' + flag, type=Path, required=True)
    r.add_argument('--target', required=True)
    r.add_argument('--review', type=Path)
    review = sub.add_parser('review')
    for flag in ('receipt', 'review', 'output'):
        review.add_argument('--' + flag, type=Path, required=True)
    snap = sub.add_parser('snapshot')
    for flag in ('prepared', 'registry-cache', 'output'):
        snap.add_argument('--' + flag, type=Path, required=True)
    a = sub.add_parser('assemble')
    for flag in ('evidence', 'artifacts', 'output'):
        a.add_argument('--' + flag, type=Path, required=True)
    a.add_argument('--tag', required=True)
    v = sub.add_parser('verify-release')
    v.add_argument('--artifacts', type=Path, required=True)
    v.add_argument('--tag', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'verify-release':
            print('FORMAT/REVIEW VALIDATION ONLY; provenance must be independently verified', file=sys.stderr)
        problems = {'record': record, 'review': finalize_review, 'snapshot': snapshot, 'assemble': assemble, 'verify-release': verify_format}[args.command](args)
        for problem in problems:
            print('BLOCKER: ' + problem, file=sys.stderr)
        return int(args.command == 'verify-release' and bool(problems))
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, EOFError, tarfile.TarError, zipfile.BadZipFile, subprocess.CalledProcessError) as exc:
        print('admission failed: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
