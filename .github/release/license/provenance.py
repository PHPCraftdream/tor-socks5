#!/usr/bin/env python3
"""Authenticate retained producer bytes against fresh GitHub Actions API data.

Trust requires protected main, reviewed workflow/code at the externally selected
head SHA, GitHub and gh authentication. This does not establish legal compliance,
reviewer identity, tag-to-commit binding, or promotion artifact provenance.
The publisher must independently recheck both producer and promotion artifacts.
Manifest schema: {schema: 1, run_id: int, run_attempt: int, head_sha: str,
 tag: str, files: {relative_path: sha256}}; files excludes the manifest itself.
"""
import argparse
import base64
import hashlib
import importlib.util
import io
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

bundle = load('bundle')
inventory = load('source_inventory')
admission = load('admission')
REPO = 'PHPCraftdream/tor-socks5'
PRODUCER_WORKFLOW = '.github/workflows/license-bundle.yml'
PROMOTION_WORKFLOW = '.github/workflows/license-promote.yml'
EVENT = 'workflow_dispatch'
BRANCH = 'main'
# Producer integration must create this successful, non-gated retention job.
RETAIN_JOB = 'Retain release candidate'
REQUIRED_JOBS = {'License tooling offline tests', RETAIN_JOB} | {
    'License build (' + target + ')' for target in admission.TARGETS}
MAX_ARCHIVE = bundle.MAX_TOTAL
MAX_ENTRIES = bundle.MAX_ENTRIES
OID = re.compile(r'^[0-9a-f]{40}$')
TAG = re.compile(r'^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9][A-Za-z0-9.+-]*)?$')


def gh(endpoint, limit=8 * 1024 * 1024, paginate=False):
    # gh's stdout is bounded even for an adversarial API response; never invoke a shell.
    cmd = ['gh', 'api'] + (['--paginate', '--slurp'] if paginate else []) + [endpoint]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        data = proc.stdout.read(limit + 1)
        if len(data) > limit:
            proc.kill()
            raise ValueError('GitHub response exceeds limit')
        if proc.wait() != 0:
            raise ValueError('GitHub API request failed: ' + endpoint)
        return data
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def api(endpoint, paginate=False):
    return bundle.strict_json(gh('repos/' + REPO + '/' + endpoint, paginate=paginate))


def identity(run_id, attempt, artifact_id, head_sha, tag, *, promotion=False):
    if (any(type(x) is not int or x <= 0 for x in (run_id, attempt, artifact_id)) or
            not isinstance(head_sha, str) or not OID.fullmatch(head_sha) or
            not isinstance(tag, str) or not TAG.fullmatch(tag)):
        raise ValueError('invalid requested identity')
    run = api(f'actions/runs/{run_id}/attempts/{attempt}')
    if (run.get('id') != run_id or run.get('run_attempt') != attempt or
            run.get('head_sha') != head_sha or run.get('head_branch') != BRANCH or
            run.get('event') != EVENT or run.get('status') != 'completed' or
            run.get('conclusion') != 'success' or
            (run.get('repository') or {}).get('full_name') != REPO or
            (run.get('head_repository') or {}).get('full_name') != REPO):
        raise ValueError('untrusted producer run')
    workflow_id = run.get('workflow_id')
    if type(workflow_id) is not int or workflow_id <= 0:
        raise ValueError('missing workflow identity')
    workflow = api(f'actions/workflows/{workflow_id}')
    if workflow.get('id') != workflow_id or workflow.get('path') != (PROMOTION_WORKFLOW if promotion else PRODUCER_WORKFLOW):
        raise ValueError('untrusted producer workflow')
    pages = api(f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100', paginate=True)
    if not isinstance(pages, list) or not pages:
        raise ValueError('missing job pages')
    jobs = []
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get('jobs'), list):
            raise ValueError('invalid job response')
        jobs.extend(page['jobs'])
    names = [job.get('name') for job in jobs]
    if (len(names) != len(set(names)) or not ({'Finalize retained release candidate'} if promotion else REQUIRED_JOBS).issubset(names) or
            any(j.get('status') != 'completed' or j.get('conclusion') != 'success' for j in jobs)):
        raise ValueError('missing, duplicate, or unsuccessful producer jobs')
    artifact = api(f'actions/artifacts/{artifact_id}')
    digest = artifact.get('digest')
    if not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise ValueError('GitHub artifact SHA-256 digest absent or invalid')
    relation = artifact.get('workflow_run') or {}
    if (artifact.get('id') != artifact_id or
            artifact.get('name') != f"license-{'admitted' if promotion else 'retained'}-{run_id}-{attempt}" or
            artifact.get('expired') is not False or relation.get('id') != run_id or
            relation.get('head_sha') != head_sha or
            not isinstance(artifact.get('created_at'), str) or not artifact['created_at'] or
            not isinstance(artifact.get('expires_at'), str) or not artifact['expires_at']):
        raise ValueError('artifact identity mismatch')
    return digest[7:]


def unzip(data):
    files, seen, parents = {}, set(), set()
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise ValueError('too many zip entries')
        for info in entries:
            name = bundle.safe(info.filename)
            key = name.casefold()
            ancestor = {'/'.join(name.split('/')[:i]).casefold() for i in range(1, len(name.split('/')))}
            mode = info.external_attr >> 16
            if (info.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or
                    key in seen or key in parents or ancestor & seen or info.flag_bits & 1):
                raise ValueError('unsafe zip member: ' + name)
            seen.add(key)
            parents.update(ancestor)
            total += info.file_size
            if info.file_size > bundle.MAX_TOTAL or total > bundle.MAX_TOTAL:
                raise ValueError('zip contents exceed limit')
            with archive.open(info) as stream:
                content = stream.read(info.file_size + 1)
            if len(content) != info.file_size:
                raise ValueError('zip member size mismatch')
            files[name] = content
    return files


def verify_git_bundle(data, tag, head_sha):
    """Verify candidate Git proofs against the API-anchored project commit and pinned SDK."""
    payload = bundle.read_tar(data, limit=bundle.MAX_TOTAL, files_only=True, max_member=bundle.MAX_TOTAL)
    inventory.verify_sources(payload, tag, expected_project_commit=head_sha)


def validate(files, run_id, attempt, head_sha, tag):
    manifest = bundle.strict_json(files['retained-manifest.json'])
    hashes = {name: bundle.digest(data) for name, data in files.items() if name != 'retained-manifest.json'}
    if (not isinstance(manifest, dict) or set(manifest) != {'schema', 'run_id', 'run_attempt', 'head_sha', 'tag', 'files'} or
            manifest['schema'] != 1 or manifest['run_id'] != run_id or manifest['run_attempt'] != attempt or
            manifest['head_sha'] != head_sha or manifest['tag'] != tag or manifest['files'] != hashes):
        raise ValueError('retained manifest mismatch')
    artifact_names = set()
    prefixes = {}
    for target in admission.TARGETS:
        name = admission.archive_name(tag, target)
        artifact_names.update(('artifacts/' + name, 'artifacts/' + name + '.sha256'))
        prefix = 'evidence/license-evidence-' + target + '/license-receipt/'
        prefixes[target] = prefix
        receipt_files = {p[len(prefix):]: data for p, data in files.items() if p.startswith(prefix)}
        receipt, _ = admission.check_receipt(receipt_files, target, tag)
        if receipt.get('sdk_commit') != inventory.SDK_COMMIT:
            raise ValueError('receipt identity mismatch')
        verify_git_bundle(files[prefix + 'candidate.tar.gz'], tag, head_sha)
        archive = files['artifacts/' + name]
        admission.checksum(archive, name, files['artifacts/' + name + '.sha256'])
        if bundle.digest(admission.binary_archive(archive, target)) != receipt['binary_sha256']:
            raise ValueError('binary digest mismatch: ' + target)
    if {p for p in files if p.startswith('artifacts/')} != artifact_names:
        raise ValueError('artifact file set mismatch')
    if any(p != 'retained-manifest.json' and p not in artifact_names and
           not any(p.startswith(prefix) for prefix in prefixes.values()) for p in files):
        raise ValueError('unexpected retained file')


def fetch_verified(run_id, attempt, artifact_id, head_sha, tag):
    digest = identity(run_id, attempt, artifact_id, head_sha, tag)
    data = gh(f'repos/{REPO}/actions/artifacts/{artifact_id}/zip', limit=MAX_ARCHIVE)
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('GitHub artifact archive digest mismatch')
    files = unzip(data)
    validate(files, run_id, attempt, head_sha, tag)
    return files


def fetch_promotion(run_id, attempt, artifact_id, build_sha, tag, review_commit,
                    producer_run_id, producer_attempt, producer_artifact_id, policy_sha):
    if not isinstance(review_commit, str) or not OID.fullmatch(review_commit):
        raise ValueError('invalid review commit')
    digest = identity(run_id, attempt, artifact_id, policy_sha, tag, promotion=True)
    commit = api('commits/' + review_commit)
    tree = (commit.get('commit') or {}).get('tree') or {}
    if commit.get('sha') != review_commit or not isinstance(tree.get('sha'), str) or not OID.fullmatch(tree['sha']):
        raise ValueError('review commit API identity mismatch')
    data = gh(f'repos/{REPO}/actions/artifacts/{artifact_id}/zip', limit=MAX_ARCHIVE)
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('GitHub promotion archive digest mismatch')
    files = unzip(data)
    manifest = bundle.strict_json(files['promotion-manifest.json'])
    expected = {'run_id': producer_run_id, 'attempt': producer_attempt,
                'artifact_id': producer_artifact_id, 'head_sha': build_sha, 'tag': tag}
    if not isinstance(manifest, dict) or manifest.get('producer') != expected:
        raise ValueError('requested producer identity mismatch')
    if 'review-source-proof.json' not in files:
        raise ValueError('missing reviewer Git binding')
    verify_promoted_files(files, {'run_id': run_id, 'run_attempt': attempt, 'head_sha': policy_sha},
                          build_sha, tag, review_commit)
    proof = bundle.strict_json(files['review-source-proof.json'])
    if proof['tree'] != tree['sha']:
        raise ValueError('review commit API tree mismatch')
    return files


def local_tree(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('invalid retained directory')
    files, total = {}, 0
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('linked retained path')
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError('nonregular retained path')
        name = bundle.safe(path.relative_to(root).as_posix())
        total += path.stat().st_size
        if total > bundle.MAX_TOTAL or len(files) >= MAX_ENTRIES:
            raise ValueError('retained tree exceeds limit')
        files[name] = path.read_bytes()
    return files


def env_positive(name):
    value = os.environ.get(name, '')
    if not re.fullmatch(r'[1-9][0-9]*', value):
        raise ValueError('invalid environment integer: ' + name)
    return int(value)


def write_tree(output, files):
    if '..' in output.parts:
        raise ValueError('unsafe output path')
    parent = Path(os.path.abspath(output.parent))
    if any(path.is_symlink() for path in (parent, *parent.parents)):
        raise ValueError('linked output parent')
    parent.mkdir(parents=True, exist_ok=True)
    if any(path.is_symlink() for path in (parent, *parent.parents)):
        raise ValueError('linked output parent')
    output.mkdir()
    for name, data in sorted(files.items()):
        dest = output.joinpath(*bundle.safe(name).split('/'))
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open('xb') as stream:
            stream.write(data)


def seal(artifacts, evidence, tag, output):
    run_id = env_positive('GITHUB_RUN_ID')
    attempt = env_positive('GITHUB_RUN_ATTEMPT')
    head_sha = os.environ.get('GITHUB_SHA', '')
    if not OID.fullmatch(head_sha) or not TAG.fullmatch(tag):
        raise ValueError('invalid seal identity')
    artifact_files = local_tree(artifacts)
    expected = set()
    for target in admission.TARGETS:
        name = admission.archive_name(tag, target)
        expected.update((name, name + '.sha256'))
    if set(artifact_files) != expected:
        raise ValueError('artifact file set mismatch')
    evidence_files = local_tree(evidence)
    prefixes = ['license-evidence-' + t + '/license-receipt/' for t in admission.TARGETS]
    if any(not any(p.startswith(prefix) for prefix in prefixes) for p in evidence_files):
        raise ValueError('unexpected evidence file')
    files = {'artifacts/' + p: data for p, data in artifact_files.items()}
    files.update({'evidence/' + p: data for p, data in evidence_files.items()})
    manifest = {'schema': 1, 'run_id': run_id, 'run_attempt': attempt,
                'head_sha': head_sha, 'tag': tag,
                'files': {p: bundle.digest(data) for p, data in files.items()}}
    files['retained-manifest.json'] = bundle.encoded(manifest)
    validate(files, run_id, attempt, head_sha, tag)
    write_tree(output, files)


def compare_final(artifacts, evidence, origin, tag):
    expected = set()
    prefixes = []
    for target in admission.TARGETS:
        name = admission.archive_name(tag, target)
        for item in (name, name + '.sha256'):
            expected.add(item)
            if artifacts.get(item) != origin['artifacts/' + item]:
                raise ValueError('producer artifact changed: ' + item)
        prefix = 'license-evidence-' + target + '/license-receipt/'
        prefixes.append(prefix)
        final = {p[len(prefix):]: d for p, d in evidence.items() if p.startswith(prefix)}
        original = {p[len('evidence/' + prefix):]: d for p, d in origin.items()
                    if p.startswith('evidence/' + prefix)}
        old_receipt, _ = admission.check_receipt(original, target, tag)
        new_receipt, problems = admission.check_receipt(final, target, tag)
        if problems:
            raise ValueError('final receipt has blockers: ' + target)
        def unchanged(files):
            return {p: d for p, d in files.items() if p not in ('receipt.json', 'review.json')
                    and not p.startswith('review-evidence/')}
        if unchanged(final) != unchanged(original):
            raise ValueError('producer evidence changed: ' + target)
        if {k: v for k, v in new_receipt.items() if k != 'evidence'} != {
                k: v for k, v in old_receipt.items() if k != 'evidence'}:
            raise ValueError('producer receipt identity changed: ' + target)
    name = 'tor-socks5-' + tag + '-license-bundle.tar.gz'
    expected.update((name, name + '.sha256'))
    if set(artifacts) != expected or any(not any(p.startswith(prefix) for prefix in prefixes) for p in evidence):
        raise ValueError('unexpected final file set')
    payload = bundle.read_tar(artifacts[name], limit=bundle.MAX_TOTAL, files_only=True, max_member=bundle.MAX_TOTAL)
    payload.pop('MANIFEST.json')
    expected_payload = {}
    for target, prefix in zip(admission.TARGETS, prefixes):
        expected_payload.update({'targets/' + target + '/' + p[len(prefix):]: d
                                 for p, d in evidence.items() if p.startswith(prefix)})
    if payload != expected_payload:
        raise ValueError('final evidence differs from release bundle')
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'artifacts'
        write_tree(path, artifacts)
        if admission.verify_format(SimpleNamespace(artifacts=path, tag=tag)):
            raise ValueError('release has blockers')


REVIEW_PREFIX = '.github/release/license/reviews/'


def review_inputs(contents, final_evidence=None):
    """Select referenced review bytes and reproduce add_review's data transformation."""
    used = set()
    for target in admission.TARGETS:
        path = REVIEW_PREFIX + target + '.json'
        used.add(path)
        review = bundle.strict_json(contents[path])
        if not isinstance(review, dict) or not review or not isinstance(review.get('evidence', {}), dict):
            raise ValueError('invalid review data')
        expected = {}
        for kind, entry in review.get('evidence', {}).items():
            if kind not in admission.REQUIRED or not isinstance(entry, dict):
                raise ValueError('invalid review evidence')
            source = REVIEW_PREFIX + bundle.safe(entry['path'])
            used.add(source)
            dest = 'review-evidence/' + kind
            expected[dest] = contents[source]
            entry['path'] = dest
        expected['review.json'] = bundle.encoded(review)
        if final_evidence is not None:
            prefix = 'license-evidence-' + target + '/license-receipt/'
            actual = {p[len(prefix):]: d for p, d in final_evidence.items()
                      if p == prefix + 'review.json' or p.startswith(prefix + 'review-evidence/')}
            if actual != expected:
                raise ValueError('final review differs from Git-bound review: ' + target)
    return used


def review_bundle(root, expected_commit):
    if not isinstance(expected_commit, str) or not OID.fullmatch(expected_commit):
        raise ValueError('invalid review commit')
    if not (root / '.git').exists():
        raise ValueError('reviews must be a Git checkout root')
    proof, contents = inventory.snapshot_git(root, expected_commit)
    used = review_inputs(contents)
    result = {'review-source-proof.json': bundle.encoded(proof)}
    result.update({'reviews-used/' + path: contents[path] for path in used})
    return result


def verify_review_binding(files, review_commit, final_evidence):
    if 'review-source-proof.json' not in files:
        raise ValueError('missing reviewer Git binding')
    proof = bundle.strict_json(files['review-source-proof.json'])
    if (not isinstance(proof, dict) or set(proof) != {'commit', 'tree', 'commit_object', 'files'} or
            proof['commit'] != review_commit):
        raise ValueError('invalid reviewer Git proof')
    raw = base64.b64decode(proof['commit_object'], validate=True)
    if inventory.commit_tree(raw, review_commit) != proof['tree']:
        raise ValueError('review commit tree mismatch')
    records = proof['files']
    if not isinstance(records, list) or len(records) > inventory.MAX_ENTRIES:
        raise ValueError('invalid reviewer Git records')
    for record in records:
        if (not isinstance(record, dict) or set(record) != {'path', 'oid', 'mode', 'sha256', 'size'} or
                type(record['size']) is not int or record['size'] < 0 or
                not isinstance(record['sha256'], str) or not bundle.HEX.fullmatch(record['sha256'])):
            raise ValueError('invalid reviewer Git record')
    if inventory.tree_hash(records) != proof['tree']:
        raise ValueError('review source tree mismatch')
    by_path = {r['path']: r for r in records}
    contents = {p[len('reviews-used/'):]: d for p, d in files.items() if p.startswith('reviews-used/')}
    for path, data in contents.items():
        if not path.startswith(REVIEW_PREFIX):
            raise ValueError('review source outside reviews directory')
        record = by_path.get(path)
        if (record is None or record['size'] != len(data) or record['sha256'] != bundle.digest(data) or
                record['oid'] != inventory.object_id('blob', data)):
            raise ValueError('review source blob mismatch: ' + path)
    if set(contents) != review_inputs(contents, final_evidence):
        raise ValueError('review source file set mismatch')


def verify_promoted_files(files, promotion, build_sha, tag, review_commit):
    if (not isinstance(promotion, dict) or set(promotion) != {'run_id', 'run_attempt', 'head_sha'} or
            any(type(promotion[k]) is not int or promotion[k] <= 0 for k in ('run_id', 'run_attempt')) or
            not isinstance(promotion['head_sha'], str) or not OID.fullmatch(promotion['head_sha']) or
            not isinstance(build_sha, str) or not OID.fullmatch(build_sha) or
            not isinstance(tag, str) or not TAG.fullmatch(tag) or
            not isinstance(review_commit, str) or not OID.fullmatch(review_commit)):
        raise ValueError('invalid promotion identity')
    manifest = bundle.strict_json(files['promotion-manifest.json'])
    if not isinstance(manifest, dict) or set(manifest) != {'schema', 'producer', 'review_commit', 'promotion', 'tag', 'files'}:
        raise ValueError('invalid promotion manifest')
    producer = manifest['producer']
    if (type(manifest['schema']) is not int or manifest['schema'] != 1 or
            manifest['promotion'] != promotion or manifest['review_commit'] != review_commit or manifest['tag'] != tag or
            not isinstance(producer, dict) or set(producer) != {'run_id', 'attempt', 'artifact_id', 'head_sha', 'tag'} or
            producer['head_sha'] != build_sha or producer['tag'] != tag or
            any(type(producer[k]) is not int or producer[k] <= 0 for k in ('run_id', 'attempt', 'artifact_id'))):
        raise ValueError('promotion identity mismatch')
    for path in files:
        bundle.safe(path)
    if manifest['files'] != {p: bundle.digest(d) for p, d in files.items() if p != 'promotion-manifest.json'}:
        raise ValueError('promotion manifest file set or hash mismatch')
    origin = fetch_verified(producer['run_id'], producer['attempt'], producer['artifact_id'], build_sha, tag)
    retained = {p[len('origin/retained/'):]: d for p, d in files.items() if p.startswith('origin/retained/')}
    if retained != origin:
        raise ValueError('promoted origin differs from GitHub archive')
    artifacts = {p[len('artifacts/'):]: d for p, d in files.items() if p.startswith('artifacts/')}
    evidence = {p[len('evidence/'):]: d for p, d in files.items() if p.startswith('evidence/')}
    if any(p not in ('promotion-manifest.json', 'review-source-proof.json') and
           not p.startswith(('origin/retained/', 'artifacts/', 'evidence/', 'reviews-used/')) for p in files):
        raise ValueError('unexpected promotion file')
    verify_review_binding(files, review_commit, evidence)
    compare_final(artifacts, evidence, origin, tag)


def seal_promotion(retained, artifacts, evidence, reviews, review_commit, output, producer):
    promotion = {'run_id': env_positive('GITHUB_RUN_ID'), 'run_attempt': env_positive('GITHUB_RUN_ATTEMPT'),
                 'head_sha': os.environ.get('GITHUB_SHA', '')}
    origin = fetch_verified(producer['run_id'], producer['attempt'], producer['artifact_id'], producer['head_sha'], producer['tag'])
    if local_tree(retained) != origin:
        raise ValueError('retained tree differs from GitHub archive')
    final_artifacts, final_evidence = local_tree(artifacts), local_tree(evidence)
    files = {'origin/retained/' + p: d for p, d in origin.items()}
    files.update({'artifacts/' + p: d for p, d in final_artifacts.items()})
    files.update({'evidence/' + p: d for p, d in final_evidence.items()})
    files.update(review_bundle(reviews, review_commit))
    manifest = {'schema': 1, 'producer': producer, 'review_commit': review_commit,
                'promotion': promotion, 'tag': producer['tag'],
                'files': {p: bundle.digest(d) for p, d in files.items()}}
    files['promotion-manifest.json'] = bundle.encoded(manifest)
    verify_promoted_files(files, promotion, producer['head_sha'], producer['tag'], review_commit)
    write_tree(output, files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('fetch', 'verify-origin'):
        sub = commands.add_parser(command)
        for flag in ('run-id', 'attempt', 'artifact-id'):
            sub.add_argument('--' + flag, type=int, required=True)
        sub.add_argument('--head-sha', required=True)
        sub.add_argument('--tag', required=True)
        sub.add_argument('--output' if command == 'fetch' else '--retained', type=Path, required=True)
    producer = commands.add_parser('seal')
    for flag in ('artifacts', 'evidence', 'output'):
        producer.add_argument('--' + flag, type=Path, required=True)
    producer.add_argument('--tag', required=True)
    promotion = commands.add_parser('seal-promotion')
    for flag in ('retained', 'artifacts', 'evidence', 'reviews', 'output'):
        promotion.add_argument('--' + flag, type=Path, required=True)
    promotion.add_argument('--review-commit', required=True)
    for flag in ('producer-run-id', 'producer-attempt', 'producer-artifact-id'):
        promotion.add_argument('--' + flag, type=int, required=True)
    promotion.add_argument('--head-sha', required=True)
    promotion.add_argument('--tag', required=True)
    for command in ('fetch-promotion', 'verify-promotion'):
        sub = commands.add_parser(command)
        for flag in ('run-id', 'attempt', 'artifact-id', 'producer-run-id', 'producer-attempt', 'producer-artifact-id'):
            sub.add_argument('--' + flag, type=int, required=True)
        for flag in ('head-sha', 'tag', 'review-commit', 'policy-sha'):
            sub.add_argument('--' + flag, required=True)
        sub.add_argument('--output' if command == 'fetch-promotion' else '--promoted', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'seal':
            seal(args.artifacts, args.evidence, args.tag, args.output)
            return 0
        if args.command == 'seal-promotion':
            context = {'run_id': args.producer_run_id, 'attempt': args.producer_attempt,
                       'artifact_id': args.producer_artifact_id, 'head_sha': args.head_sha, 'tag': args.tag}
            seal_promotion(args.retained, args.artifacts, args.evidence, args.reviews, args.review_commit, args.output, context)
            return 0
        if args.command in ('fetch-promotion', 'verify-promotion'):
            files = fetch_promotion(args.run_id, args.attempt, args.artifact_id, args.head_sha, args.tag,
                                    args.review_commit, args.producer_run_id, args.producer_attempt,
                                    args.producer_artifact_id, args.policy_sha)
            if args.command == 'verify-promotion':
                if local_tree(args.promoted) != files:
                    raise ValueError('promoted tree differs from GitHub archive')
            else:
                write_tree(args.output, files)
            return 0
        files = fetch_verified(args.run_id, args.attempt, args.artifact_id, args.head_sha, args.tag)
        if args.command == 'verify-origin':
            if local_tree(args.retained) != files:
                raise ValueError('retained tree differs from GitHub archive')
        else:
            write_tree(args.output, files)
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, EOFError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print('provenance failed: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
