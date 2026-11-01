#!/usr/bin/env python3
"""PR CI lifecycle integration against the existing release build, not a legal review.

The workflow must build with the supplied prepared reports embedded before invoking
this script. No build, checkout, production review, or promotion is performed here.
All fabricated review evidence is TEST ONLY and remains outside retained artifacts.
Trusted promotion requires a separately authenticated main-branch dispatch and
independently reviewed, externally committed production review data.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('admission', HERE / 'admission.py')
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)
bundle = admission.bundle


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(*args, failure=None):
    result = subprocess.run([sys.executable, '-I', str(HERE / 'admission.py'), *map(str, args)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if failure is None:
        require(result.returncode == 0, 'admission command failed: ' + result.stderr)
    else:
        require(result.returncode != 0 and failure in result.stderr,
                'expected admission failure ' + failure + ': ' + result.stderr)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('prepared', 'project', 'sdk', 'registry-cache', 'binary', 'messages',
                 'features', 'toolchain', 'native-evidence', 'expanded-before'):
        parser.add_argument('--' + flag, type=Path, required=True)
    parser.add_argument('--target', required=True, choices=admission.TARGETS)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('GITHUB_EVENT_NAME') == 'pull_request',
            'this integration test is restricted to GitHub pull_request CI')
    work = Path(tempfile.mkdtemp(prefix='license-lifecycle-test-only-'))
    original = args.prepared / 'candidate.tar.gz'
    immutable = {p: bundle.digest(p.read_bytes()) for p in (original, args.binary, args.messages)}
    original_payload, manifest, _ = admission.candidate(original)
    tag = manifest['tag']
    head = subprocess.check_output(['git', '-C', str(args.project), 'rev-parse', 'HEAD^{commit}'], text=True).strip()
    proof = bundle.strict_json(original_payload['GIT-SOURCES.json'])
    require(proof['project']['commit'] == head and proof['sdk']['commit'] == bundle.SDK_COMMIT,
            'candidate Git commits do not match checkout and pinned SDK')
    bundle.source_inventory.verify_sources(original_payload, tag, expected_project_commit=head)

    prepared = work / 'prepared'
    bundle.prepare(args.project, args.sdk, args.registry_cache, prepared, tag, None, head)
    payload, new_manifest, component_problems = admission.candidate(prepared / 'candidate.tar.gz')
    require(new_manifest['tag'] == tag and admission.source_digest(payload) == admission.source_digest(original_payload),
            'fresh preparation source identity differs from build candidate')
    require(component_problems and any('missing' in p for p in component_problems),
            'expected unreviewed component legal blockers')
    for name in ('NOTICES.txt', 'SOURCE-INFO.txt'):
        require(payload[name] == original_payload[name] and payload[name] in args.binary.read_bytes(),
                'embedded report differs: ' + name)
    snapshot = work / 'expanded.json'
    run('snapshot', '--prepared', prepared, '--registry-cache', args.registry_cache, '--output', snapshot)
    require(bundle.strict_json(snapshot.read_bytes()) == bundle.strict_json(args.expanded_before.read_bytes()),
            'registry snapshot differs from pre-build snapshot')
    record_args = ['record', '--prepared', prepared, '--project', args.project, '--sdk', args.sdk,
                   '--registry-cache', args.registry_cache, '--target', args.target, '--binary', args.binary,
                   '--messages', args.messages, '--features', args.features, '--toolchain', args.toolchain,
                   '--native-evidence', args.native_evidence]
    receipt_dir = work / 'receipt'
    run(*record_args, '--expanded-before', args.expanded_before, '--output', receipt_dir)
    files = admission.collect(receipt_dir)
    receipt, pending = admission.check_receipt(files, args.target, tag)
    require(receipt['binary_sha256'] == immutable[args.binary], 'recorded binary hash differs')
    require(files['messages.jsonl'] == args.messages.read_bytes() and
            files['candidate.tar.gz'] == (prepared / 'candidate.tar.gz').read_bytes(), 'recorded evidence differs')
    for kind in admission.REQUIRED:
        require(kind + ': missing reviewed evidence' in pending, 'missing initial review blocker: ' + kind)

    evidence = b'TEST ONLY: fabricated lifecycle evidence; not a legal or production review.\n'
    (work / 'TEST-ONLY.txt').write_bytes(evidence)
    review = {key: receipt[key] for key in ('source_digest', 'binary_sha256', 'target', 'build_evidence_digest')}
    review['evidence'] = {kind: {'path': 'TEST-ONLY.txt', 'sha256': bundle.digest(evidence),
                                 'obligations': 'TEST ONLY', 'reviewer_rationale': 'TEST ONLY'}
                          for kind in admission.REQUIRED}
    review_path = work / 'TEST-ONLY-review.json'
    review_path.write_bytes(bundle.encoded(review))
    finalized = work / 'finalized'
    run('review', '--receipt', receipt_dir, '--review', review_path, '--output', finalized)
    final_files = admission.collect(finalized)
    final_receipt, remaining = admission.check_receipt(final_files, args.target, tag)
    require(all(p in remaining for p in component_problems) and remaining,
            'component legal blockers must survive target review; release is not admissible')
    require(not any(kind + ': missing reviewed evidence' in remaining for kind in admission.REQUIRED),
            'target review blockers were not resolved')
    for key in ('source_digest', 'binary_sha256', 'target', 'build_evidence_digest'):
        require(final_receipt[key] == receipt[key], 'review changed identity: ' + key)
    require(final_files['candidate.tar.gz'] == files['candidate.tar.gz'] and
            final_files['messages.jsonl'] == files['messages.jsonl'], 'review changed build evidence')

    wrong = dict(review, binary_sha256='0' * 64 if receipt['binary_sha256'] != '0' * 64 else '1' * 64)
    wrong_path = work / 'TEST-ONLY-wrong-review.json'
    wrong_path.write_bytes(bundle.encoded(wrong))
    bad_output = work / 'wrong-receipt'
    run('review', '--receipt', receipt_dir, '--review', wrong_path, '--output', bad_output,
        failure='review identity mismatch')
    require(not bad_output.exists(), 'invalid review wrote output')

    before = bundle.strict_json(args.expanded_before.read_bytes())
    require(before, 'empty registry snapshot')
    stem = next(iter(before))
    require(before[stem], 'empty expanded crate')
    filename = next(iter(before[stem]))
    before[stem][filename] = '0' * 64 if before[stem][filename] != '0' * 64 else '1' * 64
    bad_before = work / 'tampered-before.json'
    bad_before.write_bytes(bundle.encoded(before))
    bad_record = work / 'bad-record'
    run(*record_args, '--expanded-before', bad_before, '--output', bad_record,
        failure='expanded registry sources changed since pre-build snapshot')
    require(not bad_record.exists(), 'invalid snapshot wrote output')

    tampered = dict(payload)
    sdk_path = next(p for p in tampered if p.startswith('sources/' + tag + '/sdk/'))
    tampered[sdk_path] += b'\nTEST ONLY tamper\n'
    manifest_copy = bundle.strict_json(tampered['MANIFEST.json'])
    for entry in manifest_copy['files']:
        if entry['path'] == sdk_path:
            entry['size'] = len(tampered[sdk_path])
            entry['sha256'] = bundle.digest(tampered[sdk_path])
    tampered['MANIFEST.json'] = bundle.encoded(manifest_copy)
    bad_candidate = work / 'tampered-candidate.tar.gz'
    bundle.pack(tampered, bad_candidate)
    try:
        bundle.verify(bad_candidate, expected_project_commit=head)
    except ValueError as exc:
        require('source blob mismatch' in str(exc), 'unexpected tamper rejection: ' + str(exc))
    else:
        raise AssertionError('tampered SDK source accepted')
    for path, digest in immutable.items():
        require(bundle.digest(path.read_bytes()) == digest, 'input changed: ' + str(path))
    print('Lifecycle integration passed; TEST ONLY reviews are not production admission. Fixture: ' + str(work))


if __name__ == '__main__':
    main()
