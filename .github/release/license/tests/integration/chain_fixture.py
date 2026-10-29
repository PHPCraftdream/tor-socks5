"""CI-only synthetic release fixture. ALL fabricated bytes are TEST ONLY.

This is not a build, legal review, or production provenance claim. The SDK is
retained from its genuine pinned checkout; all reviews and binaries are markers.
Callers supply an empty temporary root and the pinned SDK checkout.
"""
import io
import shutil
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace

import admission
from test_source_inventory import proof

bundle = admission.bundle
TAG = 'v1.0.0-test'
PRODUCER_RUN_ID = 101
PRODUCER_ATTEMPT = 1
PRODUCER_ARTIFACT_ID = 102
POLICY_SHA = '1' * 40
REVIEW_PREFIX = '.github/release/license/reviews/'
MARKER = b'TEST ONLY: synthetic fixture, not a build or legal review.\n'


def make_candidate(root, sdk):
    """Return (candidate path, payload, synthetic project commit)."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    crate_path = root / 'demo-1.crate'
    bundle.pack({'demo-1/Cargo.toml': b'[package]\nname="demo"\nversion="1"\nlicense="MIT"\n',
                 'demo-1/LICENSE-MIT': MARKER, 'demo-1/src/lib.rs': MARKER}, crate_path)
    crate = crate_path.read_bytes()
    project = {
        'Cargo.toml': b'[workspace.package]\nlicense="MIT"\n[patch.crates-io]\npatch={path="vendor/patch"}\n',
        'Cargo.lock': ('[[package]]\nname="demo"\nversion="1"\nsource="' + bundle.REGISTRY +
                       '"\nchecksum="' + bundle.digest(crate) + '"\n').encode(),
        'LICENSE-MIT': MARKER, 'LICENSE-APACHE': MARKER,
        'vendor/patch/Cargo.toml': b'[package]\nlicense="MIT"\n',
        'vendor/patch/lib.rs': MARKER, 'vendor/patch/NOTICE': MARKER,
    }
    project_proof = proof({p: (data, '100644') for p, data in project.items()})
    sdk_proof, sdk_data = bundle.source_inventory.snapshot_git(Path(sdk), bundle.SDK_COMMIT)
    base = 'sources/' + TAG + '/'
    payload = {base + 'project/' + p: data for p, data in project.items()}
    payload.update({base + 'sdk/' + p: data for p, data in sdk_data.items()})
    payload[base + 'registry/demo-1.crate'] = crate
    metadata = {'schema': 1, 'project': project_proof, 'sdk': sdk_proof}
    payload['GIT-SOURCES.json'] = bundle.encoded(metadata)
    modes = {base + name + '/' + record['path']: record['mode']
             for name, git_proof in (('project', project_proof), ('sdk', sdk_proof))
             for record in git_proof['files']}
    payload['SOURCE-MODES.json'] = bundle.encoded(modes)
    components, packages, copies = bundle.reconstruct(payload, TAG)
    payload.update(copies)
    reviews = {'components': {}}
    for component in components:
        def ref(path):
            return {'path': path, 'sha256': bundle.digest(payload[path])}
        notices = [ref(p) for p in component['candidates']]
        source = [ref(component['source_paths'][0])]
        reviews['components'][component['id']] = {
            'source_digest': component['source_digest'],
            'selected_license': component['declared_license'].split(' OR ')[0],
            'rationale': 'TEST ONLY', 'obligations': 'TEST ONLY',
            'notices': notices, 'retained_notices': notices,
            'evidence': source, 'corresponding_source': source,
            'attribution_review': [dict(ref(p), rationale='TEST ONLY')
                                   for p in component['source_paths']],
        }
    notices, source_info, report_problems = bundle.canonical_reports(payload, components, TAG)
    problems = bundle.blockers(components, reviews, payload) + report_problems
    assert not problems, problems
    payload.update({'NOTICES.txt': notices, 'SOURCE-INFO.txt': source_info,
                    'REVIEWS.json': bundle.encoded(reviews), 'BLOCKERS.json': bundle.encoded(problems)})
    manifest = {'schema': 1, 'tag': TAG, 'sdk_commit': bundle.SDK_COMMIT,
                'packages': packages, 'components': components,
                'files': [{'path': p, 'size': len(d), 'sha256': bundle.digest(d)}
                          for p, d in sorted(payload.items())]}
    payload['MANIFEST.json'] = bundle.encoded(manifest)
    path = root / 'candidate.tar.gz'
    bundle.pack(payload, path)
    assert bundle.verify(path, expected_project_commit=project_proof['commit']) == []
    return path, payload, project_proof['commit']


def make_inputs(root, sdk):
    """Return paths and identities for a TEST ONLY retained/promotion chain.

    artifacts contains the original 14 files; assembled_artifacts contains 16.
    review_proof_payload is the mapping used for promotion review binding.
    """
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    candidate, payload, project_sha = make_candidate(root / 'candidate', sdk)
    original = root / 'original-evidence'
    final = root / 'final-evidence'
    artifacts = root / 'artifacts'
    assembled = root / 'assembled-artifacts'
    review_root = root / 'review-checkout'
    review_dir = review_root / REVIEW_PREFIX
    for directory in (original, final, artifacts, review_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (review_dir / 'TEST-ONLY.txt').write_bytes(MARKER)
    for target in admission.TARGETS:
        binary = MARKER + target.encode() + b'\n' + payload['NOTICES.txt'] + payload['SOURCE-INFO.txt']
        binary_path = (root / 'fake-build' / target / ('tor-socks5.exe' if 'windows' in target else 'tor-socks5')).resolve()
        binary_path.parent.mkdir(parents=True, exist_ok=True)
        binary_path.write_bytes(binary)
        name = admission.archive_name(TAG, target)
        archive_path = artifacts / name
        if 'windows' in target:
            with zipfile.ZipFile(archive_path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('tor-socks5.exe', binary)
        else:
            bundle.pack({'tor-socks5': binary}, archive_path)
        archive_bytes = archive_path.read_bytes()
        suffix = ' *' + name if name.endswith('.zip') else '  ' + name + '\n'
        (artifacts / (name + '.sha256')).write_bytes((bundle.digest(archive_bytes) + suffix).encode())
        messages = (bundle.encoded({'reason': 'compiler-artifact',
                                   'package_id': 'path+file:///fixture/socks5-proxy#0.0.0',
                                   'target': {'name': 'socks5-proxy'}, 'executable': str(binary_path)}) +
                    bundle.encoded({'reason': 'build-finished', 'success': True}))
        files = {'candidate.tar.gz': candidate.read_bytes(), 'messages.jsonl': messages,
                 'features.txt': MARKER, 'toolchain.txt': MARKER,
                 'native-evidence/linkage.txt': MARKER, 'native-evidence/build-stderr.txt': MARKER,
                 'native-evidence/native/TEST-ONLY.txt': MARKER,
                 'expanded-sources.json': bundle.encoded(admission.crate_hashes(payload, TAG)),
                 'review.json': bundle.encoded({})}
        receipt = {'schema': 1, 'target': target, 'tag': TAG, 'sdk_commit': bundle.SDK_COMMIT,
                   'source_digest': admission.source_digest(payload), 'binary_sha256': bundle.digest(binary),
                   'binary_path': str(binary_path), 'build_evidence_digest': admission.build_evidence_digest(files)}
        receipt_dir = original / ('license-evidence-' + target) / 'license-receipt'
        receipt_dir.parent.mkdir(parents=True, exist_ok=True)
        admission.write_receipt(receipt_dir, files, receipt)
        receipt, pending = admission.check_receipt(admission.collect(receipt_dir), target, TAG)
        assert set(pending) == {kind + ': missing reviewed evidence' for kind in admission.REQUIRED}
        review = {key: receipt[key] for key in ('source_digest', 'binary_sha256', 'target', 'build_evidence_digest')}
        review['evidence'] = {kind: {'path': 'TEST-ONLY.txt', 'sha256': bundle.digest(MARKER),
                                     'obligations': 'TEST ONLY', 'reviewer_rationale': 'TEST ONLY'}
                              for kind in admission.REQUIRED}
        review_path = review_dir / (target + '.json')
        review_path.write_bytes(bundle.encoded(review))
        final_dir = final / ('license-evidence-' + target) / 'license-receipt'
        final_dir.parent.mkdir(parents=True, exist_ok=True)
        assert not admission.finalize_review(SimpleNamespace(receipt=receipt_dir, review=review_path, output=final_dir))
        assert not admission.check_receipt(admission.collect(final_dir), target, TAG)[1]
    review_contents = {REVIEW_PREFIX + p.name: p.read_bytes() for p in review_dir.iterdir()}
    review_proof = proof({p: (data, '100644') for p, data in review_contents.items()})
    review_payload = {'review-source-proof.json': bundle.encoded(review_proof)}
    review_payload.update({'reviews-used/' + p: data for p, data in review_contents.items()})
    shutil.copytree(artifacts, assembled)
    output = assembled / ('tor-socks5-' + TAG + '-license-bundle.tar.gz')
    assert not admission.assemble(SimpleNamespace(evidence=final, artifacts=assembled, tag=TAG, output=output))
    return {'original_evidence': original, 'final_evidence': final, 'artifacts': artifacts,
            'assembled_artifacts': assembled, 'tag': TAG, 'project_sha': project_sha,
            'review_sha': review_proof['commit'], 'review_proof_payload': review_payload,
            'producer_run_id': PRODUCER_RUN_ID, 'producer_attempt': PRODUCER_ATTEMPT,
            'producer_artifact_id': PRODUCER_ARTIFACT_ID, 'policy_sha': POLICY_SHA}
