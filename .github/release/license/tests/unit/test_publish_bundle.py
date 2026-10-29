# -*- coding: utf-8 -*-
"""Production publisher rejection tests with untrusted synthetic artifacts."""
import importlib.util
import io
import os
import subprocess
from pathlib import Path
import sys
import tarfile
import unittest
import zipfile

sys.dont_write_bytecode = True

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import bundle
import admission
from test_source_inventory import payload_proofs

ROOT = Path(__file__).resolve().parents[5]
SPEC = importlib.util.spec_from_file_location(
    "release_harness", ROOT / ".github/install/tests/test_release.py")
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)
fx = harness.fx
TAG = harness.TAG
PUBLISHER = ROOT / ".github/release/publish-bundle.sh"
BUNDLE = "tor-socks5-%s-license-bundle.tar.gz" % TAG
ORIGIN_ENV = {
    'POLICY_SHA': 'a' * 40, 'BUILD_SHA': 'b' * 40, 'REVIEW_COMMIT': 'c' * 40,
    'PROMOTION_RUN_ID': '101', 'PROMOTION_ATTEMPT': '1', 'PROMOTION_ARTIFACT_ID': '102',
    'PRODUCER_RUN_ID': '201', 'PRODUCER_ATTEMPT': '1', 'PRODUCER_ARTIFACT_ID': '202',
}

# Read-only Actions responses establish a valid run identity but deliberately
# identify an untrusted workflow. Any unexpected request fails closed.
GH_ACTIONS_STUB = r'''
import json, os, sys
args = sys.argv[1:]
read_only = len(args) == 2 and args[0] == 'api'
with open(os.environ['GH_MOCK_LOG'], 'a', encoding='utf-8') as log:
    log.write(json.dumps({'argv': args, 'mutation': not read_only}) + '\n')
repo = 'PHPCraftdream/tor-socks5'
if args == ['api', 'repos/' + repo + '/actions/runs/101/attempts/1']:
    print(json.dumps({'id': 101, 'run_attempt': 1, 'head_sha': 'a' * 40,
        'head_branch': 'main', 'event': 'workflow_dispatch', 'status': 'completed',
        'conclusion': 'success', 'repository': {'full_name': repo},
        'head_repository': {'full_name': repo}, 'workflow_id': 9}))
elif args == ['api', 'repos/' + repo + '/actions/workflows/9']:
    print(json.dumps({'id': 9, 'path': '.github/workflows/untrusted.yml'}))
else:
    sys.exit(1)
'''


def make_artifacts(area, artifacts):
    """Build synthetic source, reviews and receipts in the admission format."""
    bundle.MODES.clear()
    root = Path(area)
    artifacts = Path(artifacts)
    crate_path = root / 'demo-1.crate'
    bundle.pack({'demo-1/Cargo.toml': b'[package]\nname="demo"\nversion="1"\nlicense="MIT"\n',
                 'demo-1/LICENSE': b'MIT license for demo\n',
                 'demo-1/src/lib.rs': b'pub fn demo() {}\n'}, crate_path)
    crate = crate_path.read_bytes()
    base = 'sources/' + TAG + '/'
    sources = {base + 'project/Cargo.lock': ('[[package]]\nname="demo"\nversion="1"\nsource="' + bundle.REGISTRY + '"\nchecksum="' + bundle.digest(crate) + '"\n').encode(),
               base + 'project/Cargo.toml': b'[workspace.package]\nlicense="MIT"\n[patch.crates-io]\npatch={path="vendor/patch"}\n',
               base + 'project/LICENSE-MIT': b'MIT license\n',
               base + 'project/LICENSE-APACHE': b'Apache license\n',
               base + 'project/vendor/patch/Cargo.toml': b'[package]\nname="patch"\nversion="1.0.0"\nlicense="MIT"\n',
               base + 'project/vendor/patch/lib.rs': b'pub fn patch() {}\n',
               base + 'project/vendor/patch/NOTICE': b'Copyright 2026 Synthetic Fixture Authors\n',
               base + 'sdk/Cargo.toml': b'[workspace.package]\nlicense="MIT"\n',
               base + 'sdk/LICENSE-MIT': b'MIT license\n',
               base + 'sdk/crates/resocks5-net/lib.rs': b'pub fn net() {}\n',
               base + 'registry/demo-1.crate': crate}
    components, inventory, copies = bundle.reconstruct(sources, TAG)
    payload = dict(sources)
    payload.update(copies)
    reviews = {'components': {}}
    for component in components:
        paths = component['candidates'] or [base + 'project/LICENSE-MIT']
        refs = [{'path': path, 'sha256': bundle.digest(payload[path])} for path in paths]
        source_path = component['source_paths'][0]
        source_ref = {'path': source_path, 'sha256': bundle.digest(payload[source_path])}
        reviews['components'][component['id']] = {
            'source_digest': component['source_digest'], 'selected_license': 'MIT',
            'notices': refs, 'evidence': [source_ref],
            'retained_notices': refs, 'corresponding_source': [source_ref],
            'obligations': 'Retain license and source notices.',
            'rationale': 'Synthetic fixture review.'}
        if component['id'].startswith('vendor:'):
            reviews['components'][component['id']]['attribution_review'] = [
                {'path': p, 'sha256': bundle.digest(payload[p]), 'rationale': 'Synthetic file review.'}
                for p in component['source_paths']]
    notices, source_info, candidate_problems = bundle.canonical_reports(payload, components, TAG)
    problems = bundle.blockers(components, reviews, payload) + candidate_problems
    tracked_paths = {p for c in components if not c['id'].startswith('registry:')
                     for p in c['source_paths']}
    modes = {p: '100644' for p in tracked_paths}
    proofs = payload_proofs(payload, TAG, modes)
    payload['GIT-SOURCES.json'] = bundle.encoded(proofs)
    payload.update({'SOURCE-MODES.json': bundle.encoded(modes),
                    'REVIEWS.json': bundle.encoded(reviews),
                    'BLOCKERS.json': bundle.encoded(problems),
                    'NOTICES.txt': notices, 'SOURCE-INFO.txt': source_info})
    manifest = {'schema': 1, 'tag': TAG, 'sdk_commit': proofs['sdk']['commit'],
                'components': components, 'packages': inventory,
                'files': [{'path': p, 'size': len(d), 'sha256': bundle.digest(d)}
                          for p, d in sorted(payload.items())]}
    payload['MANIFEST.json'] = bundle.encoded(manifest)
    candidate = root / 'candidate.tar.gz'
    bundle.pack(payload, candidate)
    evidence_root = root / 'evidence'
    for target in admission.TARGETS:
        binary = b'synthetic binary ' + target.encode() + b'\n' + payload['NOTICES.txt'] + payload['SOURCE-INFO.txt']
        binary_path = str((root / ('binary-' + target)).resolve())
        messages = (bundle.encoded({'reason': 'compiler-artifact', 'package_id': 'socks5-proxy 1.0.0',
                                    'target': {'name': 'socks5-proxy'}, 'executable': binary_path})
                    + bundle.encoded({'reason': 'build-finished', 'success': True}))
        receipt = {'schema': 1, 'target': target, 'tag': TAG, 'sdk_commit': bundle.SDK_COMMIT,
                   'source_digest': admission.source_digest(payload),
                   'binary_sha256': bundle.digest(binary), 'binary_path': binary_path}
        files = {'candidate.tar.gz': candidate.read_bytes(), 'messages.jsonl': messages,
                 'features.txt': b'Synthetic features\n', 'toolchain.txt': b'Synthetic toolchain\n',
                 'native-evidence/linkage.txt': b'Synthetic linkage\n',
                 'native-evidence/build-stderr.txt': b'Synthetic build stderr\n',
                 'native-evidence/native/input.txt': b'Synthetic native input\n',
                 'expanded-sources.json': bundle.encoded(admission.crate_hashes(payload, TAG))}
        receipt['build_evidence_digest'] = admission.build_evidence_digest(files)
        review = {k: receipt[k] for k in ('source_digest', 'binary_sha256', 'target', 'build_evidence_digest')}
        review['evidence'] = {}
        for kind in admission.REQUIRED:
            path = 'review-evidence/' + kind
            files[path] = ('Synthetic reviewed evidence: ' + kind + '\n').encode()
            review['evidence'][kind] = {'path': path, 'sha256': bundle.digest(files[path]),
                                        'obligations': 'Synthetic obligations.',
                                        'reviewer_rationale': 'Synthetic reviewer assessment.'}
        files['review.json'] = bundle.encoded(review)
        receipt['evidence'] = {p: bundle.digest(d) for p, d in sorted(files.items())}
        files['receipt.json'] = bundle.encoded(receipt)
        directory = evidence_root / ('license-evidence-' + target) / 'license-receipt'
        for name, data in files.items():
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        name = admission.archive_name(TAG, target)
        path = artifacts / name
        if name.endswith('.zip'):
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('tor-socks5.exe', binary)
        else:
            bundle.pack({'tor-socks5': binary}, path)
        separator, end = (' *', '') if name.endswith('.zip') else ('  ', '\n')
        (artifacts / (name + '.sha256')).write_bytes(
            (bundle.digest(path.read_bytes()) + separator + name + end).encode())
    self_contained = {}
    receipts, candidates = {}, {}
    for target in admission.TARGETS:
        files = admission.collect(evidence_root / ('license-evidence-' + target) / 'license-receipt')
        receipts[target] = bundle.strict_json(files['receipt.json'])
        candidates[target] = files['candidate.tar.gz']
        self_contained.update({'targets/' + target + '/' + p: d for p, d in files.items()})
    records = admission.artifacts_check(artifacts, TAG, receipts, False, candidates)
    self_contained['MANIFEST.json'] = bundle.encoded({'schema': 1, 'tag': TAG, 'targets': records,
        'files': {p: bundle.digest(d) for p, d in sorted(self_contained.items())}})
    output = artifacts / BUNDLE
    bundle.pack(self_contained, output)
    (artifacts / (BUNDLE + '.sha256')).write_bytes(
        (bundle.digest(output.read_bytes()) + '  ' + BUNDLE + '\n').encode())
    return proofs


class BundlePublisherTests(unittest.TestCase):
    # Reuse only helpers, not PublisherTests' test methods or assertions.
    gh_state = harness.PublisherTests.gh_state
    assets_of = harness.PublisherTests.assets_of

    def setUp(self):
        self.area = fx.TempArea(self)
        self.bin_dir = self.area.subdir("bin")
        fx.write_executable(self.bin_dir, "gh", "\n" + GH_ACTIONS_STUB)
        self.artifacts = self.area.subdir("artifacts")
        self.proofs = make_artifacts(self.area.path, self.artifacts)
        self.names = harness.expected_names(TAG) + [BUNDLE, BUNDLE + ".sha256"]

    def run_publish(self, state, missing_origin=False):
        env = os.environ.copy()
        for name in (*ORIGIN_ENV, 'ORIGIN_DIR'):
            env.pop(name, None)
        env.update(PATH=self.bin_dir + os.pathsep + os.environ["PATH"],
                   GH_MOCK_STATE=state, GH_MOCK_LOG=os.path.join(self.area.path, "gh-log.jsonl"),
                   TAG=TAG, PRERELEASE="false", ARTIFACTS_DIR=self.artifacts,
                   REMOTE_REPO=harness.REMOTE_REPO, GH_TOKEN="offline-test")
        if not missing_origin:
            env.update(ORIGIN_ENV, ORIGIN_DIR=self.area.path)
        result = fx.run_cmd(["bash", str(PUBLISHER)], env=env, cwd=fx.REPO_ROOT)
        result.stdout = result.stdout.decode('utf-8')
        result.stderr = result.stderr.decode('utf-8')
        self.assertIsInstance(result.stdout, str)
        self.assertIsInstance(result.stderr, str)
        return result

    def assert_untrusted_workflow(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('provenance failed: untrusted producer workflow', result.stderr)
        self.assertIn('promotion provenance verification failed', result.stderr)
        calls = self.log()
        self.assertEqual([entry['argv'] for entry in calls], [
            ['api', 'repos/PHPCraftdream/tor-socks5/actions/runs/101/attempts/1'],
            ['api', 'repos/PHPCraftdream/tor-socks5/actions/workflows/9'],
        ])
        self.assertEqual(harness.mutations(calls), [])

    def test_missing_origin_context(self):
        result = self.run_publish(self.gh_state(), missing_origin=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('не задан env ORIGIN_DIR', result.stderr)
        self.assertEqual(self.log(), [])

    def test_checksum_unit_rejects_tampering(self):
        data = Path(self.artifacts, BUNDLE).read_bytes()
        sidecar = Path(self.artifacts, BUNDLE + '.sha256').read_bytes()
        admission.checksum(data, BUNDLE, sidecar)
        with self.assertRaisesRegex(ValueError, 'invalid checksum: ' + BUNDLE):
            admission.checksum(data + b'tampered', BUNDLE, sidecar)

    def log(self):
        return harness.read_log(os.path.join(self.area.path, "gh-log.jsonl"))

    def verify_cli(self):
        return subprocess.run([sys.executable, '-I', str(Path(admission.__file__).resolve()),
                               'verify-release', '--artifacts', str(self.artifacts), '--tag', TAG],
                              capture_output=True, text=True, env={})

    def test_synthetic_isolated_release_gate_rejects_sdk_pin(self):
        result = self.verify_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unsupported manifest', result.stderr)

    def test_rehashed_changed_sources_rejected(self):
        candidate = Path(self.area.path) / 'candidate.tar.gz'
        original = bundle.read_tar(candidate.read_bytes(), limit=bundle.MAX_TOTAL, files_only=True)
        for suffix in ('sdk/crates/resocks5-net/lib.rs', 'project/vendor/patch/lib.rs',
                       'project/Cargo.toml'):
            with self.subTest(source=suffix):
                payload = dict(original)
                path = 'sources/' + TAG + '/' + suffix
                payload[path] += b'\n# changed\n' if path.endswith('.toml') else b'\n// changed\n'
                manifest = bundle.strict_json(payload['MANIFEST.json'])
                for record in manifest['files']:
                    if record['path'] == path:
                        record['size'] = len(payload[path])
                        record['sha256'] = bundle.digest(payload[path])
                payload['MANIFEST.json'] = bundle.encoded(manifest)
                changed = Path(self.area.path) / ('changed-' + suffix.replace('/', '-') + '.tar.gz')
                bundle.pack(payload, changed)
                with self.assertRaisesRegex(ValueError, 'source blob mismatch'):
                    bundle.verify_format(changed, self.proofs['project']['commit'], self.proofs['sdk']['commit'])

    def test_receipt_target_and_named_native_evidence_rejected(self):
        target = admission.TARGETS[0]
        directory = Path(self.area.path) / 'evidence' / ('license-evidence-' + target) / 'license-receipt'
        original = admission.collect(directory)
        with self.assertRaisesRegex(ValueError, 'receipt identity mismatch'):
            admission.check_receipt(original, admission.TARGETS[1], TAG)
        files = dict(original)
        del files['native-evidence/linkage.txt']
        receipt = bundle.strict_json(files['receipt.json'])
        del receipt['evidence']['native-evidence/linkage.txt']
        files['receipt.json'] = bundle.encoded(receipt)
        with self.assertRaisesRegex(ValueError, 'missing build evidence'):
            admission.check_receipt(files, target, TAG)

    def test_cli_missing_bundle(self):
        Path(self.artifacts, BUNDLE).unlink()
        result = self.verify_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('admission failed:', result.stderr)

    def test_synthetic_draft_rejected_without_gh_mutation(self):
        release = {"id": 7, "tag_name": TAG, "draft": True, "prerelease": False, "assets": []}
        state = self.gh_state(releases=[release])
        result = self.run_publish(state)
        self.assert_untrusted_workflow(result)
        self.assertEqual(self.assets_of(harness.read_state(state)), release)

    def test_missing_bundle_rejected_before_network(self):
        os.remove(os.path.join(self.artifacts, BUNDLE))
        result = self.run_publish(self.gh_state())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('не найден файл', result.stderr)
        self.assertEqual(self.log(), [])

    def test_bad_checksum_rejected_before_network(self):
        Path(self.artifacts, BUNDLE + '.sha256').write_bytes(b'bad checksum\n')
        result = self.run_publish(self.gh_state())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('checksum-файл', result.stderr)
        self.assertEqual(self.log(), [])

    def test_tampered_bundle_rejected_by_provenance_first(self):
        path = os.path.join(self.artifacts, BUNDLE)
        members = bundle.read_tar(Path(path).read_bytes(), limit=bundle.MAX_TOTAL, files_only=True,
                                  max_member=bundle.MAX_TOTAL)
        member = next(p for p in members if p.endswith('/features.txt'))
        members[member] += b'tampered\n'
        with tarfile.open(path, 'w:gz') as archive:
            for name, data in sorted(members.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        # Keep the outer checksum consistent; provenance rejects before admission.
        digest = fx.sha256_hex(fx.file_bytes(path))
        with open(path + ".sha256", "wb") as f:
            f.write((digest + "  " + BUNDLE + "\n").encode("ascii"))
        state = self.gh_state()
        self.assert_untrusted_workflow(self.run_publish(state))

    def test_published_no_mutation(self):
        assets = [{"name": n, "size": 1, "state": "uploaded"} for n in self.names]
        release = {"id": 5, "tag_name": TAG, "draft": False, "prerelease": False, "assets": assets}
        state = self.gh_state(releases=[release])
        result = self.run_publish(state)
        self.assert_untrusted_workflow(result)
        self.assertEqual(self.assets_of(harness.read_state(state)), release)

    def test_partial_published_rejected_without_mutation(self):
        assets = [{"name": n, "size": 1, "state": "uploaded"} for n in self.names[:-1]]
        release = {"id": 5, "tag_name": TAG, "draft": False, "prerelease": False, "assets": assets}
        state = self.gh_state(releases=[release])
        self.assert_untrusted_workflow(self.run_publish(state))
        self.assertEqual(self.assets_of(harness.read_state(state)), release)


if __name__ == "__main__":
    unittest.main()
