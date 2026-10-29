#!/usr/bin/env python3
"""Pure synthetic Git-format and mocked API unit tests, not production provenance."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

spec = importlib.util.spec_from_file_location('provenance', Path(__file__).resolve().parents[2] / 'provenance.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
proof_spec = importlib.util.spec_from_file_location(
    'source_inventory_test_helper', Path(__file__).with_name('test_source_inventory.py'))
proof_helper = importlib.util.module_from_spec(proof_spec)
proof_spec.loader.exec_module(proof_helper)


class WriteTreeTests(unittest.TestCase):
    def test_nested_output_and_refusals(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / 'missing' / 'target' / 'promoted'
            files = {'one': b'\x00\xff\n', 'nested/two': b'exact\r\n'}
            p.write_tree(output, files)
            self.assertEqual(p.local_tree(output), files)
            with self.assertRaises(FileExistsError):
                p.write_tree(output, {'one': b'replacement'})
            self.assertEqual(p.local_tree(output), files)

            outside = root / 'outside'
            outside.mkdir()
            link = root / 'link'
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'linked output parent'):
                p.write_tree(link / 'missing' / 'promoted', files)
            self.assertFalse((outside / 'missing').exists())


class ApiBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.sha = 'a' * 40
        self.run = {'id': 12, 'run_attempt': 2, 'head_sha': self.sha, 'head_branch': 'main',
                    'event': 'workflow_dispatch', 'status': 'completed', 'conclusion': 'success',
                    'repository': {'full_name': p.REPO}, 'head_repository': {'full_name': p.REPO},
                    'workflow_id': 33}
        self.workflow = {'id': 33, 'path': p.PRODUCER_WORKFLOW}
        self.jobs = [{'name': name, 'status': 'completed', 'conclusion': 'success'}
                     for name in sorted(p.REQUIRED_JOBS)]
        self.artifact = {'id': 45, 'name': 'license-retained-12-2', 'expired': False,
                         'digest': 'sha256:' + 'b' * 64, 'created_at': '2026-01-01T00:00:00Z',
                         'expires_at': '2027-01-01T00:00:00Z',
                         'workflow_run': {'id': 12, 'head_sha': self.sha}}

    def api(self, endpoint, paginate=False):
        if endpoint == 'actions/runs/12/attempts/2':
            return self.run
        if endpoint == 'actions/workflows/33':
            return self.workflow
        if endpoint == 'actions/runs/12/attempts/2/jobs?per_page=100':
            return [{'jobs': self.jobs}]
        if endpoint == 'actions/artifacts/45':
            return self.artifact
        raise AssertionError(endpoint)

    def check(self):
        with mock.patch.object(p, 'api', side_effect=self.api):
            return p.identity(12, 2, 45, self.sha, 'v1.2.3')

    def test_promotion_identity_and_fail_closed_review_binding(self):
        self.workflow['path'] = p.PROMOTION_WORKFLOW
        self.jobs = [{'name': 'Finalize retained release candidate', 'status': 'completed', 'conclusion': 'success'}]
        self.artifact['name'] = 'license-admitted-12-2'
        producer = {'run_id': 7, 'attempt': 1, 'artifact_id': 8,
                    'head_sha': 'c' * 40, 'tag': 'v1.2.3'}
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            archive.writestr('promotion-manifest.json', json.dumps({'producer': producer}))
        data = out.getvalue()
        self.artifact['digest'] = 'sha256:' + hashlib.sha256(data).hexdigest()
        def api(endpoint, paginate=False):
            if endpoint == 'commits/' + 'd' * 40:
                return {'sha': 'd' * 40, 'commit': {'tree': {'sha': 'e' * 40}}}
            return self.api(endpoint, paginate)
        with mock.patch.object(p, 'api', side_effect=api), mock.patch.object(p, 'gh', return_value=data):
            with self.assertRaisesRegex(ValueError, 'missing reviewer Git binding'):
                p.fetch_promotion(12, 2, 45, 'c' * 40, 'v1.2.3', 'd' * 40, 7, 1, 8, self.sha)
            with self.assertRaisesRegex(ValueError, 'requested producer identity mismatch'):
                p.fetch_promotion(12, 2, 45, 'c' * 40, 'v1.2.3', 'd' * 40, 9, 1, 8, self.sha)

    def test_valid_api_identity(self):
        self.assertEqual(self.check(), 'b' * 64)

    def test_reject_untrusted_runs(self):
        for field, value in [('event', 'pull_request'), ('id', 13), ('head_branch', 'feature'),
                             ('head_sha', 'c' * 40), ('run_attempt', 1),
                             ('conclusion', 'failure'), ('head_repository', {'full_name': 'fork/repo'})]:
            original = self.run[field]
            self.run[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check()
            self.run[field] = original

    def test_reject_workflow_and_job_mismatch(self):
        self.workflow['path'] = p.PROMOTION_WORKFLOW
        with self.assertRaises(ValueError):
            self.check()
        self.workflow['path'] = p.PRODUCER_WORKFLOW
        self.workflow['id'] = 34
        with self.assertRaisesRegex(ValueError, 'workflow'):
            self.check()
        self.workflow['id'] = 33
        self.jobs[0]['conclusion'] = 'failure'
        with self.assertRaises(ValueError):
            self.check()
        self.jobs[0]['conclusion'] = 'success'
        self.jobs.pop()
        with self.assertRaises(ValueError):
            self.check()
        self.jobs.append(dict(self.jobs[0]))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.check()

    def test_reject_missing_digest_and_attempt_binding(self):
        for field, value in [('digest', None), ('id', 46), ('name', 'license-retained-12-1'),
                             ('expired', True), ('workflow_run', {'id': 99, 'head_sha': self.sha})]:
            old = self.artifact[field]
            self.artifact[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check()
            self.artifact[field] = old

    def test_reject_archive_digest_tamper_before_parsing(self):
        with mock.patch.object(p, 'api', side_effect=self.api), mock.patch.object(p, 'gh', return_value=b'tampered'):
            with self.assertRaisesRegex(ValueError, 'archive digest mismatch'):
                p.fetch_verified(12, 2, 45, self.sha, 'v1.2.3')

    def test_reject_unsafe_zip(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as z:
            z.writestr('../escape', b'x')
        with self.assertRaises(ValueError):
            p.unzip(out.getvalue())

    def test_reject_manifest_tamper(self):
        files = {'data': b'changed'}
        manifest = {'schema': 1, 'run_id': 12, 'run_attempt': 2, 'head_sha': self.sha,
                    'tag': 'v1.2.3', 'files': {'data': hashlib.sha256(b'original').hexdigest()}}
        files['retained-manifest.json'] = json.dumps(manifest).encode()
        with self.assertRaisesRegex(ValueError, 'manifest mismatch'):
            p.validate(files, 12, 2, self.sha, 'v1.2.3')

    def test_git_verifier_anchors_project_and_uses_sdk_default(self):
        with mock.patch.object(p.bundle, 'read_tar', return_value={'GIT-SOURCES.json': b'{}'}), \
             mock.patch.object(p.inventory, 'verify_sources') as verify:
            p.verify_git_bundle(b'candidate', 'v1.2.3', self.sha)
        verify.assert_called_once_with({'GIT-SOURCES.json': b'{}'}, 'v1.2.3', expected_project_commit=self.sha)


class PromotionTests(unittest.TestCase):
    """Mocked envelope-dispatch tests; neither origin nor reviewer proof is verified here."""
    def setUp(self):
        self.sha, self.review, self.tag = 'a' * 40, 'b' * 40, 'v1.2.3'
        self.producer = {'run_id': 12, 'attempt': 2, 'artifact_id': 45,
                         'head_sha': self.sha, 'tag': self.tag}
        self.promotion = {'run_id': 99, 'run_attempt': 1, 'head_sha': 'c' * 40}
        self.origin = {'retained-manifest.json': b'origin'}
        self.files = {'origin/retained/retained-manifest.json': b'origin',
                      'artifacts/item': b'artifact', 'evidence/item': b'evidence'}
        self.manifest = {'schema': 1, 'producer': self.producer, 'promotion': self.promotion,
                         'tag': self.tag, 'review_commit': self.review}
        self.rehash()

    def rehash(self):
        self.manifest['files'] = {k: p.bundle.digest(v) for k, v in self.files.items()
                                  if k != 'promotion-manifest.json'}
        self.files['promotion-manifest.json'] = p.bundle.encoded(self.manifest)

    def verify(self):
        with mock.patch.object(p, 'fetch_verified', return_value=self.origin) as fetch, \
             mock.patch.object(p, 'verify_review_binding') as binding, \
             mock.patch.object(p, 'compare_final') as compare:
            p.verify_promoted_files(self.files, self.promotion, self.sha, self.tag, self.review)
            fetch.assert_called_once_with(12, 2, 45, self.sha, self.tag)
            binding.assert_called_once()
            compare.assert_called_once()

    def test_missing_review_proof_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'missing reviewer Git binding'):
            p.verify_review_binding({}, self.review, {})

    def test_envelope_dispatch_with_mocked_origin_and_binding(self):
        self.verify()

    def test_reject_tampered_hash_and_extra_file(self):
        self.files['artifacts/item'] = b'changed'
        with self.assertRaisesRegex(ValueError, 'manifest'):
            self.verify()
        self.rehash()
        self.files['extra'] = b'x'
        self.rehash()
        with self.assertRaisesRegex(ValueError, 'unexpected promotion file'):
            self.verify()

    def test_reject_origin_substitution_even_with_rehashed_manifest(self):
        self.files['origin/retained/retained-manifest.json'] = b'other'
        self.rehash()
        with self.assertRaisesRegex(ValueError, 'origin differs'):
            self.verify()

    def test_reject_review_and_promotion_context_changes(self):
        self.manifest['review_commit'] = 'd' * 40
        self.rehash()
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            self.verify()


class ReviewerBindingTests(unittest.TestCase):
    """Synthetic object-format tests, not proof of production origin or main admission."""
    def setUp(self):
        self.source = {p.REVIEW_PREFIX + 'evidence.txt': b'TEST ONLY evidence\n',
                       'unrelated.txt': b'full tree record\n'}
        self.final = {}
        for target in p.admission.TARGETS:
            review = {'target': target, 'source_digest': '1' * 64,
                      'binary_sha256': '2' * 64, 'build_evidence_digest': '3' * 64,
                      'evidence': {kind: {'path': 'evidence.txt',
                                          'sha256': p.bundle.digest(b'TEST ONLY evidence\n'),
                                          'obligations': 'TEST ONLY',
                                          'reviewer_rationale': 'TEST ONLY'}
                                   for kind in p.admission.REQUIRED}}
            self.source[p.REVIEW_PREFIX + target + '.json'] = p.bundle.encoded(review)
            prefix = 'license-evidence-' + target + '/license-receipt/'
            for kind, entry in review['evidence'].items():
                entry['path'] = 'review-evidence/' + kind
                self.final[prefix + entry['path']] = b'TEST ONLY evidence\n'
            self.final[prefix + 'review.json'] = p.bundle.encoded(review)
        self.proof = proof_helper.proof({path: (data, '100644') for path, data in self.source.items()})
        self.anchor = self.proof['commit']
        self.files = {'reviews-used/' + path: data for path, data in self.source.items()
                      if path.startswith(p.REVIEW_PREFIX)}
        self.update_proof()

    def update_proof(self):
        self.files['review-source-proof.json'] = p.bundle.encoded(self.proof)

    def verify(self):
        return p.verify_review_binding(self.files, self.anchor, self.final)

    def test_real_synthetic_commit_tree_blob_and_review_bytes(self):
        self.assertIsNone(self.verify())

    def test_rehashed_review_and_manifest_cannot_replace_git_blob(self):
        path = p.REVIEW_PREFIX + p.admission.TARGETS[0] + '.json'
        data = self.files['reviews-used/' + path] + b' '
        self.files['reviews-used/' + path] = data
        record = next(r for r in self.proof['files'] if r['path'] == path)
        record['size'], record['sha256'] = len(data), p.bundle.digest(data)
        self.update_proof()
        self.files['promotion-manifest.json'] = p.bundle.encoded(
            {'files': {k: p.bundle.digest(v) for k, v in self.files.items()}})
        with self.assertRaisesRegex(ValueError, 'review source blob mismatch'):
            self.verify()

    def test_replaced_commit_fails_external_anchor(self):
        changed = dict(self.source, **{'unrelated.txt': b'replaced'})
        self.proof = proof_helper.proof({path: (data, '100644') for path, data in changed.items()})
        self.update_proof()
        with self.assertRaisesRegex(ValueError, 'invalid reviewer Git proof'):
            self.verify()

    def test_final_review_and_evidence_substitution_rejected(self):
        target = p.admission.TARGETS[0]
        prefix = 'license-evidence-' + target + '/license-receipt/'
        for suffix in ('review.json', 'review-evidence/' + p.admission.REQUIRED[0]):
            with self.subTest(suffix=suffix):
                old = self.final[prefix + suffix]
                self.final[prefix + suffix] = b'substituted'
                with self.assertRaisesRegex(ValueError, 'final review differs'):
                    self.verify()
                self.final[prefix + suffix] = old

    def test_missing_and_extra_review_sources_rejected(self):
        path = 'reviews-used/' + p.REVIEW_PREFIX + 'evidence.txt'
        old = self.files.pop(path)
        with self.assertRaises(KeyError):
            self.verify()
        self.files[path] = old
        extra = p.REVIEW_PREFIX + 'extra'
        self.source[extra] = b'extra'
        self.proof = proof_helper.proof({name: (data, '100644') for name, data in self.source.items()})
        self.anchor = self.proof['commit']
        self.update_proof()
        self.files['reviews-used/' + extra] = b'extra'
        with self.assertRaisesRegex(ValueError, 'review source file set mismatch'):
            self.verify()

    def test_dangerous_review_evidence_path_rejected(self):
        target = p.admission.TARGETS[0]
        path = p.REVIEW_PREFIX + target + '.json'
        review = json.loads(self.source[path])
        review['evidence'][p.admission.REQUIRED[0]]['path'] = '../escape'
        self.source[path] = p.bundle.encoded(review)
        self.proof = proof_helper.proof({name: (data, '100644') for name, data in self.source.items()})
        self.anchor = self.proof['commit']
        self.files['reviews-used/' + path] = self.source[path]
        self.update_proof()
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.verify()


class ProducerSourceMetadataTests(unittest.TestCase):
    """Format-only checks with explicitly supplied synthetic project and SDK anchors."""
    def setUp(self):
        self.metadata = {'schema': 1, 'project': proof_helper.proof({'a': (b'project', '100644')}),
                         'sdk': proof_helper.proof({'b': (b'sdk', '100644')})}
        self.project = self.metadata['project']['commit']
        self.sdk = self.metadata['sdk']['commit']
        self.payload = {'sources/v1/project/a': b'project', 'sources/v1/sdk/b': b'sdk'}

    def verify(self):
        self.payload['GIT-SOURCES.json'] = p.bundle.encoded(self.metadata)
        return p.inventory.verify_sources(self.payload, 'v1', expected_project_commit=self.project,
                                          sdk_expected=self.sdk)

    def test_source_metadata_invalid_schema_rejected(self):
        self.metadata['schema'] = 2
        with self.assertRaisesRegex(ValueError, 'metadata'):
            self.verify()

    def test_source_metadata_changed_blob_rejected(self):
        self.payload['sources/v1/sdk/b'] = b'changed'
        record = self.metadata['sdk']['files'][0]
        record['size'] = len(b'changed')
        record['sha256'] = p.bundle.digest(b'changed')
        with self.assertRaisesRegex(ValueError, 'source blob mismatch'):
            self.verify()

    def test_source_metadata_replaced_commit_rejected(self):
        self.metadata['project'] = proof_helper.proof({'a': (b'replaced', '100644')})
        with self.assertRaisesRegex(ValueError, 'source commit mismatch: project'):
            self.verify()


if __name__ == '__main__':
    unittest.main()
