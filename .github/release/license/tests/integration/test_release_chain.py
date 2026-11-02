#!/usr/bin/env python3
"""CI-only offline transport mechanics, NOT build, production, or legal evidence.

The SDK is the pinned checkout; binaries and reviews are TEST ONLY markers.
GitHub API responses and release mutations are simulated by a local gh transport.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
LICENSE = HERE.parents[1]
ROOT = HERE.parents[4]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'unit'))
sys.path.insert(0, str(LICENSE))
import chain_fixture
import provenance as p

REPO = p.REPO
POLICY = 'c' * 40
RUN, ATTEMPT, ARTIFACT = 12, 1, 45
PROMOTION_RUN, PROMOTION_ARTIFACT = 99, 98


def zip_files(path, files):
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)


def route_identity(routes, run, artifact, sha, workflow_id, promotion, archive):
    prefix = 'repos/' + REPO + '/'
    def put(path, value):
        routes[prefix + path] = value
    put(f'actions/runs/{run}/attempts/1', {
        'id': run, 'run_attempt': 1, 'head_sha': sha, 'head_branch': 'main',
        'event': 'workflow_dispatch', 'status': 'completed', 'conclusion': 'success',
        'repository': {'full_name': REPO}, 'head_repository': {'full_name': REPO},
        'workflow_id': workflow_id})
    put(f'actions/workflows/{workflow_id}', {'id': workflow_id, 'path':
        p.PROMOTION_WORKFLOW if promotion else p.PRODUCER_WORKFLOW})
    names = {'Finalize retained release candidate'} if promotion else p.REQUIRED_JOBS
    put(f'actions/runs/{run}/attempts/1/jobs?per_page=100', [{'jobs': [
        {'name': name, 'status': 'completed', 'conclusion': 'success'}
        for name in sorted(names)]}])
    put(f'actions/artifacts/{artifact}', {
        'id': artifact, 'name': f"license-{'admitted' if promotion else 'retained'}-{run}-1",
        'expired': False, 'digest': 'sha256:' + p.bundle.digest(archive.read_bytes()),
        'created_at': '2026-01-01T00:00:00Z', 'expires_at': '2027-01-01T00:00:00Z',
        'workflow_run': {'id': run, 'head_sha': sha}})
    put(f'actions/artifacts/{artifact}/zip', {'file': archive.name})


class ReleaseChainTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('GITHUB_ACTIONS') != 'true':
            raise AssertionError('release chain transport suite requires GitHub Actions CI')
        sdk = ROOT.parent / 'resocks5'
        if not sdk.is_dir():
            raise AssertionError('pinned SDK checkout missing: ' + str(sdk))
        # Deliberately retain temporary files; no cleanup or shared fixture mutation.
        cls.base = Path(tempfile.mkdtemp(prefix='license-chain-test-only-')).resolve()
        cls.inputs = chain_fixture.make_inputs(cls.base / 'inputs', sdk)
        cls.tag = cls.inputs['tag']
        cls.sha = cls.inputs['project_sha']
        cls.review = cls.inputs['review_sha']
        cls.producer = {'run_id': RUN, 'attempt': ATTEMPT, 'artifact_id': ARTIFACT,
                        'head_sha': cls.sha, 'tag': cls.tag}
        cls.promotion = {'run_id': PROMOTION_RUN, 'run_attempt': 1, 'head_sha': POLICY}
        origin = {'artifacts/' + name: data for name, data in
                  p.local_tree(cls.inputs['artifacts']).items()}
        origin.update({'evidence/' + name: data for name, data in
                       p.local_tree(cls.inputs['original_evidence']).items()})
        assert len(p.local_tree(cls.inputs['artifacts'])) == 14
        origin['retained-manifest.json'] = p.bundle.encoded({
            'schema': 1, 'run_id': RUN, 'run_attempt': ATTEMPT, 'head_sha': cls.sha,
            'tag': cls.tag, 'files': {name: p.bundle.digest(data) for name, data in origin.items()}})
        p.validate(origin, RUN, ATTEMPT, cls.sha, cls.tag)
        retained_zip = cls.base / 'retained.zip'
        zip_files(retained_zip, origin)
        cls.routes = {}
        route_identity(cls.routes, RUN, ARTIFACT, cls.sha, 33, False, retained_zip)
        cls.state = cls.base / 'state.json'
        cls.state.write_text(json.dumps({'releases': []}), encoding='utf-8')
        cls.log = cls.base / 'calls.jsonl'
        cls.log.write_text('', encoding='utf-8')
        cls.config = cls.base / 'config.json'
        cls.write_config()
        bin_dir = cls.base / 'bin'
        bin_dir.mkdir()
        gh = bin_dir / 'gh'
        gh.write_text('#!' + sys.executable + ' -I\nimport runpy\nrunpy.run_path(' +
                      repr(str(HERE / 'chain_transport.py')) + ', run_name="__main__")\n', encoding='utf-8')
        gh.chmod(0o755)
        cls.env = os.environ.copy()
        cls.env.update(PATH=str(bin_dir) + os.pathsep + os.environ.get('PATH', ''),
                       LICENSE_CHAIN_CONFIG=str(cls.config), LICENSE_CHAIN_LOG=str(cls.log),
                       GH_TOKEN='test-only-offline')
        final = p.local_tree(cls.inputs['assembled_artifacts'])
        assert len(final) == 16
        files = {'origin/retained/' + name: data for name, data in origin.items()}
        files.update({'artifacts/' + name: data for name, data in final.items()})
        files.update({'evidence/' + name: data for name, data in
                      p.local_tree(cls.inputs['final_evidence']).items()})
        files.update(cls.inputs['review_proof_payload'])
        files['promotion-manifest.json'] = p.bundle.encoded({
            'schema': 1, 'producer': cls.producer, 'review_commit': cls.review,
            'promotion': cls.promotion, 'tag': cls.tag,
            'files': {name: p.bundle.digest(data) for name, data in files.items()}})
        # Use real validators and real gh subprocesses; only the transport is fake.
        previous = os.environ.copy()
        try:
            os.environ.update(cls.env)
            p.verify_promoted_files(files, cls.promotion, cls.sha, cls.tag, cls.review)
        finally:
            os.environ.clear()
            os.environ.update(previous)
        promotion_zip = cls.base / 'promotion.zip'
        zip_files(promotion_zip, files)
        route_identity(cls.routes, PROMOTION_RUN, PROMOTION_ARTIFACT, POLICY, 34, True, promotion_zip)
        proof = p.bundle.strict_json(files['review-source-proof.json'])
        cls.routes['repos/' + REPO + '/commits/' + cls.review] = {
            'sha': cls.review, 'commit': {'tree': {'sha': proof['tree']}}}
        cls.write_config()
        cls.original = origin
        cls.final = final

    @classmethod
    def write_config(cls):
        cls.config.write_text(json.dumps({'repo': REPO, 'routes': cls.routes,
                                          'state': cls.state.name}), encoding='utf-8')

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='case-', dir=self.base))
        self.log.write_text('', encoding='utf-8')
        self.state.write_text(json.dumps({'releases': []}), encoding='utf-8')
        self.output = self.work / 'absent' / 'nested' / 'promoted'
        result = subprocess.run([sys.executable, '-I', str(LICENSE / 'provenance.py'),
                                 'fetch-promotion', *self.identity_args(), '--output', str(self.output)],
                                cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.output.is_dir())
        for name, data in self.original.items():
            if name.startswith('artifacts/'):
                self.assertEqual((self.output / name).read_bytes(), data)
        self.log.write_text('', encoding='utf-8')

    def identity_args(self):
        return ['--run-id', str(PROMOTION_RUN), '--attempt', '1', '--artifact-id', str(PROMOTION_ARTIFACT),
                '--head-sha', self.sha, '--tag', self.tag, '--review-commit', self.review,
                '--policy-sha', POLICY, '--producer-run-id', str(RUN), '--producer-attempt', '1',
                '--producer-artifact-id', str(ARTIFACT)]

    def assets(self):
        return [{'name': name, 'size': len(data), 'state': 'uploaded',
                 'digest': 'sha256:' + p.bundle.digest(data)} for name, data in sorted(self.final.items())]

    def publish(self, release):
        self.state.write_text(json.dumps({'releases': [release]}), encoding='utf-8')
        env = self.env.copy()
        env.update(TAG=self.tag, PRERELEASE='true', REMOTE_REPO=REPO,
                   ORIGIN_DIR=str(self.output), ARTIFACTS_DIR=str(self.output / 'artifacts'),
                   POLICY_SHA=POLICY, BUILD_SHA=self.sha, REVIEW_COMMIT=self.review,
                   PROMOTION_RUN_ID=str(PROMOTION_RUN), PROMOTION_ATTEMPT='1',
                   PROMOTION_ARTIFACT_ID=str(PROMOTION_ARTIFACT), PRODUCER_RUN_ID=str(RUN),
                   PRODUCER_ATTEMPT='1', PRODUCER_ARTIFACT_ID=str(ARTIFACT))
        return subprocess.run(['bash', str(ROOT / '.github/release/publish-bundle.sh')],
                              cwd=ROOT, env=env, capture_output=True, text=True)

    def release(self, draft, assets):
        return {'id': 7, 'tag_name': self.tag, 'draft': draft, 'prerelease': True, 'assets': assets}

    def calls(self):
        return [json.loads(line) for line in self.log.read_text(encoding='utf-8').splitlines()]

    def assert_release_read_no_mutations(self):
        calls = self.calls()
        self.assertIn(['api', '--paginate', '--slurp', 'repos/' + REPO + '/releases?per_page=100'],
                      [call['argv'] for call in calls])
        self.assertFalse([call for call in calls if call['mutation']])

    def test_fetch_nested_and_draft_publish(self):
        result = self.publish(self.release(True, []))
        self.assertEqual(result.returncode, 0, result.stderr)
        mutations = [c['argv'] for c in self.calls() if c['mutation']]
        uploads = [c for c in mutations if c[:2] == ['release', 'upload']]
        self.assertEqual(len(uploads), 16)
        self.assertEqual({Path(c[3]).name for c in uploads}, set(self.final))
        self.assertEqual(len(mutations), 17)
        self.assertEqual(mutations[-1], ['api', '--method', 'PATCH',
                         'repos/' + REPO + '/releases/7', '--input', '-'])
        release = json.loads(self.state.read_text(encoding='utf-8'))['releases'][0]
        self.assertFalse(release['draft'])
        self.assertEqual(release['prerelease'], True)
        self.assertEqual(release['make_latest'], 'false')
        self.assertEqual(sorted(release['assets'], key=lambda a: a['name']), self.assets())

    def test_matching_published_noop(self):
        result = self.publish(self.release(False, self.assets()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_release_read_no_mutations()

    def check_published_rejection(self, kind):
        assets = self.assets()
        if kind == 'missing asset':
            assets.pop()
        elif kind == 'wrong digest':
            assets[0]['digest'] = 'sha256:' + '0' * 64
        elif kind == 'wrong size':
            assets[0]['size'] += 1
        else:
            del assets[0]['digest']
        result = self.publish(self.release(False, assets))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('PUBLISHED', result.stderr)
        self.assert_release_read_no_mutations()

    def test_published_missing_asset(self):
        self.check_published_rejection('missing asset')

    def test_published_wrong_digest(self):
        self.check_published_rejection('wrong digest')

    def test_published_wrong_size(self):
        self.check_published_rejection('wrong size')

    def test_published_missing_digest(self):
        self.check_published_rejection('missing digest')

    def test_rehashed_bundle_tamper_rejected_by_fresh_archive(self):
        name = 'tor-socks5-' + self.tag + '-license-bundle.tar.gz'
        path = self.output / 'artifacts' / name
        members = p.bundle.read_tar(path.read_bytes(), limit=p.bundle.MAX_TOTAL, files_only=True,
                                    max_member=p.bundle.MAX_TOTAL)
        member = next(name for name in members if name.endswith('/features.txt'))
        members[member] += b'TEST ONLY tamper\n'
        new_path = self.output / (name + '.tampered')
        p.bundle.pack(members, new_path)
        path.write_bytes(new_path.read_bytes())
        (path.parent / (name + '.sha256')).write_bytes(
            (p.bundle.digest(path.read_bytes()) + '  ' + name + '\n').encode())
        result = self.publish(self.release(True, []))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('promoted tree differs', result.stderr)
        self.assertFalse([call for call in self.calls() if call['mutation']])
        self.assertNotIn(['api', '--paginate', '--slurp', 'repos/' + REPO + '/releases?per_page=100'],
                         [call['argv'] for call in self.calls()])


if __name__ == '__main__':
    unittest.main()
