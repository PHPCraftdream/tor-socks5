"""Basic admission boundary tests; run only when explicitly permitted."""
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.dont_write_bytecode = True

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import admission


class AdmissionTests(unittest.TestCase):
    def test_cargo_modern_id_and_failure(self):
        b = admission.bundle
        artifact = {'reason': 'compiler-artifact', 'package_id': 'path+file:///work/apps/socks5-proxy#0.2.0',
                    'target': {'name': 'socks5-proxy'}, 'executable': '/tmp/proxy'}
        data = b.encoded(artifact) + b.encoded({'reason': 'build-finished', 'success': True})
        admission.cargo(data, '/tmp/proxy')
        with self.assertRaises(ValueError):
            admission.cargo(data[:-1], '/tmp/proxy')

    def test_cargo_rejects_verbose_stdout_and_invalid_streams(self):
        b = admission.bundle
        artifact = b.encoded({'reason': 'compiler-artifact',
                              'package_id': 'path+file:///work/apps/socks5-proxy#0.2.0',
                              'target': {'name': 'socks5-proxy'}, 'executable': '/tmp/proxy'})
        finished = b.encoded({'reason': 'build-finished', 'success': True})
        admission.cargo(artifact + finished, '/tmp/proxy')
        # Строка stdout из фактического журнала CI не является JSON.
        verbose = b'[proc-macro2 1.0.106] cargo:rustc-check-cfg=cfg(fuzzing)\n'
        invalid = (artifact + verbose + finished, artifact + b'{\n' + finished,
                   (artifact + finished)[:-1], artifact + finished + artifact,
                   artifact + b.encoded({'reason': 'build-finished', 'success': False}))
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(ValueError):
                admission.cargo(data, '/tmp/proxy')
        with self.assertRaises(ValueError):
            admission.cargo(artifact + finished, '/tmp/other')

    def test_expanded_source_checks(self):
        b = admission.bundle
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / 'crate.tar.gz'
            b.pack({'demo-1/Cargo.toml': b'example', 'demo-1/src/lib.rs': b'code'}, archive)
            payload = {'sources/v1/registry/demo-1.crate': archive.read_bytes()}
            cache = root / 'registry/cache'
            src = root / 'registry/src/index/demo-1'
            (src / 'src').mkdir(parents=True)
            (src / 'Cargo.toml').write_bytes(b'example')
            (src / 'src/lib.rs').write_bytes(b'code')
            (src / '.cargo-ok').write_bytes(b'')
            self.assertEqual(admission.expanded_sources(payload, 'v1', cache), admission.crate_hashes(payload, 'v1'))
            (src / 'src/lib.rs').write_bytes(b'modified')
            with self.assertRaises(ValueError):
                admission.expanded_sources(payload, 'v1', cache)
            (src / 'src/lib.rs').write_bytes(b'code')
            (src / 'extra').write_bytes(b'generated')
            with self.assertRaises(ValueError):
                admission.expanded_sources(payload, 'v1', cache)

    def test_review_binds_build_evidence(self):
        b = admission.bundle
        files = {'messages.jsonl': b'm', 'features.txt': b'f', 'toolchain.txt': b't',
                 'native-evidence/linkage.txt': b'l', 'native-evidence/build-stderr.txt': b's',
                 'expanded-sources.json': b'{}'}
        receipt = {'source_digest': 's', 'binary_sha256': 'b', 'target': 't',
                   'build_evidence_digest': admission.build_evidence_digest(files)}
        review = dict(receipt, evidence={})
        files['toolchain.txt'] = b'replaced'
        receipt['build_evidence_digest'] = admission.build_evidence_digest(files)
        with self.assertRaises(ValueError):
            admission.review_problems(review, files, receipt)

    def test_review_finalize_rejects_invalid_receipt(self):
        b = admission.bundle
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = {'candidate.tar.gz': b'candidate', 'review.json': b.encoded({})}
            receipt = {'target': admission.TARGETS[0], 'tag': 'v1'}
            admission.write_receipt(root / 'input', files, receipt)
            (root / 'review.json').write_bytes(b.encoded({}))
            with self.assertRaises(ValueError):
                admission.finalize_review(SimpleNamespace(receipt=root / 'input', review=root / 'review.json', output=root / 'output'))

    def test_source_identity_binds_proof_modes_and_review_bytes(self):
        payload = {'sources/v1/project/a': b'a',
                   'sources/v1/project/.github/release/license/reviews/review.json': b'one',
                   'GIT-SOURCES.json': b'proof-one',
                   'SOURCE-MODES.json': admission.bundle.encoded({'sources/v1/project/a': '100644'})}
        identity = admission.source_digest(payload)
        payload['sources/v1/project/.github/release/license/reviews/review.json'] = b'two'
        self.assertNotEqual(identity, admission.source_digest(payload))
        payload['sources/v1/project/.github/release/license/reviews/review.json'] = b'one'
        payload['GIT-SOURCES.json'] = b'proof-two'
        self.assertNotEqual(identity, admission.source_digest(payload))
        payload['GIT-SOURCES.json'] = b'proof-one'
        payload['sources/v1/project/a'] = b'b'
        self.assertNotEqual(identity, admission.source_digest(payload))
        payload['sources/v1/project/a'] = b'a'
        payload['SOURCE-MODES.json'] = admission.bundle.encoded({'sources/v1/project/a': '100755'})
        self.assertNotEqual(identity, admission.source_digest(payload))

    def test_isolated_cli_import(self):
        result = subprocess.run([sys.executable, '-I', str(Path(admission.__file__).resolve()),
                                 'verify-release', '--artifacts', str(Path(__file__).parent), '--tag', 'v1'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('admission failed:', result.stderr)
        self.assertNotIn('ModuleNotFoundError', result.stderr)

    def test_missing_target_receipts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(ValueError):
                admission.assemble(SimpleNamespace(evidence=root, artifacts=root, tag='v1', output=root / 'out'))

    def test_missing_binary(self):
        with tempfile.TemporaryDirectory() as temp:
            receipts = {target: {'binary_sha256': '0' * 64} for target in admission.TARGETS}
            with self.assertRaises((ValueError, OSError)):
                admission.artifacts_check(Path(temp), 'v1', receipts, False, {})

    def test_missing_receipt(self):
        with self.assertRaises((ValueError, KeyError)):
            admission.check_receipt({}, admission.TARGETS[0], 'v1')

    def test_checksum_exact(self):
        data = b'archive'
        name = 'archive.tar.gz'
        digest = admission.bundle.digest(data)
        admission.checksum(data, name, (digest + '  ' + name + '\n').encode())
        admission.checksum(data, 'archive.zip', (digest + ' *archive.zip').encode())
        for invalid in (digest, digest + ' *' + name, digest + ' *' + name + '\n', digest + '  other\n', digest + '  ' + name + '\nextra',
                        digest.upper() + '  ' + name + '\n'):
            with self.assertRaises(ValueError):
                admission.checksum(data, name, invalid.encode())


if __name__ == '__main__':
    unittest.main()
