"""Basic admission boundary tests; run only when explicitly permitted."""
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

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
        invalid = (artifact, artifact + verbose + finished, artifact + b'{\n' + finished,
                   (artifact + finished)[:-1], artifact + finished + artifact,
                   artifact + b.encoded({'reason': 'build-finished', 'success': False}))
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(ValueError):
                admission.cargo(data, '/tmp/proxy')
        with self.assertRaises(ValueError):
            admission.cargo(artifact + finished, '/tmp/other')

    def test_cargo_target_path_contract(self):
        b = admission.bundle
        windows = 'x86_64-pc-windows-msvc'
        receipt = r'D:\ci\project\target\license-build\x86_64-pc-windows-msvc\release\socks5-proxy.exe'
        mixed = r'd:\CI\project/target/license-build\x86_64-pc-windows-msvc\release\SOCKS5-PROXY.EXE'
        artifact = {'reason': 'compiler-artifact', 'package_id': 'path+file:///fixture/socks5-proxy#0.2.0',
                    'target': {'name': 'socks5-proxy'}, 'executable': mixed}
        finished = b.encoded({'reason': 'build-finished', 'success': True})
        def stream(item):
            return b.encoded(item) + finished
        admission.cargo(stream(dict(artifact, executable=r'D:\ci\project/target/license-build\x86_64-pc-windows-msvc\release\socks5-proxy.exe')), receipt, windows)
        admission.cargo(stream(artifact), receipt, windows)
        for target in admission.TARGETS:
            path = receipt if target == windows else '/fixture/foreign-host/' + target + '/release/socks5-proxy'
            with self.subTest(target=target):
                admission.cargo(stream(dict(artifact, executable=path)), path, target)
        for path in (receipt.replace('project', 'other'), 'E:' + receipt[2:],
                     receipt.replace('socks5-proxy.exe', 'other.exe')):
            with self.subTest(path=path), self.assertRaises(ValueError):
                admission.cargo(stream(artifact), path, windows)
        for item in (dict(artifact, package_id='other 1.0'),
                     dict(artifact, target={'name': 'other'})):
            with self.subTest(item=item), self.assertRaises(ValueError):
                admission.cargo(stream(item), receipt, windows)
        with self.assertRaises(ValueError):
            admission.cargo(stream(artifact), receipt, admission.TARGETS[0])
        posix = '/foreign-host/target/release/socks5-proxy'
        with self.assertRaises(ValueError):
            admission.cargo(stream(dict(artifact, executable=posix.upper())), posix, admission.TARGETS[0])

    def test_cargo_rejects_unsafe_windows_paths(self):
        b = admission.bundle
        target = 'x86_64-pc-windows-msvc'
        good = r'C:\fixture\release\socks5-proxy.exe'
        artifact = {'reason': 'compiler-artifact', 'package_id': 'socks5-proxy 1.0',
                    'target': {'name': 'socks5-proxy'}, 'executable': good}
        finished = b.encoded({'reason': 'build-finished', 'success': True})
        invalid = (r'C:\fixture\..\release\socks5-proxy.exe', r'C:\fixture\.\release\socks5-proxy.exe',
                   r'fixture\release\socks5-proxy.exe', r'C:fixture\release\socks5-proxy.exe',
                   r'\\server\share\socks5-proxy.exe', r'\\?\C:\fixture\socks5-proxy.exe',
                   r'C:\fixture\release\socks5-proxy.exe:stream', r'C:\fixture\\release\socks5-proxy.exe',
                   good + '\\', r'C:\fixture.\release\socks5-proxy.exe',
                   r'C:\fixture \release\socks5-proxy.exe', r'C:\CON.txt\socks5-proxy.exe',
                   'C:\\fixture\\bad\x01name\\socks5-proxy.exe')
        for path in invalid:
            with self.subTest(path=path):
                for message_path, receipt_path in ((path, good), (good, path), (path, path)):
                    with self.assertRaises(ValueError):
                        admission.cargo(b.encoded(dict(artifact, executable=message_path)) + finished,
                                        receipt_path, target)

    def test_cargo_rejects_unsafe_posix_paths(self):
        b = admission.bundle
        target = 'x86_64-unknown-linux-gnu'
        artifact = {'reason': 'compiler-artifact', 'package_id': 'socks5-proxy 1.0',
                    'target': {'name': 'socks5-proxy'}}
        finished = b.encoded({'reason': 'build-finished', 'success': True})
        invalid = ('fixture/release/socks5-proxy', '//fixture/release/socks5-proxy',
                   '/fixture/./release/socks5-proxy', '/fixture/../release/socks5-proxy',
                   r'/fixture\release/socks5-proxy', '/fixture/bad\x01name/socks5-proxy')
        for path in invalid:
            with self.subTest(path=path), self.assertRaises(ValueError):
                admission.cargo(b.encoded(dict(artifact, executable=path)) + finished, path, target)

    def test_check_receipt_passes_target_to_cargo(self):
        b = admission.bundle
        target = 'x86_64-pc-windows-msvc'
        path = r'C:\fixture\release\socks5-proxy.exe'
        messages = (b.encoded({'reason': 'compiler-artifact', 'package_id': 'socks5-proxy 1.0',
                               'target': {'name': 'socks5-proxy'},
                               'executable': r'C:\fixture/release\socks5-proxy.exe'}) +
                    b.encoded({'reason': 'build-finished', 'success': True}))
        files = {'candidate.tar.gz': b'fixture', 'messages.jsonl': messages, 'features.txt': b'f',
                 'toolchain.txt': b't', 'native-evidence/linkage.txt': b'l',
                 'native-evidence/build-stderr.txt': b's', 'expanded-sources.json': b.encoded({}),
                 'review.json': b.encoded({})}
        receipt = {'schema': 1, 'target': target, 'tag': 'v1', 'sdk_commit': b.SDK_COMMIT,
                   'binary_path': path, 'binary_sha256': '0' * 64, 'source_digest': 'source',
                   'build_evidence_digest': admission.build_evidence_digest(files),
                   'evidence': {p: b.digest(data) for p, data in files.items()}}
        files['receipt.json'] = b.encoded(receipt)
        altered_files = dict(files, **{'messages.jsonl': messages + b'altered'})
        with self.assertRaisesRegex(ValueError, 'receipt evidence hash mismatch'):
            admission.check_receipt(altered_files, target, 'v1')
        with mock.patch.object(admission, 'candidate', return_value=({}, {'tag': 'v1'}, [])), \
             mock.patch.object(admission, 'crate_hashes', return_value={}), \
             mock.patch.object(admission, 'source_digest', return_value='source'), \
             mock.patch.object(admission, 'cargo', wraps=admission.cargo) as cargo:
            admission.check_receipt(files, target, 'v1')
            cargo.assert_called_once_with(messages, path, target)
        with self.assertRaisesRegex(ValueError, 'receipt identity mismatch'):
            admission.check_receipt(files, admission.TARGETS[0], 'v1')

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
