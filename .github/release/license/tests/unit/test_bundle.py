"""Bundle boundary tests; run explicitly when permitted."""
import importlib.util
import io
import subprocess
from pathlib import Path
import tarfile
import tempfile
import unittest
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_source_inventory import payload_proofs

spec = importlib.util.spec_from_file_location('release_bundle', Path(__file__).resolve().parents[2] / 'bundle.py')
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'bundle.tar.gz'
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for name, data in [('demo-1/Cargo.toml', b'[package]\nname="demo"\nversion="1"\nlicense="MIT"\n'),
                               ('demo-1/LICENSE', b'MIT license')]:
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
        crate = buf.getvalue()
        base = 'sources/v1/'
        self.payload = {base + 'project/Cargo.lock': ('[[package]]\nname="demo"\nversion="1"\nsource="' + bundle.REGISTRY + '"\nchecksum="' + bundle.digest(crate) + '"\n').encode(),
                        base + 'project/LICENSE-MIT': b'MIT', base + 'project/LICENSE-APACHE': b'Apache',
                        base + 'project/Cargo.toml': b'[workspace.package]\nlicense="MIT"\n[patch.crates-io]\npatch={path="vendor/patch"}\n',
                        base + 'project/vendor/README.md': b'vendor documentation',
                        base + 'project/vendor/extra/file': b'extra',
                        base + 'project/vendor/patch/Cargo.toml': b'[package]\nlicense="MIT"\n',
                        base + 'project/vendor/patch/lib.rs': b'patch',
                        base + 'project/vendor/patch/NOTICE': b'Copyright synthetic patch authors; attribution for Cargo.toml and lib.rs',
                        base + 'sdk/Cargo.toml': b'[workspace.package]\nlicense="MIT"\n',
                        base + 'sdk/LICENSE': b'MIT',
                        base + 'sdk/crates/resocks5-net/lib.rs': b'net',
                        base + 'registry/demo-1.crate': crate}
        self.components, self.inventory, copies = bundle.reconstruct(self.payload, 'v1')
        self.payload.update(copies)
        reviews = {'components': {}}
        for component in self.components:
            paths = component['candidates']
            notices = [{'path': path, 'sha256': bundle.digest(self.payload[path])} for path in paths]
            source_path = component['source_paths'][0]
            source = {'path': source_path, 'sha256': bundle.digest(self.payload[source_path])}
            reviews['components'][component['id']] = {'source_digest': component['source_digest'],
                'selected_license': 'MIT', 'rationale': 'Reviewed provenance and license',
                'obligations': 'Retain license notices', 'notices': notices, 'evidence': [source],
                'retained_notices': notices, 'corresponding_source': [source],
                'attribution_review': [{'path': p, 'sha256': bundle.digest(self.payload[p]),
                                        'rationale': 'Reviewed file attribution'} for p in component['source_paths']]}
        notices, source_info, _ = bundle.canonical_reports(self.payload, self.components, 'v1')
        modes = {p: '100644' for c in self.components if not c['id'].startswith('registry:') for p in c['source_paths']}
        modes[base + 'sdk/crates/resocks5-net/lib.rs'] = '100755'
        self.proofs = payload_proofs(self.payload, 'v1', modes)
        self.payload['GIT-SOURCES.json'] = bundle.encoded(self.proofs)
        self.payload.update({'SOURCE-MODES.json': bundle.encoded(modes), 'REVIEWS.json': bundle.encoded(reviews), 'BLOCKERS.json': bundle.encoded([]),
                             'NOTICES.txt': notices, 'SOURCE-INFO.txt': source_info})

    def archive(self, payload, components=None, inventory=None):
        data = dict(payload)
        manifest = {'schema': 1, 'tag': 'v1', 'sdk_commit': self.proofs['sdk']['commit'],
                    'components': self.components if components is None else components,
                    'packages': self.inventory if inventory is None else inventory,
                    'files': [{'path': p, 'size': len(d), 'sha256': bundle.digest(d)} for p, d in sorted(data.items())]}
        data['MANIFEST.json'] = bundle.encoded(manifest)
        bundle.pack(data, self.path)

    def test_genuine_crate(self):
        self.archive(self.payload)
        self.assertEqual([], bundle.verify_format(self.path, self.proofs['project']['commit'], self.proofs['sdk']['commit']))
        self.assertIn('vendor:patch', [c['id'] for c in self.components])
        project = next(c for c in self.components if c['id'] == 'project')
        self.assertIn('sources/v1/project/vendor/README.md', project['source_paths'])
        self.assertIn('sources/v1/project/vendor/extra/file', project['source_paths'])

    def test_strict_verify_rejects_synthetic_sdk(self):
        self.archive(self.payload)
        with self.assertRaisesRegex(ValueError, 'unsupported manifest'):
            bundle.verify(self.path, self.proofs['project']['commit'])

    def test_cli_rejects_synthetic_sdk(self):
        self.archive(self.payload)
        result = subprocess.run([sys.executable, '-I', str(Path(bundle.__file__).resolve()),
                                 'verify', '--bundle', str(self.path),
                                 '--project-commit', self.proofs['project']['commit']],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unsupported manifest', result.stderr)

    def test_wrong_explicit_anchors_rejected(self):
        self.archive(self.payload)
        with self.assertRaisesRegex(ValueError, 'source commit mismatch: project'):
            bundle.verify_format(self.path, '0' * 40, self.proofs['sdk']['commit'])
        with self.assertRaisesRegex(ValueError, 'unsupported manifest'):
            bundle.verify_format(self.path, self.proofs['project']['commit'], '0' * 40)

    def test_supported_and_blocked_declarations(self):
        reviews = bundle.strict_json(self.payload['REVIEWS.json'])
        component = next(c for c in self.components if c['id'] == 'registry:demo-1')
        record = reviews['components'][component['id']]
        for license_name in sorted(bundle.SUPPORTED):
            component['declared_license'] = license_name
            record['selected_license'] = license_name
            self.assertEqual([], bundle.blockers(self.components, reviews, self.payload))
        component['declared_license'] = 'MIT OR Apache-2.0 OR BSD-3-Clause'
        record['selected_license'] = 'BSD-3-Clause'
        self.assertEqual([], bundle.blockers(self.components, reviews, self.payload))
        for declaration in ('MIT OR MPL-2.0', 'CDLA-Permissive-2.0', 'MIT AND Apache-2.0'):
            component['declared_license'] = declaration
            record['selected_license'] = 'MIT'
            self.assertTrue(any('unsupported license' in p for p in bundle.blockers(self.components, reviews, self.payload)))

    def test_vendor_requires_per_file_attribution(self):
        reviews = bundle.strict_json(self.payload['REVIEWS.json'])
        reviews['components']['vendor:patch']['attribution_review'].pop()
        self.assertTrue(any('per-file attribution' in p for p in bundle.blockers(self.components, reviews, self.payload)))

    def test_missing_vendor_notice_blocks_and_still_has_heading(self):
        data = dict(self.payload)
        del data['sources/v1/project/vendor/patch/NOTICE']
        components, _, _ = bundle.reconstruct(data, 'v1')
        reviews = bundle.strict_json(self.payload['REVIEWS.json'])
        self.assertIn('vendor:patch: missing attributable notice text', bundle.blockers(components, reviews, data))
        notices, _, _ = bundle.canonical_reports(data, components, 'v1')
        self.assertIn(b'=== vendor:patch ===', notices)

    def test_member_limit_override(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            entry = tarfile.TarInfo('candidate.tar.gz')
            entry.size = 5
            tar.addfile(entry, io.BytesIO(b'12345'))
        with self.assertRaisesRegex(ValueError, 'tar content exceeds limit'):
            bundle.read_tar(buf.getvalue(), max_member=4)
        self.assertEqual(b'12345', bundle.read_tar(buf.getvalue(), max_member=5)['candidate.tar.gz'])

    def test_custom_license_file(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for name, data in [('demo-1/Cargo.toml', b'[package]\nname="demo"\nversion="1"\nlicense="MIT"\nlicense-file="terms.txt"\n'), ('demo-1/terms.txt', b'terms')]:
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
        data = dict(self.payload)
        crate = buf.getvalue()
        data['sources/v1/registry/demo-1.crate'] = crate
        data['sources/v1/project/Cargo.lock'] = ('[[package]]\nname="demo"\nversion="1"\nsource="' + bundle.REGISTRY + '"\nchecksum="' + bundle.digest(crate) + '"\n').encode()
        components, _, copies = bundle.reconstruct(data, 'v1')
        self.assertIn('sources/v1/candidates/demo-1/terms.txt', copies)
        self.assertIn('sources/v1/candidates/demo-1/terms.txt', next(c for c in components if c['id'] == 'registry:demo-1')['candidates'])

    def test_mode_mismatch(self):
        self.archive(self.payload)
        members = bundle.read_tar(self.path.read_bytes())
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            modes = bundle.strict_json(members['SOURCE-MODES.json'])
            for name, content in sorted(members.items()):
                entry = tarfile.TarInfo(name)
                entry.size = len(content)
                entry.mode = int(modes.get(name, '100644')[-3:], 8)
                if name == 'sources/v1/sdk/crates/resocks5-net/lib.rs':
                    entry.mode = 0o644
                tar.addfile(entry, io.BytesIO(content))
        self.path.write_bytes(buf.getvalue())
        with self.assertRaisesRegex(ValueError, 'source mode mismatch'):
            bundle.verify_format(self.path, self.proofs['project']['commit'], self.proofs['sdk']['commit'])

    def test_empty_notices_rehashed_manifest(self):
        data = dict(self.payload)
        data['NOTICES.txt'] = b''
        self.archive(data)
        with self.assertRaises(ValueError):
            bundle.verify_format(self.path, self.proofs['project']['commit'], self.proofs['sdk']['commit'])

    def test_missing_patch_manifest(self):
        data = dict(self.payload)
        del data['sources/v1/project/vendor/patch/Cargo.toml']
        with self.assertRaises(ValueError):
            bundle.reconstruct(data, 'v1')

    def test_invalid_review(self):
        reviews = bundle.strict_json(self.payload['REVIEWS.json'])
        record = reviews['components']['vendor:patch']
        record['selected_license'] = 'GPL-3.0'
        record['obligations'] = ''
        manifest = 'sources/v1/project/vendor/patch/Cargo.toml'
        record['notices'] = [{'path': manifest, 'sha256': bundle.digest(self.payload[manifest])}]
        problems = bundle.blockers(self.components, reviews, self.payload)
        self.assertTrue(any('unsupported license' in p for p in problems))
        self.assertTrue(any('missing obligations' in p for p in problems))
        self.assertTrue(any('invalid notices' in p for p in problems))

    def test_missing_lock_component(self):
        data = dict(self.payload)
        del data['sources/v1/registry/demo-1.crate']
        self.archive(data, [c for c in self.components if c['id'] != 'registry:demo-1'])
        with self.assertRaises((ValueError, KeyError)):
            bundle.verify_format(self.path, self.proofs['project']['commit'], self.proofs['sdk']['commit'])

    def test_manifest_omission(self):
        self.archive(self.payload, self.components[:-1])
        with self.assertRaises(ValueError):
            bundle.verify_format(self.path, self.proofs['project']['commit'], self.proofs['sdk']['commit'])

    def test_candidate_tamper_rehashed_manifest(self):
        data = dict(self.payload)
        data['sources/v1/candidates/demo-1/LICENSE'] = b'forged'
        self.archive(data)
        with self.assertRaises(ValueError):
            bundle.verify_format(self.path, self.proofs['project']['commit'], self.proofs['sdk']['commit'])

    def test_duplicate_json_keys(self):
        with self.assertRaises(ValueError):
            bundle.strict_json('{"x":1,"x":2}')

    def test_unsafe_tar(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            entry = tarfile.TarInfo('../escape')
            entry.size = 1
            tar.addfile(entry, io.BytesIO(b'x'))
        with self.assertRaises(ValueError):
            bundle.read_tar(buf.getvalue())


if __name__ == '__main__':
    unittest.main()
