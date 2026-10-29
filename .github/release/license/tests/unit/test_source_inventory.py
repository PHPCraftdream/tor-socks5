"""Synthetic Git object format tests; execute only in CI when permitted."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('source_inventory_tested', Path(__file__).resolve().parents[2] / 'source_inventory.py')
sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sources)


def proof(files):
    records = [{'path': path, 'oid': sources.object_id('blob', data), 'mode': mode,
                'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
               for path, (data, mode) in sorted(files.items())]
    tree = sources.tree_hash(records)
    raw = ('tree ' + tree + '\nauthor Test <test@example.invalid> 0 +0000\n'
           'committer Test <test@example.invalid> 0 +0000\n\nsynthetic\n').encode()
    return {'commit': sources.object_id('commit', raw), 'tree': tree,
            'commit_object': base64.b64encode(raw).decode(), 'files': records}


def payload_proofs(payload, tag, modes):
    """Construct synthetic Git proofs and return their explicit trust anchors."""
    metadata = {'schema': 1}
    for name in ('project', 'sdk'):
        prefix = 'sources/' + tag + '/' + name + '/'
        metadata[name] = proof({p[len(prefix):]: (data, modes[p])
                                for p, data in payload.items() if p.startswith(prefix)})
    return metadata


class SourceProofTests(unittest.TestCase):
    def setUp(self):
        project = {'dir/a': (b'project', '100644'), 'run': (b'run', '100755')}
        sdk = {'lib.rs': (b'sdk', '100644')}
        self.metadata = {'schema': 1, 'project': proof(project), 'sdk': proof(sdk)}
        self.payload = {'sources/v1/' + name + '/' + path: data
                        for name, files in (('project', project), ('sdk', sdk))
                        for path, (data, _) in files.items()}
        self.update_metadata()

    def update_metadata(self):
        self.payload['GIT-SOURCES.json'] = json.dumps(self.metadata).encode()

    def verify(self):
        return sources.verify_sources(self.payload, 'v1', self.metadata['project']['commit'],
                                      sdk_expected=self.metadata['sdk']['commit'])

    def test_valid_objects_and_modes(self):
        modes = self.verify()
        self.assertEqual(modes['sources/v1/project/run'], '100755')
        self.assertEqual(len(modes), 3)

    def test_sdk_bytes_and_rehashed_manifest_cannot_change_blob(self):
        self.payload['sources/v1/sdk/lib.rs'] = b'tampered'
        record = self.metadata['sdk']['files'][0]
        record['size'] = len(b'tampered')
        record['sha256'] = hashlib.sha256(b'tampered').hexdigest()
        self.payload['MANIFEST.json'] = json.dumps({'sha256': record['sha256']}).encode()
        self.update_metadata()
        with self.assertRaises(ValueError):
            self.verify()

    def test_replacing_sdk_object_does_not_match_anchor(self):
        anchor = self.metadata['sdk']['commit']
        self.payload['sources/v1/sdk/lib.rs'] = b'tampered'
        self.metadata['sdk'] = proof({'lib.rs': (b'tampered', '100644')})
        self.update_metadata()
        with self.assertRaises(ValueError):
            sources.verify_sources(self.payload, 'v1', sdk_expected=anchor)

    def test_missing_extra_and_mode_tampering(self):
        self.payload['sources/v1/project/extra'] = b'extra'
        with self.assertRaises(ValueError):
            self.verify()
        del self.payload['sources/v1/project/extra']
        self.metadata['project']['files'][0]['mode'] = '100755'
        self.update_metadata()
        with self.assertRaises(ValueError):
            self.verify()

    def test_project_anchor_and_commit_proof(self):
        with self.assertRaises(ValueError):
            sources.verify_sources(self.payload, 'v1', '0' * 40, sdk_expected=self.metadata['sdk']['commit'])
        self.metadata['project']['commit_object'] = base64.b64encode(b'tree ' + b'0' * 40 + b'\n').decode()
        self.update_metadata()
        with self.assertRaises(ValueError):
            self.verify()


if __name__ == '__main__':
    unittest.main()
