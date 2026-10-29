"""Synthetic Git object format tests; execute only in CI when permitted."""
import ast
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True

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


class SourceInventoryRegressionTests(unittest.TestCase):
    def test_cli_help_does_not_write_bytecode(self):
        tooling = Path(__file__).resolve().parents[2]
        for cli in ('bundle.py', 'admission.py', 'provenance.py'):
            with self.subTest(cli=cli), tempfile.TemporaryDirectory() as temp:
                copied = Path(temp) / 'tooling'
                copied.mkdir()
                for path in tooling.glob('*.py'):
                    shutil.copyfile(path, copied / path.name)

                def contents():
                    return {p.relative_to(copied).as_posix():
                            None if p.is_dir() else p.read_bytes() for p in copied.rglob('*')}

                before = contents()
                result = subprocess.run([sys.executable, '-I', str(copied / cli), '--help'],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                after = contents()
                self.assertEqual(before, after)
                self.assertFalse(any('__pycache__' in p.parts or p.suffix == '.pyc'
                                     for p in copied.rglob('*')))

    def test_integration_loaders_do_not_write_bytecode(self):
        tooling = Path(__file__).resolve().parents[2]
        for entry in ('test_lifecycle.py', 'test_release_chain.py'):
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as temp:
                copied = Path(temp) / 'tooling'
                copied.mkdir()
                for path in tooling.glob('*.py'):
                    shutil.copyfile(path, copied / path.name)
                for relative in ('tests/integration/test_lifecycle.py',
                                 'tests/integration/test_release_chain.py',
                                 'tests/integration/chain_fixture.py',
                                 'tests/unit/test_source_inventory.py'):
                    destination = copied / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(tooling / relative, destination)
                target = copied / 'tests' / 'integration' / entry

                # Загрузчик может записать pyc после выполнения модуля, поэтому
                # флаг admission маскирует поздний флаг вызывающего файла.
                statements = ast.parse(target.read_bytes()).body
                flag = next((i for i, node in enumerate(statements)
                             if isinstance(node, ast.Assign) and len(node.targets) == 1
                             and isinstance(node.targets[0], ast.Attribute)
                             and isinstance(node.targets[0].value, ast.Name)
                             and node.targets[0].value.id == 'sys'
                             and node.targets[0].attr == 'dont_write_bytecode'
                             and isinstance(node.value, ast.Constant) and node.value.value is True), None)
                self.assertIsNotNone(flag)
                local_load = next(i for i, node in enumerate(statements)
                                  if (isinstance(node, ast.Import) and any(
                                      alias.name == 'chain_fixture' for alias in node.names))
                                  or (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                                      and isinstance(node.value.func, ast.Attribute)
                                      and node.value.func.attr == 'spec_from_file_location'))
                self.assertLess(flag, local_load)

                def contents():
                    return {p.relative_to(copied).as_posix():
                            None if p.is_dir() else p.read_bytes() for p in copied.rglob('*')}

                if entry == 'test_lifecycle.py':
                    command = [sys.executable, '-I', str(target), '--help']
                else:
                    runner = Path(temp) / 'runner.py'
                    runner.write_text('import runpy, sys\nrunpy.run_path(sys.argv[1], run_name="not_main")\n',
                                      encoding='utf-8')
                    command = [sys.executable, '-I', str(runner), str(target)]
                before = contents()
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(before, contents())
                self.assertFalse(any('__pycache__' in p.parts or p.suffix == '.pyc'
                                     for p in copied.rglob('*')))

    def test_untracked_inputs_are_rejected_with_escaped_checkout_and_paths(self):
        synthetic = proof({})
        raw = base64.b64decode(synthetic['commit_object'])
        paths = [b'__pycache__/source_inventory.pyc', b'other\ninput', b'odd\xff']

        def fake_git(root, *args):
            if args == ('rev-parse', '--verify', 'HEAD^{commit}'):
                return synthetic['commit'].encode() + b'\n'
            if args == ('cat-file', 'commit', synthetic['commit']):
                return raw
            if args == ('ls-files', '--stage', '-z'):
                return b''
            if args == ('ls-files', '--others', '--exclude-standard', '-z'):
                return b'\0'.join(case) + b'\0'
            self.fail('unexpected Git call: ' + repr(args))

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'arbitrary-checkout'
            root.mkdir()
            for case in [[path] for path in paths] + [paths]:
                with self.subTest(paths=case):
                    with mock.patch.object(sources, 'git', side_effect=fake_git):
                        with self.assertRaises(ValueError) as caught:
                            sources.snapshot_git(root, checkout='sdk')
                    message = str(caught.exception)
                    self.assertIn('untracked source inputs', message)
                    self.assertIn('"sdk" checkout "arbitrary-checkout"', message)
                    self.assertIn(json.dumps([p.decode('utf-8', 'surrogateescape') for p in case]), message)
                    self.assertIn('(total: {})'.format(len(case)), message)
                    self.assertNotIn('\n', message)
                    self.assertNotIn(str(root), message)


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
