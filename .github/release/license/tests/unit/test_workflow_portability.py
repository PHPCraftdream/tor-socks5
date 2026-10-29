#!/usr/bin/env python3
"""Проверка переносимости необязательных аргументов реальных шагов workflow."""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest


WORKFLOW = Path(__file__).resolve().parents[4] / 'workflows' / 'license-bundle.yml'
FETCH = 'Fetch and capture source before build'
RECORD = 'Snapshot receipt and compare sources after build'


def extract(text, name):
    jobs = re.split(r'(?m)^  ([\w-]+):\s*$', text.split('jobs:\n', 1)[1])
    build = dict(zip(jobs[1::2], jobs[2::2]))['build']
    steps = re.split(r'(?m)^      - ', build)[1:]
    matches = [step for step in steps if step.splitlines()[0] == 'name: ' + name]
    if len(matches) != 1:
        raise AssertionError(name)
    match = re.search(r'(?m)^        run: \|\s*\n((?:          .*\n)+)', matches[0])
    if not match or '        shell: bash\n' not in matches[0]:
        raise AssertionError(name)
    return '\n'.join(line[10:] for line in match.group(1).splitlines()) + '\n'


class WorkflowPortability(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding='utf-8')

    def check_pattern(self, text):
        for name, flag, gate, append, command in (
            (FETCH, '--reviews', 'if [ -f .github/release/license/reviews/components.json ]; then',
             'set -- "$@" --reviews .github/release/license/reviews/components.json', 'bundle.py prepare '),
            (RECORD, '--review', 'if [ -f "$review_file" ]; then',
             'set -- "$@" --review "$review_file"', 'admission.py record '),
        ):
            script = extract(text, name)
            self.assertNotIn('${prepare_args[@]}', script)
            self.assertNotIn('${review_args[@]}', script)
            self.assertEqual(script.splitlines()[0], 'set -euo pipefail')
            self.assertEqual(script.count('set --\n'), 1)
            self.assertIn(gate + '\n  ' + append + '\nfi\n', script)
            self.assertLess(script.index('set --\n'), script.index(gate))
            lines = [line for line in script.splitlines() if command in line]
            self.assertEqual(len(lines), 1)
            self.assertTrue(lines[0].endswith(' "$@"'))
            self.assertNotIn(flag, lines[0])

    def test_pattern_and_mutations(self):
        self.check_pattern(self.text)
        for name, old in ((FETCH, '${prepare_args[@]}'), (RECORD, '${review_args[@]}')):
            script = extract(self.text, name)
            mutated = script.replace('"$@"\n', '"' + old + '"\n', 1)
            self.assertNotEqual(script, mutated)
            with self.subTest(name=name), self.assertRaises(AssertionError):
                self.check_pattern(self.text.replace(script.replace('\n', '\n          ').rstrip(),
                                                     mutated.replace('\n', '\n          ').rstrip(), 1))

    def test_real_scripts_with_transport(self):
        # Подменяются только внешние команды; проектные валидаторы не запускаются.
        for name in (FETCH, RECORD):
            for present in (False, True):
                with self.subTest(name=name, present=present), tempfile.TemporaryDirectory(prefix='bash transport ') as temp:
                    root = Path(temp)
                    data = root / 'data space'
                    tools = root / 'tools space'
                    data.mkdir()
                    tools.mkdir()
                    log = root / 'argv log.jsonl'
                    fake = tools / 'transport.py'
                    fake.write_bytes(('import json, os, sys\n'
                                      'with open(os.environ["ARGV_LOG"], "a", encoding="utf-8") as f:\n'
                                      '    f.write(json.dumps(sys.argv[1:]) + "\\n")\n').encode('utf-8'))
                    for tool in ('cargo', 'python'):
                        wrapper = tools / tool
                        intended = ('#!/bin/bash\n'
                                    'exe="$FAKE_PYTHON"\n'
                                    'if command -v cygpath >/dev/null 2>&1; then exe=$(cygpath -u "$exe"); fi\n'
                                    'exec "$exe" -I "$FAKE_SCRIPT" ' + shlex.quote(tool) + ' "$@"\n').encode('utf-8')
                        wrapper.write_bytes(intended)
                        actual = wrapper.read_bytes()
                        self.assertTrue(actual.startswith(b'#!/bin/bash\n'))
                        self.assertNotIn(b'\r', actual)
                        self.assertEqual(actual, intended)
                        wrapper.chmod(0o755)
                    target = 'target with spaces'
                    review = data / '.github/release/license/reviews' / (
                        'components.json' if name == FETCH else target + '.json')
                    if present:
                        review.parent.mkdir(parents=True)
                        review.write_text('{}', encoding='utf-8')
                    env = os.environ.copy()
                    env.update(PATH=str(tools) + os.pathsep + env.get('PATH', ''),
                               FAKE_PYTHON=sys.executable, FAKE_SCRIPT=str(fake), ARGV_LOG=str(log),
                               CARGO_HOME='cargo home', CARGO_TARGET_DIR='build directory',
                               GITHUB_WORKSPACE='workspace space', TAG='tag', GITHUB_SHA='sha',
                               TARGET=target, RUNNER_OS='Linux')
                    script = extract(self.text, name).encode('utf-8')
                    self.assertNotIn(b'\r', script)
                    result = subprocess.run(['bash'], input=script,
                                            cwd=data, env=env, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    calls = [json.loads(line) for line in log.read_text(encoding='utf-8').splitlines()]
                    self.assertEqual(len(calls), 3 if name == FETCH else 1)
                    self.assertTrue(all('' not in call for call in calls))
                    call = calls[1] if name == FETCH else calls[0]
                    self.assertEqual(call[:4], ['python', '-I',
                        '.github/release/license/bundle.py' if name == FETCH else '.github/release/license/admission.py',
                        'prepare' if name == FETCH else 'record'])
                    flag = '--reviews' if name == FETCH else '--review'
                    expected = '.github/release/license/reviews/' + ('components.json' if name == FETCH else target + '.json')
                    self.assertEqual(call.count(flag), int(present))
                    if present:
                        self.assertEqual(call[-2:], [flag, expected])
                    self.assertNotIn('--review' if name == FETCH else '--reviews', call)


if __name__ == '__main__':
    unittest.main(verbosity=2)
