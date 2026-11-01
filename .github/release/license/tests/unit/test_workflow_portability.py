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


def selected_bash(value):
    if not value or not Path(value).is_absolute() or not Path(value).is_file():
        raise ValueError('LICENSE_TEST_BASH должен указывать на абсолютный путь к файлу Bash')
    return value


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

    def check_build_command(self, text):
        script = extract(text, 'Build release and collect evidence')
        lines = [line for line in script.splitlines() if re.match(r'^\s*cargo\s+build\b', line)]
        self.assertEqual(len(lines), 1)
        self.assertNotRegex(lines[0], r'(?:^|\s)(?:-v+|--verbose)(?:\s|$)')
        self.assertEqual(lines[0], 'cargo build --locked --offline --release -p socks5-proxy --target "$TARGET" '
                         '--message-format=json-render-diagnostics > target/license-logs/build-messages.jsonl '
                         '2> target/license-logs/build-stderr.txt')

    def test_build_command_and_verbose_mutations(self):
        self.check_build_command(self.text)
        for flag in ('-v', '-vv', '--verbose'):
            mutated = self.text.replace('cargo build --locked', 'cargo build ' + flag + ' --locked', 1)
            self.assertNotEqual(mutated, self.text)
            with self.subTest(flag=flag), self.assertRaises(AssertionError):
                self.check_build_command(mutated)

    def test_bash_path_contract(self):
        for value in (None, '', 'bash', 'relative/bash', str(WORKFLOW / 'missing-bash')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                selected_bash(value)

    def test_real_scripts_with_transport(self):
        bash = selected_bash(os.environ.get('LICENSE_TEST_BASH'))
        smoke = subprocess.run([bash, '--noprofile', '--norc', '-c',
                                'p="$BASH"; if command -v cygpath >/dev/null 2>&1; '
                                'then p="$(cygpath -w "$p")"; fi; '
                                'printf "LICENSE_BASH_ID\\n%s\\n" "$p"'],
                               capture_output=True)
        diagnostic = f'exe={bash!r} stdout={smoke.stdout[:4096]!r} stderr={smoke.stderr[:4096]!r}'
        self.assertEqual(smoke.returncode, 0, diagnostic)
        lines = smoke.stdout.splitlines()
        self.assertEqual(len(lines), 2, diagnostic)
        self.assertEqual(lines[0], b'LICENSE_BASH_ID', diagnostic)
        self.assertTrue(os.path.samefile(bash, os.fsdecode(lines[1])), diagnostic)
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
                    result = subprocess.run([bash], input=script,
                                            cwd=data, env=env, capture_output=True)
                    logged = None
                    if log.is_file():
                        with log.open('rb') as stream:
                            logged = stream.read(4096)
                    diagnostic = (f'exe={bash!r} stdout={result.stdout[:4096]!r} '
                                  f'stderr={result.stderr[:4096]!r} argv={logged!r}')
                    self.assertEqual(result.returncode, 0, diagnostic)
                    self.assertTrue(log.is_file(), diagnostic)
                    calls = [json.loads(line) for line in log.read_text(encoding='utf-8').splitlines()]
                    self.assertEqual(len(calls), 3 if name == FETCH else 1, diagnostic)
                    self.assertTrue(all('' not in call for call in calls), diagnostic)
                    call = calls[1] if name == FETCH else calls[0]
                    self.assertEqual(call[:4], ['python', '-I',
                        '.github/release/license/bundle.py' if name == FETCH else '.github/release/license/admission.py',
                        'prepare' if name == FETCH else 'record'], diagnostic)
                    flag = '--reviews' if name == FETCH else '--review'
                    expected = '.github/release/license/reviews/' + ('components.json' if name == FETCH else target + '.json')
                    self.assertEqual(call.count(flag), int(present), diagnostic)
                    if present:
                        self.assertEqual(call[-2:], [flag, expected], diagnostic)
                    self.assertNotIn('--review' if name == FETCH else '--reviews', call, diagnostic)


if __name__ == '__main__':
    unittest.main(verbosity=2)
