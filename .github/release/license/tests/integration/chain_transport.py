"""CI-only fake gh transport; never imports or executes gh.

LICENSE_CHAIN_CONFIG names a trusted JSON fixture with:
  routes: {exact endpoint: JSON response}, with zip responses {"file": "..."};
  state: relative JSON file containing {"releases": [...]};
  repo: owner/name for the fake release API.
Zip files and state are resolved inside the config directory. LICENSE_CHAIN_LOG
names an append-only JSONL call log. The test driver supplies the gh wrapper.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sys


def fixture_file(root, name):
    if not isinstance(name, str) or not name:
        raise ValueError('invalid fixture path')
    path = (root / name).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError('fixture file must be regular and inside config directory')
    return path


def output(value):
    sys.stdout.write(json.dumps(value, separators=(',', ':')) + '\n')


def main():
    args = sys.argv[1:]
    mutation = (args[:2] in (['release', 'upload'], ['release', 'create']) or
                (args[:1] == ['api'] and any(
                    args[i:i + 2] == ['--method', 'PATCH'] for i in range(len(args)))))
    with open(os.environ['LICENSE_CHAIN_LOG'], 'a', encoding='utf-8') as log:
        log.write(json.dumps({'argv': args, 'mutation': mutation}) + '\n')

    config_path = Path(os.environ['LICENSE_CHAIN_CONFIG']).resolve()
    config = json.loads(config_path.read_text(encoding='utf-8'))
    root = config_path.parent
    repo = config['repo']
    if not isinstance(repo, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ValueError('invalid repository')
    prefix = 'repos/' + repo + '/'
    state_path = fixture_file(root, config['state'])
    state = json.loads(state_path.read_text(encoding='utf-8'))
    releases = state['releases']
    if not isinstance(releases, list):
        raise ValueError('invalid release state')

    def save():
        state_path.write_text(json.dumps(state, separators=(',', ':')) + '\n', encoding='utf-8')

    def one(matches):
        if len(matches) != 1:
            raise ValueError('release not found or ambiguous')
        return matches[0]

    if args[:1] == ['api']:
        if len(args) == 2:
            endpoint, mode = args[1], 'get'
        elif len(args) == 4 and args[1:3] == ['--paginate', '--slurp']:
            endpoint, mode = args[3], 'pages'
        elif len(args) == 6 and args[1:3] == ['--method', 'PATCH'] and args[4:] == ['--input', '-']:
            endpoint, mode = args[3], 'patch'
        else:
            raise ValueError('unexpected api arguments')
        if not endpoint.startswith(prefix):
            raise ValueError('unexpected repository or endpoint')
        path = endpoint[len(prefix):]
        if path == 'releases?per_page=100' and mode == 'pages':
            output([releases])
            return
        match = re.fullmatch(r'releases/([1-9][0-9]*)', path)
        if match and mode in ('get', 'patch'):
            release = one([r for r in releases if type(r.get('id')) is int and r['id'] == int(match[1])])
            if mode == 'patch':
                patch = json.load(sys.stdin)
                if (not isinstance(patch, dict) or set(patch) != {'draft', 'prerelease', 'make_latest', 'body'}
                        or patch['draft'] is not False or type(patch['prerelease']) is not bool
                        or patch['make_latest'] not in ('false', 'legacy', 'true')
                        or not isinstance(patch['body'], str) or release.get('draft') is not True):
                    raise ValueError('invalid release PATCH')
                release.update(patch)
                save()
            output(release)
            return
        match = re.fullmatch(r'releases/tags/([^/?#]+)', path)
        if match and mode == 'get':
            output(one([r for r in releases if r.get('tag_name') == match[1]]))
            return
        allowed = (re.fullmatch(r'actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*', path) or
                   re.fullmatch(r'actions/workflows/[1-9][0-9]*', path) or
                   re.fullmatch(r'actions/artifacts/[1-9][0-9]*(?:/zip)?', path) or
                   re.fullmatch(r'commits/[0-9a-f]{40}', path))
        jobs = re.fullmatch(r'actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*/jobs\?per_page=100', path)
        if not ((allowed and mode == 'get') or (jobs and mode == 'pages')):
            raise ValueError('unexpected endpoint or flags: ' + endpoint)
        routes = config['routes']
        if endpoint not in routes:
            raise ValueError('unconfigured endpoint: ' + endpoint)
        response = routes[endpoint]
        if path.endswith('/zip'):
            if not isinstance(response, dict) or set(response) != {'file'}:
                raise ValueError('invalid binary route')
            with fixture_file(root, response['file']).open('rb') as stream:
                while True:
                    chunk = stream.read  # bounded streaming, no network
                    data = chunk(1024 * 1024)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
        else:
            if not isinstance(response, (dict, list)):
                raise ValueError('invalid JSON route')
            output(response)
        return

    if args[:2] == ['release', 'upload']:
        if len(args) != 7 or args[4:6] != ['--clobber', '--repo'] or args[6] != repo:
            raise ValueError('unexpected upload arguments')
        release = one([r for r in releases if r.get('tag_name') == args[2]])
        if release.get('draft') is not True:
            raise ValueError('upload requires draft release')
        path = Path(args[3])
        if not path.is_file():
            raise ValueError('upload is not a regular file')
        digest, size = hashlib.sha256(), 0
        with path.open('rb') as stream:
            for data in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(data)
                size += len(data)
        assets = release.setdefault('assets', [])
        release['assets'] = [a for a in assets if a.get('name') != path.name]
        release['assets'].append({'name': path.name, 'size': size, 'state': 'uploaded',
                                  'digest': 'sha256:' + digest.hexdigest()})
        save()
        return

    if args[:2] == ['release', 'create']:
        if len(args) not in (11, 12) or args[3:6] != ['--draft', '--verify-tag', '--repo'] or args[6] != repo:
            raise ValueError('unexpected create arguments')
        rest = args[7:]
        prerelease = rest[:1] == ['--prerelease']
        if prerelease:
            rest = rest[1:]
        if len(rest) != 4 or rest[0] != '--title' or rest[2] != '--notes':
            raise ValueError('unexpected create flags')
        if any(r.get('tag_name') == args[2] for r in releases):
            raise ValueError('release already exists')
        ids = [r['id'] for r in releases if type(r.get('id')) is int and r['id'] > 0]
        releases.append({'id': max(ids, default=0) + 1, 'tag_name': args[2], 'draft': True,
                         'prerelease': prerelease, 'assets': [], 'name': rest[1], 'body': rest[3]})
        save()
        return
    raise ValueError('unexpected gh command')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print('chain_transport: ' + str(exc), file=sys.stderr)
        sys.exit(2)
