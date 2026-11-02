import hashlib
import importlib.util
import io
import pathlib
import re
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('trusted_analyze_safe', pathlib.Path(__file__).resolve().parent / 'analyze-safe.py')
safe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safe)

PACKAGES = ('colored-2.2.0', 'option-ext-0.2.0', 'priority-queue-2.7.0', 'webpki-roots-0.26.11', 'webpki-roots-1.0.7', 'xxhash-rust-0.8.18', 'async_executors-0.7.0', 'notify-8.2.0', 'ring-0.17.14', 'liblzma-sys-0.4.7', 'zstd-sys-2.0.16+zstd.1.5.7', 'openssl-src-300.6.1+3.6.3', 'libsqlite3-sys-0.37.0')
LICENSE = re.compile(r'^(license|licence|copying|copyright|notice|unlicense|lgpl|gpl|mpl|authors|legal|patents)(?:$|[._-])', re.I)
KEY = re.compile(r'copyright|redistribut|distribution|attribution|ccadb|notice|source code|public domain|warranty|permission|license|licence', re.I)
PRIVATE = re.compile(r'(?:[A-Za-z]:[\\/]|/home/|/Users/|file://|\\\\|https?://)', re.I)


def excerpts(data):
    matches = []
    for i, line in enumerate(data.decode('utf-8', 'replace').splitlines(), 1):
        if KEY.search(line) and not PRIVATE.search(line):
            matches.append({'line': i, 'text': line.strip()[:300]})
    return {'matching_lines': len(matches), 'excerpts': matches[:18]}


def main():
    args = safe.parser('Проверка выбранных первичных файлов crate').parse_args()
    out = safe.output_dir(args)
    with safe.evidence_file(args.candidate) as f:
        safe.checked(f, safe.CANDIDATE_SIZE, safe.CANDIDATE_HASH)
        outer, nested, payload = safe.candidate_nested(f)
        safe.checked(f, safe.CANDIDATE_SIZE, safe.CANDIDATE_HASH)
    paths = {m['path']: m for m in nested['members']}
    base = 'sources/v0.0.0-license-ci/registry/'
    results = {}
    for pkg in PACKAGES:
        path = base + pkg + '.crate'
        if path not in paths:
            raise ValueError('Отсутствует выбранный crate')
        _, selected = safe.tar_scan(io.BytesIO(payload), 512_000_000, 10000, 100_000_000, lambda name, size: name == path)
        data = selected[path]
        try:
            stats, _ = safe.tar_scan(io.BytesIO(data), 512_000_000, 50000, 100_000_000)
        except ValueError as exc:
            raise ValueError('Ошибка выбранного crate ' + pkg + ': ' + str(exc)) from exc
        for member in stats['members']:
            if member['path'].split('/')[0] != pkg:
                raise ValueError('Неверный префикс crate')
        def choose(name, size):
            parts = name.split('/')
            namebase = parts[-1]
            primary = bool(LICENSE.match(namebase)) or (len(parts) == 2 and namebase.lower().startswith('readme')) or (pkg.startswith('webpki-roots-') and '/src/' in name and namebase == 'lib.rs') or (pkg.startswith('libsqlite3-sys-') and namebase in ('sqlite3.c', 'sqlite3.h') and len(parts) <= 4)
            if primary and size > safe.TEXT_LIMIT:
                raise ValueError('Первичный файл слишком велик')
            return primary
        # Каждый выбранный файл читается отдельно, без накопления всех данных crate.
        primary = []
        for member in stats['members']:
            name, size = member['path'], member['size']
            if member['directory'] or not choose(name, size):
                continue
            _, contents = safe.tar_scan(io.BytesIO(data), 512_000_000, 50000, 100_000_000, lambda n, s: n == name)
            content = contents[name]
            primary.append({'path': name, 'size': size, 'sha256': member['sha256'], **excerpts(content)})
        results[pkg] = {'path': path, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'inventory': stats, 'primary_files': primary}
    notice_path = 'NOTICES.txt'
    _, notices = safe.tar_scan(io.BytesIO(payload), 512_000_000, 10000, 100_000_000, lambda n, s: n == notice_path and s <= safe.TEXT_LIMIT)
    if notice_path not in notices:
        raise ValueError('Отсутствует NOTICES')
    notice = notices[notice_path]
    patterns = {'ccadb': r'ccadb|common ca database', 'gpl': r'GNU GENERAL PUBLIC LICENSE', 'lgpl': r'GNU LESSER GENERAL PUBLIC LICENSE', 'priority_queue': r'priority-queue-2\.7\.0'}
    counts = {}
    notice_lines = notice.decode('utf-8', 'replace').splitlines()
    for key, pattern in patterns.items():
        matches = [(i, line) for i, line in enumerate(notice_lines, 1) if re.search(pattern, line, re.I)]
        counts[key] = {'count': len(matches), 'first': [{'line': i, 'text': line.strip()[:250]} for i, line in matches if not PRIVATE.search(line)][:20]}
    project_files = []
    for member in nested['members']:
        path = member['path']
        parts = path.split('/')
        if member['directory'] or len(parts) < 4 or parts[:2] != ['sources', 'v0.0.0-license-ci'] or parts[2] not in ('project', 'sdk') or not LICENSE.match(parts[-1]):
            continue
        if member['size'] > safe.TEXT_LIMIT:
            raise ValueError('Первичный файл слишком велик')
        _, contents = safe.tar_scan(io.BytesIO(payload), 512_000_000, 10000, 100_000_000, lambda n, s: n == path)
        project_files.append({'path': path, 'size': member['size'], 'sha256': member['sha256'], **excerpts(contents[path])})
    safe.write_json(out, 'primary.json', {'outer': outer, 'candidate_stats': nested, 'crates': results, 'project_sdk_license_files': project_files, 'notices': {'sha256': hashlib.sha256(notice).hexdigest(), 'matches': counts}})


if __name__ == '__main__':
    main()
