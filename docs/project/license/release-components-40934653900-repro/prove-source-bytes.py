import base64
import gzip
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import sys
import tomllib
import zipfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('trusted_analyze_safe', pathlib.Path(__file__).resolve().parent / 'analyze-safe.py')
safe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safe)

TARGETS = {'aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-pc-windows-msvc', 'aarch64-unknown-linux-musl', 'aarch64-unknown-linux-gnu', 'x86_64-unknown-linux-gnu', 'x86_64-unknown-linux-musl'}
ANCHORS = {
    'project': ('67f82c1e107ab24e8fd22afb9fd12134ffa7f982', '8c5be9171f2a2fa0f83dc42a60d9bb731d891d4c', ['b4a27a0cb806ce4efeef23aa94b375ce2f4222d1', 'ff8a4253b1b632a50d45d91bbe23fa86d2a7f5bc']),
    'sdk': ('e754abaa88ce4f9745b4729652789ffc57f8ba4c', '263db1bd209e4151eb4deadf532d423d0bf2b41c', ['98a8ac9004f4fc6eb5d6713037f213dded6404ba']),
}
BASE = 'sources/v0.0.0-license-ci/'
REQUIRED = ('messages.jsonl', 'features.txt', 'toolchain.txt', 'native-evidence/linkage.txt', 'native-evidence/build-stderr.txt', 'expanded-sources.json')
PRODUCERS = ('bundle.py', 'admission.py', 'source_inventory.py')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def oid(kind, data):
    return hashlib.sha1(kind.encode('ascii') + b' ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()


def scan(raw, stream_limit, entry_limit, member_limit, choose):
    names = safe.Names()
    records, selected = {}, {}
    total = headers = selected_total = 0
    pending = None
    with gzip.GzipFile(fileobj=raw, mode='rb') as gz:
        stream = safe.Budget(gz, stream_limit)
        while True:
            h = safe.exact(stream, 512)
            if h == bytes(512):
                require(safe.exact(stream, 512) == bytes(512) and pending is None, 'Неверное завершение TAR')
                while True:
                    b = stream.read(1024 * 1024)
                    if not b:
                        break
                    require(not any(b), 'Ненулевые данные после TAR')
                break
            headers += 1
            require(headers <= entry_limit * 2 + 1, 'Слишком много заголовков TAR')
            require(sum(h[:148]) + 8 * 32 + sum(h[156:]) == safe.number(h[148:156]), 'Неверная checksum TAR')
            require(h[257:263] in (b'ustar\0', b'ustar '), 'Не ustar')
            mode = safe.number(h[100:108])
            require(not mode & ~0o777 and not safe.number(h[329:337]) and not safe.number(h[337:345]), 'Недопустимый mode или device TAR')
            size, kind = safe.number(h[124:136]), h[156:157]
            require(not any(h[157:257]), 'Linkname запрещён')
            def field(value):
                return value.split(b'\0', 1)[0].decode('utf-8', 'strict')
            name, prefix = field(h[:100]), field(h[345:500])
            header_name = prefix + '/' + name if prefix else name
            if kind in (b'L', b'x'):
                require(pending is None, 'Повтор метаданных TAR')
                if kind == b'L':
                    require(1 <= size <= 513, 'Размер GNU longname')
                    if not (prefix == '' and name == '././@LongLink'):
                        safe.Names().check(header_name, False)
                    data = safe.exact(stream, size)
                    require(data[-1:] == b'\0' and b'\0' not in data[:-1], 'Неверный GNU longname')
                    pending = data[:-1].decode('utf-8', 'strict')
                    safe.Names().check(pending, False)
                else:
                    require(size <= 65536, 'Размер PAX')
                    if not (prefix == '' and name == '././@PaxHeader'):
                        safe.Names().check(header_name, False)
                    pending = safe.pax_path(safe.exact(stream, size))
                require(not any(safe.exact(stream, (-size) % 512)), 'Ненулевой padding TAR')
                continue
            require(kind in (b'0', b'\0', b'5') and size <= member_limit, 'Недопустимый тип или размер TAR')
            directory = kind == b'5'
            require(not directory or size == 0, 'Каталог с данными')
            name = pending if pending is not None else header_name
            pending = None
            names.check(name, directory)
            total += size
            require(len(records) < entry_limit and total <= stream_limit, 'Превышен бюджет TAR')
            keep = not directory and choose(name, size)
            if keep:
                selected_total += size
                require(selected_total <= safe.MEMORY_LIMIT, 'Превышен бюджет выбранных данных')
            h256 = hashlib.sha256()
            h1 = hashlib.sha1(b'blob ' + str(size).encode('ascii') + b'\0')
            chunks = []
            remaining = size
            while remaining:
                b = stream.read(min(remaining, 1024 * 1024))
                require(bool(b), 'Обрезанный член TAR')
                remaining -= len(b)
                h256.update(b)
                h1.update(b)
                if keep:
                    chunks.append(b)
            require(not any(safe.exact(stream, (-size) % 512)), 'Ненулевой padding TAR')
            records[name] = {'size': size, 'sha256': None if directory else h256.hexdigest(), 'oid': None if directory else h1.hexdigest(), 'mode': mode, 'directory': directory}
            if keep:
                selected[name] = b''.join(chunks)
        return records, selected, {'entries': len(records), 'member_bytes': total, 'decompressed_bytes': stream.count}


def tree(records):
    root = {}
    for path, record in records.items():
        node = root
        parts = path.split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            require(isinstance(node, dict), 'Коллизия Git дерева')
        require(parts[-1] not in node, 'Повтор Git пути')
        node[parts[-1]] = (record['git_mode'], record['oid'])
    def encode(node):
        entries = []
        for name, value in node.items():
            raw = name.encode('utf-8')
            if isinstance(value, dict):
                mode, digest, key = '40000', encode(value), raw + b'/'
            else:
                mode, digest = value
                key = raw
            entries.append((key, mode.encode('ascii') + b' ' + raw + b'\0' + bytes.fromhex(digest)))
        return oid('tree', b''.join(v for _, v in sorted(entries)))
    return encode(root)


def verify_git(records, texts, report):
    meta = safe.strict_json(texts['GIT-SOURCES.json'])
    require(isinstance(meta, dict) and set(meta) == {'schema', 'project', 'sdk'} and meta['schema'] == 1, 'Неверная схема Git proof')
    modes = safe.strict_json(texts['SOURCE-MODES.json'])
    require(isinstance(modes, dict), 'Неверный SOURCE-MODES')
    all_git_modes = {}
    for kind, (commit, expected_tree, parents) in ANCHORS.items():
        proof = meta[kind]
        require(isinstance(proof, dict) and set(proof) == {'commit', 'tree', 'commit_object', 'files'}, 'Неверный Git proof')
        require(proof['commit'] == commit and proof['tree'] == expected_tree, 'Несовпадение Git anchors: ' + kind)
        require(isinstance(proof['commit_object'], str) and len(proof['commit_object']) <= 1_400_000, 'Размер commit')
        raw = base64.b64decode(proof['commit_object'], validate=True)
        require(len(raw) <= 1_000_000 and oid('commit', raw) == commit, 'Несовпадение commit')
        header, sep, _ = raw.partition(b'\n\n')
        lines = header.split(b'\n')
        require(bool(sep) and lines[0] == b'tree ' + expected_tree.encode() and [x[7:].decode('ascii') for x in lines if x.startswith(b'parent ')] == parents and len([x for x in lines if x.startswith(b'tree ')]) == 1, 'Несовпадение tree/parents commit')
        prefix = BASE + kind + '/'
        actual = {}
        for path, rec in records.items():
            if path.startswith(prefix) and not rec['directory']:
                require(rec['mode'] in (0o644, 0o755), 'Неверный mode source: ' + path)
                mode = '100755' if rec['mode'] == 0o755 else '100644'
                actual[path[len(prefix):]] = {**rec, 'git_mode': mode}
                all_git_modes[path] = mode
        proof_files = proof['files']
        require(isinstance(proof_files, list) and len(proof_files) <= 100000, 'Неверный список Git')
        embedded = {}
        for item in proof_files:
            require(isinstance(item, dict) and set(item) == {'path', 'oid', 'mode', 'sha256', 'size'} and isinstance(item['path'], str), 'Неверная запись Git')
            path = item['path']
            safe.Names().check(path, False)
            require(path not in embedded, 'Повтор записи Git')
            embedded[path] = item
        require(set(actual) == set(embedded), 'Несовпадение множества Git файлов: ' + kind)
        for path, rec in actual.items():
            entry = embedded[path]
            require(entry['oid'] == rec['oid'] and entry['mode'] == rec['git_mode'] and entry['sha256'] == rec['sha256'] and type(entry['size']) is int and entry['size'] == rec['size'], 'Несовпадение metadata: ' + kind + '/' + path)
        calculated = tree(actual)
        require(calculated == expected_tree, 'Несовпадение реконструированного дерева: ' + kind)
        report['git'][kind] = {'commit': commit, 'tree': calculated, 'parents': parents, 'files': len(actual), 'metadata_match': True}
    require(all(modes.get(p) == v for p, v in all_git_modes.items()), 'SOURCE-MODES не совпадают с Git/TAR')
    source_paths = {p for p, r in records.items() if p.startswith('sources/') and not r['directory']}
    require(all(isinstance(p, str) and isinstance(m, str) and m in ('100644', '100755') for p, m in modes.items()), 'Недопустимый SOURCE-MODES')
    require(set(modes) <= source_paths, 'SOURCE-MODES содержит лишние пути')
    for p, m in modes.items():
        require(records[p]['mode'] == (0o755 if m == '100755' else 0o644), 'SOURCE-MODES отличается от TAR: ' + p)
    require(modes == all_git_modes, 'SOURCE-MODES не совпадает с множеством Git файлов')
    for p in source_paths - set(modes):
        require(records[p]['mode'] == 0o644, 'Неверный default mode TAR: ' + p)
    report['source_modes'] = {'tracked_files': len(modes), 'default_files': len(source_paths - set(modes)), 'tar_match': True}
    return modes


def registry(records, texts, report):
    data = texts[BASE + 'project/Cargo.lock']
    require(len(data) <= safe.TEXT_LIMIT, 'Cargo.lock слишком велик')
    obj = tomllib.loads(data.decode('utf-8', 'strict'))
    packages = obj.get('package')
    require(isinstance(packages, list) and len(packages) <= 10000, 'Неверный Cargo.lock')
    prefix = BASE + 'registry/'
    expected, folded = {}, set()
    for pkg in packages:
        require(isinstance(pkg, dict), 'Неверная запись Cargo.lock')
        source = pkg.get('source')
        if source is None:
            continue
        require(source == 'registry+https://github.com/rust-lang/crates.io-index', 'Неподдерживаемый источник Cargo')
        name, version, checksum = pkg.get('name'), pkg.get('version'), pkg.get('checksum')
        require(all(isinstance(x, str) and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.+\-]*', x) for x in (name, version)) and isinstance(checksum, str) and re.fullmatch(r'[0-9a-f]{64}', checksum), 'Неверная identity/checksum Cargo')
        stem = name + '-' + version
        require(stem.casefold() not in folded, 'Повтор Cargo identity')
        folded.add(stem.casefold())
        expected[prefix + stem + '.crate'] = checksum
    actual = {p: r for p, r in records.items() if p.startswith(prefix) and not r['directory']}
    require(set(expected) == set(actual), 'Множество registry archives не совпадает с lock')
    for p, checksum in expected.items():
        require(actual[p]['sha256'] == checksum, 'Checksum registry не совпадает: ' + p)
    report['registry'] = {'archives': len(actual), 'lock_sha256': sha(data), 'all_checksums_match': True, 'archive_contents_scanned': False}


def main():
    args = safe.parser('Независимая проверка source bytes').parse_args()
    out = safe.output_dir(args)
    report = {'status': 'BLOCKED', 'blockers': [], 'git': {}, 'receipts': {}, 'boundary': 'Доверенный каталог скриптов; конкурентная замена входов не защищена. Не подтверждает production origin, состав binary или юридические выводы.', 'protocol': {'source': 'bundle.py:165-166; admission.py:45-55', 'build': 'admission.py:220-226', 'git': 'source_inventory.py:25-26,110-188', 'canonical': 'UTF-8 JSON sort_keys, ensure_ascii=False, separators comma/colon, LF'}}
    try:
        with safe.evidence_file(args.candidate) as f:
            safe.checked(f, safe.CANDIDATE_SIZE, safe.CANDIDATE_HASH)
            report['outer_sha256_before'] = safe.CANDIDATE_HASH
            with zipfile.ZipFile(f) as z:
                entries = safe.zip_inventory(z, 100, 1_000_000_000, 2_000_000_000)
                archives = [x for x in entries if not x.is_dir() and x.filename.lower().endswith(('.tar.gz', '.tgz'))]
                require(len(archives) == 1, 'Ожидается один outer TAR')
                chosen = 'targets/aarch64-apple-darwin/candidate.tar.gz'
                def outer_select(name, size):
                    return name == chosen or (name.startswith('targets/') and name.endswith('/receipt.json') and size <= safe.TEXT_LIMIT)
                for x in entries:
                    if x.is_dir():
                        continue
                    if x is archives[0]:
                        with z.open(x) as raw:
                            bounded = safe.Budget(raw, x.file_size)
                            outer, selected, outer_stats = scan(bounded, 2_000_000_000, 50000, 150_000_000, outer_select)
                            while bounded.read(1024 * 1024):
                                pass
                            require(bounded.count == x.file_size, 'Неверный размер ZIP члена')
                    else:
                        safe.zip_read(z, x)
            report['outer'] = outer_stats
            expected_nested = {'targets/' + t + '/candidate.tar.gz' for t in TARGETS}
            found_nested = {p for p, r in outer.items() if not r['directory'] and p.endswith('/candidate.tar.gz')}
            require(found_nested == expected_nested and all(outer[p]['sha256'] == safe.NESTED_HASH for p in found_nested), 'Несовпадение семи nested candidate')
            require(chosen in selected, 'Нет выбранного nested candidate')
            report['nested_candidates'] = {'count': len(found_nested), 'sha256': safe.NESTED_HASH}
            nested_data = selected.pop(chosen)
            def nested_select(name, size):
                return name in {'GIT-SOURCES.json', 'SOURCE-MODES.json', BASE + 'project/Cargo.lock'} or name in {BASE + 'project/.github/release/license/' + n for n in PRODUCERS}
            nested, texts, nested_stats = scan(io.BytesIO(nested_data), 512_000_000, 10000, 100_000_000, nested_select)
            del nested_data
            report['nested'] = nested_stats
            modes = verify_git(nested, texts, report)
            registry(nested, texts, report)
            sources = {p: r for p, r in nested.items() if p.startswith('sources/') and not r['directory']}
            filtered_modes = {p: m for p, m in modes.items() if p in sources}
            mode_bytes = canonical(filtered_modes)
            descriptors = [{'path': p, 'sha256': r['sha256'], 'size': r['size']} for p, r in sources.items()]
            descriptors += [{'path': 'GIT-SOURCES.json', 'sha256': sha(texts['GIT-SOURCES.json']), 'size': len(texts['GIT-SOURCES.json'])}, {'path': 'SOURCE-MODES.json', 'sha256': sha(mode_bytes), 'size': len(mode_bytes)}]
            source_digest = sha(canonical(sorted(descriptors, key=lambda x: x['path'])))
            report['source_digest'] = {'sha256': source_digest, 'files': len(sources)}
            producer_report = {}
            project_root = pathlib.Path(__file__).resolve().parents[4]
            for name in PRODUCERS:
                path = BASE + 'project/.github/release/license/' + name
                require(path in texts, 'Нет producer в candidate: ' + name)
                with safe.evidence_file(project_root / '.github' / 'release' / 'license' / name) as local:
                    data = local.read(safe.TEXT_LIMIT + 1)
                require(len(data) <= safe.TEXT_LIMIT, 'Локальный producer слишком велик')
                producer_report[name] = {'candidate_sha256': sha(texts[path]), 'local_sha256': sha(data), 'identical': texts[path] == data}
            report['producer_text'] = producer_report
            require(all(v['identical'] for v in producer_report.values()), 'Producer в candidate отличается от прочитанного контракта; требуется текстовый анализ')
            for target in sorted(TARGETS):
                prefix = 'targets/' + target + '/'
                receipt_path = prefix + 'receipt.json'
                require(receipt_path in selected, 'Отсутствует receipt: ' + target)
                receipt = safe.strict_json(selected[receipt_path])
                require(isinstance(receipt, dict) and receipt.get('target') == target, 'Неверный target receipt: ' + target)
                files = {p[len(prefix):]: r for p, r in outer.items() if p.startswith(prefix) and not r['directory']}
                require(all(n in files for n in REQUIRED), 'Отсутствует build evidence: ' + target)
                paths = sorted(set(REQUIRED) | {p for p in files if p.startswith('native-evidence/native/')})
                digest = sha(canonical({p: files[p]['sha256'] for p in paths}))
                report['receipts'][target] = {'receipt_sha256': outer[receipt_path]['sha256'], 'source_digest': receipt.get('source_digest'), 'source_match': receipt.get('source_digest') == source_digest, 'build_evidence_digest': receipt.get('build_evidence_digest'), 'computed_build_evidence_digest': digest, 'build_match': receipt.get('build_evidence_digest') == digest, 'evidence_files': len(paths)}
                require(report['receipts'][target]['source_match'] and report['receipts'][target]['build_match'], 'Несовпадение receipt: ' + target)
            safe.checked(f, safe.CANDIDATE_SIZE, safe.CANDIDATE_HASH)
            report['outer_sha256_after'] = safe.CANDIDATE_HASH
            report['status'] = 'PASS_DATA_ONLY'
            report['files'] = {p: {'sha256': r['sha256'], 'size': r['size'], 'mode': format(r['mode'], '04o'), 'git_blob_oid': r['oid']} for p, r in sorted(sources.items())}
    except Exception as exc:
        report['blockers'].append(type(exc).__name__ + ': ' + str(exc)[:2000])
    safe.write_json(out, 'proof.json', report)
    print(json.dumps({'status': report['status'], 'blockers': report['blockers']}, ensure_ascii=True))
    return 0 if report['status'] == 'PASS_DATA_ONLY' else 1


if __name__ == '__main__':
    sys.exit(main())
