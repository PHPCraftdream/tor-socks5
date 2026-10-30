"""Data-only orchestration; результат не является юридическим заключением."""

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import sys

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('trusted_materials_archive_data', HERE / 'archive-data.py')
archive = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive)
safe = archive.safe

BASE = 'sources/v0.0.0-license-ci/'
REGISTRY = BASE + 'registry/'
COPIES = BASE + 'candidates/'
LOCK = BASE + 'project/Cargo.lock'
LOCK_HASH = '44fec566e140a674ba45477f46ff616684d5e8ab5edcccc8d295a9e8ca975811'
PROOF_SIZE = 732801
PROOF_HASH = 'da0a383f93db18c9fd0a08947015685a575c49b834d78f00bd395ea6f8a7f259'
TARGETS = {'aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-pc-windows-msvc', 'aarch64-unknown-linux-musl', 'aarch64-unknown-linux-gnu', 'x86_64-unknown-linux-gnu', 'x86_64-unknown-linux-musl'}
CHOSEN = 'targets/aarch64-apple-darwin/candidate.tar.gz'
OUTPUT_LIMIT = 400_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def provenance():
    result = {}
    for label, path in (('audit.py', HERE / 'audit.py'), ('archive-data.py', HERE / 'archive-data.py'), ('tar-data.py', HERE / 'tar-data.py'), ('analyze-safe.py', HERE.parent / 'analyze-safe.py')):
        with safe.evidence_file(path) as f:
            data = f.read(1_000_001)
        require(len(data) <= 1_000_000, 'Размер инструмента превышен')
        result[label] = {'size': len(data), 'sha256': sha(data)}
    return result


def lock_packages(data):
    require(sha(data) == LOCK_HASH, 'Cargo.lock не совпадает с закреплённым hash')
    obj = archive.bounded_toml(data)
    packages = obj.get('package')
    require(isinstance(packages, list) and len(packages) <= 10000, 'Неверный Cargo.lock')
    expected = {}
    folded = set()
    for package in packages:
        require(isinstance(package, dict), 'Неверная запись package')
        source = package.get('source')
        if source is None:
            continue
        require(source == 'registry+https://github.com/rust-lang/crates.io-index', 'Неподдерживаемый источник Cargo.lock')
        name, version, checksum = (package.get(x) for x in ('name', 'version', 'checksum'))
        require(isinstance(name, str) and archive.IDENT.fullmatch(name) and isinstance(version, str) and archive.IDENT.fullmatch(version), 'Неверная identity')
        require(isinstance(checksum, str) and re.fullmatch(r'[0-9a-f]{64}', checksum), 'Неверная checksum')
        stem = name + '-' + version
        require(stem.casefold() not in folded, 'Повтор identity')
        folded.add(stem.casefold())
        expected[REGISTRY + stem + '.crate'] = (name, version, checksum)
    require(len(expected) == 727, 'Неверное количество registry в lock')
    return expected


def analyze(candidate, proof, report, materials):
    proof_bytes = proof.read(PROOF_SIZE + 1)
    require(len(proof_bytes) == PROOF_SIZE, 'Неверный размер proof')
    obj = safe.strict_json(proof_bytes)
    require(isinstance(obj, dict) and obj.get('status') == 'PASS_DATA_ONLY' and obj.get('blockers') == [], 'Proof не является успешным data-only результатом')
    files = obj.get('files')
    require(isinstance(files, dict), 'Отсутствует files proof')
    outer, selected = safe.candidate_outer(candidate, lambda path, size: path == CHOSEN)
    expected_nested = {'targets/' + t + '/candidate.tar.gz' for t in TARGETS}
    nested_records = {r['path']: r for r in outer['members'] if not r['directory'] and r['path'].endswith('/candidate.tar.gz')}
    require(set(nested_records) == expected_nested and all(r['sha256'] == safe.NESTED_HASH for r in nested_records.values()), 'Неверные семь nested candidate')
    require(set(selected) == {CHOSEN}, 'Отсутствует выбранный nested candidate')
    nested_bytes = selected.pop(CHOSEN)
    require(sha(nested_bytes) == safe.NESTED_HASH, 'Неверный выбранный nested candidate')
    nested, saved = safe.tar_scan(io.BytesIO(nested_bytes), 512_000_000, 10000, 100_000_000, lambda path, size: path == LOCK or path.startswith(REGISTRY) or path.startswith(COPIES))
    del nested_bytes
    actual = {r['path']: r for r in nested['members'] if not r['directory'] and (r['path'] == LOCK or r['path'].startswith(REGISTRY) or r['path'].startswith(COPIES))}
    require(set(saved) == set(actual), 'Неполное сохранение выбранных записей')
    proof_paths = {p for p in files if p == LOCK or p.startswith(REGISTRY) or p.startswith(COPIES)}
    require(set(actual) == proof_paths, 'Множество выбранных путей отличается от proof')
    for path, rec in actual.items():
        pin = files[path]
        require(isinstance(pin, dict) and type(pin.get('size')) is int and pin['size'] == rec['size'] and pin.get('sha256') == rec['sha256'] and len(saved[path]) == rec['size'] and sha(saved[path]) == rec['sha256'], 'Несовпадение с proof: ' + path)
    require(LOCK in saved, 'Cargo.lock отсутствует')
    expected = lock_packages(saved[LOCK])
    actual_archives = {p for p in actual if p.startswith(REGISTRY)}
    require(actual_archives == set(expected), 'Множество registry отличается от lock')
    require(all(actual[p]['sha256'] == values[2] for p, values in expected.items()), 'Checksum registry отличается от lock')
    copies = {p: saved[p] for p in actual if p.startswith(COPIES)}
    require(len(copies) == 1212, 'Неверное количество сохранённых копий')
    report['inputs'] = {'candidate_size': safe.CANDIDATE_SIZE, 'candidate_sha256': safe.CANDIDATE_HASH, 'proof_size': PROOF_SIZE, 'proof_sha256': PROOF_HASH, 'lock_sha256': LOCK_HASH, 'nested_sha256': safe.NESTED_HASH, 'nested_count': len(nested_records)}
    report['outer'] = {k: outer[k] for k in ('entries', 'member_bytes', 'decompressed_bytes')}
    report['nested'] = {k: nested[k] for k in ('entries', 'member_bytes', 'decompressed_bytes')}
    budget = archive.AggregateBudget()
    expected_copies = {}
    failed_stems = []
    results = []
    attempts = []
    for path, (name, version, checksum) in sorted(expected.items()):
        before = (budget.decompressed, budget.entries, budget.selected_bytes)
        try:
            result = archive.scan_crate(saved[path], name, version, checksum, budget)
        except Exception as exc:
            failed_stems.append(name + '-' + version)
            error = type(exc).__name__ + ': ' + str(exc)[:2000]
            report['blockers'].append({'archive': path, 'error': error})
            attempts.append({'archive': path, 'status': 'BLOCKED', 'error': error, 'decompressed_bytes_charged': budget.decompressed - before[0], 'entries_charged': budget.entries - before[1], 'selected_bytes_charged': budget.selected_bytes - before[2]})
            continue
        attempts.append({'archive': path, 'status': 'SCANNED', 'decompressed_bytes_charged': budget.decompressed - before[0], 'entries_charged': budget.entries - before[1], 'selected_bytes_charged': budget.selected_bytes - before[2]})
        raw = result.pop('materials')
        for item in raw:
            if item['producer_candidate'] or item['explicit_license_file']:
                require(item['retention'] == 'full', 'Не сохранены полные bytes копии')
                copy_path = COPIES + item['path']
                require(copy_path not in expected_copies, 'Повтор ожидаемой копии')
                expected_copies[copy_path] = item
        materials.extend({'archive': path, **item} for item in raw)
        result['archive_path'] = path
        results.append(result)
    missing, extra, mismatch, matches = [], [], [], []
    # Для неразобранных crate невозможно утверждать, что их сохранённые копии лишние.
    failed_prefixes = tuple(COPIES + stem + '/' for stem in failed_stems)
    for path in sorted(set(expected_copies) - set(copies)):
        missing.append(path)
    for path in sorted(set(copies) - set(expected_copies)):
        if not path.startswith(failed_prefixes):
            extra.append(path)
    for path in sorted(set(expected_copies) & set(copies)):
        item = expected_copies[path]
        original = base64.b64decode(item['bytes_base64'], validate=True)
        data = copies[path]
        size_match = len(data) == item['size']
        hash_match = sha(data) == item['sha256']
        bytes_match = data == original
        if size_match and hash_match and bytes_match:
            matches.append(path)
        else:
            mismatch.append({'path': path, 'size_match': size_match, 'sha256_match': hash_match, 'bytes_match': bytes_match})
    unknown = sorted(p for p in copies if p.startswith(failed_prefixes))
    report['components'] = results
    report['attempts'] = attempts
    report['copies'] = {'saved_count': len(copies), 'expected_from_scanned': len(expected_copies), 'match': matches, 'missing': missing, 'extra': extra, 'mismatch': mismatch, 'unresolved_failed_crate': unknown}
    report['budget'] = {'decompressed_bytes_charged': budget.decompressed, 'entries_charged': budget.entries, 'selected_bytes_charged': budget.selected_bytes}
    if missing or extra or mismatch or unknown:
        report['blockers'].append({'error': 'Несовпадение или неполная проверка сохранённых копий'})
    report['coverage'] = {'archives_expected': len(expected), 'archives_scanned': len(results), 'archives_failed': len(failed_stems)}


def serialize(obj):
    # Компактный JSON занимает одну строку; бюджет применяется до записи.
    encoder = json.JSONEncoder(ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    chunks = []
    total = 1
    for chunk in encoder.iterencode(obj):
        raw = chunk.encode('ascii')
        total += len(raw)
        require(total <= OUTPUT_LIMIT, 'Превышен бюджет сериализации')
        chunks.append(raw)
    return b''.join(chunks) + b'\n'


def main():
    parser = argparse.ArgumentParser(description='Ограниченный анализ материалов исходного дистрибутива')
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--proof', required=True)
    parser.add_argument('--target-root', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    out = safe.output_dir(args)
    report = {'status': 'BLOCKED', 'overall': 'PARTIAL', 'blockers': [], 'boundary': 'Эвристики не являются юридическим аудитом; source distribution не доказывает сборку или связывание. Нет защиты от конкурентной замены; жёсткого RSS-лимита нет.', 'provenance': {}}
    materials = []
    try:
        report['provenance'] = provenance()
        with safe.evidence_file(args.candidate) as candidate, safe.evidence_file(args.proof) as proof:
            try:
                safe.checked(candidate, safe.CANDIDATE_SIZE, safe.CANDIDATE_HASH)
                safe.checked(proof, PROOF_SIZE, PROOF_HASH)
                analyze(candidate, proof, report, materials)
            finally:
                # Обе повторные проверки выполняются независимо, даже после ошибки анализа.
                errors = []
                for f, size, digest in ((candidate, safe.CANDIDATE_SIZE, safe.CANDIDATE_HASH), (proof, PROOF_SIZE, PROOF_HASH)):
                    try:
                        safe.checked(f, size, digest)
                    except Exception as exc:
                        errors.append(type(exc).__name__ + ': ' + str(exc)[:1000])
                if errors:
                    raise ValueError('Повторная проверка входов: ' + '; '.join(errors))
        if not report['blockers']:
            report['status'] = 'DATA_COMPLETE'
    except Exception as exc:
        report['blockers'].append({'error': type(exc).__name__ + ': ' + str(exc)[:2000]})
        report['status'] = 'BLOCKED'
    try:
        report_data = serialize(report)
        material_data = serialize({'materials': materials})
        require(len(report_data) + len(material_data) <= OUTPUT_LIMIT, 'Общий бюджет JSON превышен')
        for name, data in (('report.json', report_data), ('materials.json', material_data)):
            with open(out / name, 'xb') as f:
                f.write(data)
    except Exception as exc:
        print('Ошибка записи результата: ' + type(exc).__name__ + ': ' + str(exc)[:2000], file=sys.stderr)
        return 1
    print(json.dumps({'status': report['status'], 'overall': report['overall'], 'blockers': len(report['blockers'])}, ensure_ascii=True))
    return 0 if report['status'] == 'DATA_COMPLETE' else 1


if __name__ == '__main__':
    sys.exit(main())
