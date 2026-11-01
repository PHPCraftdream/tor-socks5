"""Локальная сводка сохранённых результатов; исходные архивы не открываются."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import sys

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('trusted_summary_safe', HERE.parent / 'analyze-safe.py')
safe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(safe)
ROOT = HERE.parents[4]
SOURCE = ROOT / 'target' / 'materials-20261030-b'
PINS = {'report.json': (6690273, '577b4c83baad5f7e9887064284769763fcfa556e928d3eff3c605a60f6a1bf94'), 'materials.json': (81214730, 'fba5864fe228e29767782468035437d8dd972981cd476275e4a938ad0bf1eb08')}


def load(name):
    path = SOURCE / name
    size, digest = PINS[name]
    with safe.evidence_file(path) as f:
        safe.checked(f, size, digest)
        try:
            raw = f.read(size + 1)
            if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError('Вход не совпадает с закреплёнными bytes: ' + name)
        finally:
            safe.checked(f, size, digest)
    depth = 0
    quoted = escaped = False
    for c in raw:
        if quoted:
            if escaped:
                escaped = False
            elif c == 92:
                escaped = True
            elif c == 34:
                quoted = False
        elif c == 34:
            quoted = True
        elif c in (91, 123):
            depth += 1
            if depth > 64:
                raise ValueError('Глубина JSON превышена')
        elif c in (93, 125):
            depth -= 1
            if depth < 0:
                raise ValueError('Неверная вложенность JSON')
    if quoted or depth:
        raise ValueError('Незавершённый JSON')
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError('Повтор ключа JSON')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Недопустимая константа')))


def main():
    parser = argparse.ArgumentParser(description='Ограниченная сводка сохранённых результатов')
    parser.add_argument('--target-root', default='target')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    out = safe.output_dir(args)
    report = load('report.json')
    data = load('materials.json')
    components = {c['archive_path']: {'name': c['name'], 'version': c['version'], 'manifest': c['manifest'], 'review_flags': c['review_flags'], 'materials': []} for c in report['components']}
    histogram = {}
    for c in components.values():
        expr = c['manifest']['license']
        histogram[str(expr)] = histogram.get(str(expr), 0) + 1
    for item in data['materials']:
        raw = base64.b64decode(item['bytes_base64'], validate=True)
        if len(raw) != item['retained_size'] or hashlib.sha256(raw).hexdigest() != item['retained_sha256']:
            raise ValueError('Повреждены сохранённые bytes')
        try:
            text = raw.decode('utf-8', 'strict')
            encoding = 'utf-8'
        except UnicodeDecodeError:
            text = ''
            encoding = 'unknown'
        hits = []
        for number, line in enumerate(text.splitlines(), 1):
            if re.search(r'CDLA|CCADB|community data license agreement|common ca database', line, re.I):
                hits.append({'line': number, 'text': line[:500]})
                if len(hits) > 100:
                    raise ValueError('Слишком много совпадений в материале')
        meta = {k: item[k] for k in ('path', 'size', 'sha256', 'classification', 'retention', 'explicit_license_file')}
        meta.update({'encoding': encoding, 'cdla_ccadb_lines': hits, 'nested_vendor_native': bool(re.search(r'(^|/)(vendor|vendored|native|third.party|deps|openssl|sqlite|zstd|lzma|ring)(/|[-_])', item['path'], re.I))})
        components[item['archive']]['materials'].append(meta)
    result = {'input_pins': PINS, 'status': report['status'], 'coverage': report['coverage'], 'copy_counts': {k: len(v) if isinstance(v, list) else v for k, v in report['copies'].items()}, 'license_histogram': histogram, 'components': components, 'blockers': report['blockers']}
    encoded = (json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    if len(encoded) > 100_000_000:
        raise ValueError('Сводка слишком велика')
    with (out / 'summary.json').open('xb') as f:
        f.write(encoded)
    print('summary.json', len(encoded), hashlib.sha256(encoded).hexdigest())


if __name__ == '__main__':
    sys.exit(main())
