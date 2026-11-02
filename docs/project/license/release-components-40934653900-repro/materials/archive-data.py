"""Ограниченный анализ одного registry-архива; модуль не запускается сам."""

import base64
import hashlib
import importlib.util
import io
import pathlib
import re
import sys
import tomllib

sys.dont_write_bytecode = True
_HELPER = pathlib.Path(__file__).resolve().parent.parent / 'analyze-safe.py'
_SPEC = importlib.util.spec_from_file_location('trusted_analyze_safe_materials', _HELPER)
safe = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(safe)
_TAR_SPEC = importlib.util.spec_from_file_location('trusted_materials_tar_data', pathlib.Path(__file__).resolve().parent / 'tar-data.py')
tar_data = importlib.util.module_from_spec(_TAR_SPEC)
_TAR_SPEC.loader.exec_module(tar_data)

PRODUCER_CANDIDATE = re.compile(r'^(license|licence|copying|notice|copyright|unlicense|mpl|lgpl|gpl|apache|mit)(?:$|[-._])', re.I)
BROAD_NAME = re.compile(r'(license|licence|copying|notice|copyright|unlicense|authors?|contributors?|patents?|legal|(?:^|[-._])(mpl|lgpl|gpl|mit|apache)(?:$|[-._])|\bspdx\b|certificate|certdata|ccadb)', re.I)
LICENSE_TEXT = re.compile(rb'(permission is hereby granted|apache license|redistribution and use in source and binary forms|mozilla public license|gnu\s+(?:lesser\s+|library\s+)?general\s+public\s+license|spdx-license-identifier|creative commons|community data license agreement|isc license|the unlicense|unlicense\.org|permission to use, copy, modify, and/or distribute|permission to use, copy, modify, and distribute|zero-clause bsd|0bsd|unicode (?:license|data files and software)|zlib license|boost software license|this software is provided [\"\']?as.is|this is free and unencumbered software)', re.I)
NOTICE_TEXT = re.compile(rb'(copyright|all rights reserved|contributors?|authors?|attribution|notice)', re.I)
HEADER_TEXT = re.compile(rb'(copyright|spdx-license-identifier|licensed under|permission is hereby granted|redistribution and use)', re.I)
IDENT = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.+\-]*\Z')
MAX_TOML = 10_000_000
MAX_LINES = 200_000
MAX_LINE = 100_000
MAX_TOKENS = 1_000_000
MAX_NODES = 1_000_000
MAX_DEPTH = 64
MAX_SELECTED = 150_000_000
MAX_OUTPUT_BYTES = 200_000_000
PREFIX = 32_768


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _toml_guard(text):
    # Лексический предел применяется до tomllib; синтаксис проверяет tomllib.
    _require(len(text.splitlines()) <= MAX_LINES, 'Слишком много строк TOML')
    _require(all(len(line) <= MAX_LINE for line in text.splitlines()), 'Слишком длинная строка TOML')
    i = depth = tokens = 0
    length = len(text)
    while i < length:
        c = text[i]
        if c == '#':
            end = text.find('\n', i)
            i = length if end < 0 else end + 1
            continue
        if c in "\"'":
            quote = c
            triple = text[i:i + 3] == c * 3
            delimiter = c * (3 if triple else 1)
            i += len(delimiter)
            closed = False
            while i < length:
                if text.startswith(delimiter, i):
                    i += len(delimiter)
                    # TOML допускает одну или две дополнительные кавычки в конце.
                    if triple:
                        for _ in range(2):
                            if i < length and text[i] == quote:
                                i += 1
                            else:
                                break
                    closed = True
                    break
                if quote == '"' and text[i] == '\\':
                    i += 2
                else:
                    i += 1
            _require(closed, 'Незавершённая строка TOML')
            tokens += 1
            continue
        if c in '[{':
            depth += 1
            _require(depth <= MAX_DEPTH, 'Глубина TOML превышена')
        elif c in ']}':
            depth -= 1
            _require(depth >= 0, 'Неверная вложенность TOML')
        if not c.isspace():
            # Предел по символам вне строк консервативен относительно числа токенов.
            tokens += 1
            _require(tokens <= MAX_TOKENS, 'Превышен бюджет токенов TOML')
        i += 1
    _require(depth == 0, 'Незавершённая вложенность TOML')


def bounded_toml(data):
    _require(isinstance(data, bytes) and len(data) <= MAX_TOML, 'Размер TOML превышен')
    text = data.decode('utf-8', 'strict')
    _toml_guard(text)
    obj = tomllib.loads(text)
    stack = [(obj, 0)]
    count = 0
    while stack:
        value, depth = stack.pop()
        count += 1
        _require(count <= MAX_NODES and depth <= MAX_DEPTH, 'Превышен бюджет дерева TOML')
        if isinstance(value, dict):
            count += len(value)
            _require(count <= MAX_NODES, 'Превышен бюджет ключей TOML')
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return obj


class AggregateBudget:
    """Общий бюджет одного анализа; после ошибки экземпляр больше не использовать."""

    def __init__(self):
        self.decompressed = 0
        self.entries = 0
        self.selected_bytes = 0

    def charge(self, stats, selected_bytes):
        self.decompressed += stats['decompressed_bytes']
        self.entries += stats['entries']
        self.selected_bytes += selected_bytes
        _require(self.decompressed <= 4_000_000_000, 'Общий бюджет распаковки превышен')
        _require(self.entries <= 1_000_000, 'Общий бюджет записей превышен')
        _require(self.selected_bytes <= MAX_OUTPUT_BYTES, 'Общий бюджет сохранённых bytes превышен')


def _encoded(data):
    return base64.b64encode(data).decode('ascii')


def _classify(path, data, explicit):
    name = path.rsplit('/', 1)[-1]
    license_marker = bool(LICENSE_TEXT.search(data))
    notice_marker = bool(NOTICE_TEXT.search(data))
    broad = bool(BROAD_NAME.search(name))
    producer = bool(PRODUCER_CANDIDATE.match(name))
    readme = bool(re.match(r'^readme(?:$|[._-])', name, re.I))
    if (broad or explicit) and license_marker and not re.search(r'\.(?:py|sh|rs|c|h|cpp|js|yml|yaml)$', name, re.I) and not readme:
        kind = 'primary_license_candidate'
    elif (broad or explicit) and notice_marker:
        kind = 'copyright_or_author_notice_candidate'
    elif broad or explicit:
        kind = 'filename_only_uncertain'
    elif HEADER_TEXT.search(data):
        kind = 'embedded_header_candidate'
    else:
        kind = 'other'
    return kind, producer, broad, readme


def _scan_tracked(data, aggregate):
    remaining_stream = 4_000_000_000 - aggregate.decompressed
    remaining_entries = 1_000_000 - aggregate.entries
    _require(remaining_stream > 0 and remaining_entries > 0, 'Общий бюджет исчерпан')
    return tar_data.tar_scan(io.BytesIO(data), min(512_000_000, remaining_stream), min(50_000, remaining_entries), 100_000_000, lambda path, size: True, aggregate)


def scan_crate(data, name, version, checksum, aggregate):
    """Один проход по crate; результат содержит исходные bytes только выбранных записей.

    Все файлы временно сохраняются в памяти с общим пределом safe.MEMORY_LIMIT.
    Неизвестный формат и превышение любого лимита отклоняются исключением.
    """
    _require(isinstance(data, bytes) and len(data) <= 100_000_000, 'Размер crate превышен')
    _require(isinstance(name, str) and IDENT.fullmatch(name) and isinstance(version, str) and IDENT.fullmatch(version), 'Неверная identity crate')
    _require(isinstance(checksum, str) and re.fullmatch(r'[0-9a-f]{64}', checksum), 'Неверная checksum crate')
    _require(hashlib.sha256(data).hexdigest() == checksum, 'Checksum crate не совпадает')
    _require(isinstance(aggregate, AggregateBudget), 'Не задан общий бюджет')
    stats, selected = _scan_tracked(data, aggregate)
    stem = name + '-' + version
    records = stats['members']
    for item in records:
        path = item['path'].rstrip('/') if item['directory'] else item['path']
        _require(path == stem or path.startswith(stem + '/'), 'Запись вне корня crate')
    manifest_path = stem + '/Cargo.toml'
    _require(manifest_path in selected, 'Отсутствует нормализованный Cargo.toml')
    manifest = bounded_toml(selected[manifest_path])
    package = manifest.get('package')
    _require(isinstance(package, dict), 'Отсутствует package Cargo.toml')
    _require(package.get('name') == name and package.get('version') == version, 'Identity manifest не совпадает')
    license_value = package.get('license')
    license_file = package.get('license-file')
    _require(license_value is None or isinstance(license_value, str), 'Неподдерживаемое поле license')
    _require(license_file is None or isinstance(license_file, str), 'Неподдерживаемое поле license-file')
    target = None
    if license_file is not None:
        safe.Names().check(license_file, False)
        target = stem + '/' + license_file
    target_record = next((r for r in records if r['path'] == target and not r['directory']), None)
    materials = []
    output_bytes = 0
    for record in records:
        if record['directory']:
            continue
        path = record['path']
        content = selected[path]
        kind, producer, broad, readme = _classify(path, content, path == target)
        if broad or producer or path == target or readme:
            retained = content
            retention = 'full'
        elif kind == 'embedded_header_candidate':
            retained = content[:PREFIX]
            retention = 'prefix'
        else:
            continue
        output_bytes += len(retained)
        _require(output_bytes <= MAX_SELECTED and aggregate.selected_bytes + output_bytes <= MAX_OUTPUT_BYTES, 'Бюджет материалов превышен')
        materials.append({'path': path, 'size': record['size'], 'sha256': record['sha256'], 'classification': kind, 'classification_uncertain': True, 'producer_candidate': producer, 'broad_filename_candidate': broad, 'explicit_license_file': path == target, 'retention': retention, 'classification_scan': 'full_content', 'embedded_match_may_be_outside_retained_prefix': retention == 'prefix', 'retained_size': len(retained), 'retained_sha256': hashlib.sha256(retained).hexdigest(), 'bytes_base64': _encoded(retained)})
    aggregate.selected_bytes += output_bytes
    flags = []
    if target is not None and target_record is None:
        flags.append('license_file_missing')
    if not any(m['classification'] == 'primary_license_candidate' for m in materials):
        flags.append('primary_text_missing_or_unrecognized')
    if not license_value:
        flags.append('license_expression_missing')
    if license_value and re.search(r'\b(?:OR|AND|WITH|LicenseRef|CDLA|CCADB)\b', license_value, re.I):
        flags.append('mixed_custom_exception_or_data_license_review')
    return {'name': name, 'version': version, 'archive_sha256': checksum, 'analysis_boundary': 'Полный поиск маркеров не является пофайловым юридическим исследованием; для embedded сохранён только prefix.', 'manifest': {'path': manifest_path, 'sha256': hashlib.sha256(selected[manifest_path]).hexdigest(), 'license': license_value, 'license_file': license_file, 'license_file_target': target, 'license_file_target_verified': target_record is not None if target else None, 'license_file_target_metadata': target_record}, 'inventory': records, 'materials': materials, 'review_flags': flags, 'scan': {k: stats[k] for k in ('entries', 'member_bytes', 'decompressed_bytes')}}
