"""Ограниченный разбор registry TAR; совместимость не является legal review."""
import gzip
import hashlib
import importlib.util
import pathlib
import sys

sys.dont_write_bytecode = True
_HELPER = pathlib.Path(__file__).resolve().parent.parent / 'analyze-safe.py'
_SPEC = importlib.util.spec_from_file_location('trusted_tar_safe_materials', _HELPER)
safe = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(safe)


def tar_scan(raw, stream_limit, entry_limit, member_limit, select, aggregate):
    """Копия ограниченного scanner: дополнительный режим только для regular.

    Списание фактических bytes и проверок имён происходит также при исключении.
    Смещение заголовка отсчитывается в распакованном TAR, начиная с нуля.
    """
    class TrackedNames(safe.Names):
        def check(self, name, directory):
            aggregate.entries += 1
            if aggregate.entries > 1_000_000:
                raise ValueError('Общий бюджет записей превышен')
            return super().check(name, directory)

    names = TrackedNames()
    records, selected = [], {}
    total, headers, pending, selected_total = 0, 0, None, 0
    stream = None
    try:
        with gzip.GzipFile(fileobj=raw, mode='rb') as gz:
            stream = safe.Budget(gz, stream_limit)
            while True:
                offset = stream.count
                header = safe.exact(stream, 512)
                if header == bytes(512):
                    if safe.exact(stream, 512) != bytes(512) or pending is not None:
                        raise ValueError('Неверное завершение TAR')
                    while True:
                        b = stream.read(1024 * 1024)
                        if not b:
                            break
                        if any(b):
                            raise ValueError('Ненулевые данные после TAR')
                    break
                headers += 1
                if headers > entry_limit * 2 + 1:
                    raise ValueError('Слишком много заголовков TAR')
                expected = safe.number(header[148:156])
                if sum(header[:148]) + 8 * 32 + sum(header[156:]) != expected:
                    raise ValueError('Неверная контрольная сумма TAR')
                if header[257:263] not in (b'ustar\0', b'ustar '):
                    raise ValueError('Поддерживается только ustar')
                mode = safe.number(header[100:108])
                major = safe.number(header[329:337])
                minor = safe.number(header[337:345])
                kind = header[156:157]
                redundant = mode & ~0o777 == 0o100000 and kind in (b'0', b'\0')
                if (mode & ~0o777 and not redundant) or major or minor:
                    raise ValueError('Недопустимые mode или device TAR mode=' + oct(mode) + ' typeflag=' + repr(kind) + ' device_major=' + str(major) + ' device_minor=' + str(minor) + ' header_offset=' + str(offset) + ' header_sha256=' + hashlib.sha256(header).hexdigest())
                size = safe.number(header[124:136])
                if any(header[157:257]):
                    raise ValueError('Linkname запрещён')
                if kind == b'L':
                    if pending is not None or not 1 <= size <= 513:
                        raise ValueError('Недопустимый заголовок GNU longname')
                    long_name = header[:100].split(b'\0', 1)[0].decode('utf-8', 'strict')
                    long_prefix = header[345:500].split(b'\0', 1)[0].decode('utf-8', 'strict')
                    if not (long_prefix == '' and long_name == '././@LongLink'):
                        TrackedNames().check(long_prefix + '/' + long_name if long_prefix else long_name, False)
                    value = safe.exact(stream, size)
                    if value[-1:] != b'\0' or b'\0' in value[:-1]:
                        raise ValueError('Неверное завершение GNU longname')
                    pending = value[:-1].decode('utf-8', 'strict')
                    TrackedNames().check(pending, False)
                    if any(safe.exact(stream, (-size) % 512)):
                        raise ValueError('Ненулевой padding TAR')
                    continue
                if kind == b'x':
                    if pending is not None or size > 65536:
                        raise ValueError('Недопустимый заголовок PAX')
                    pax_name = header[:100].split(b'\0', 1)[0].decode('utf-8', 'strict')
                    pax_prefix = header[345:500].split(b'\0', 1)[0].decode('utf-8', 'strict')
                    if not (pax_prefix == '' and pax_name == '././@PaxHeader'):
                        try:
                            TrackedNames().check(pax_prefix + '/' + pax_name if pax_prefix else pax_name, False)
                        except ValueError as exc:
                            raise ValueError('Недопустимое имя PAX: name=' + repr(pax_name[:512]) + ' prefix=' + repr(pax_prefix[:512])) from exc
                    pending = safe.pax_path(safe.exact(stream, size))
                    if any(safe.exact(stream, (-size) % 512)):
                        raise ValueError('Ненулевой padding TAR')
                    continue
                if kind not in (b'0', b'\0', b'5') or size > member_limit:
                    raise ValueError('Недопустимый тип или размер TAR: kind=' + repr(kind) + ' size=' + str(size) + ' header_sha256=' + hashlib.sha256(header).hexdigest())
                directory = kind == b'5'
                if directory and size:
                    raise ValueError('Каталог TAR содержит данные')
                def field(b):
                    return b.split(b'\0', 1)[0].decode('utf-8', 'strict')
                name = field(header[:100])
                prefix = field(header[345:500])
                name = pending if pending is not None else (prefix + '/' + name if prefix else name)
                pending = None
                names.check(name, directory)
                total += size
                if len(records) >= entry_limit or total > stream_limit:
                    raise ValueError('Превышен бюджет TAR')
                keep = bool(select and not directory and select(name, size))
                if keep:
                    selected_total += size
                    if selected_total > safe.MEMORY_LIMIT:
                        raise ValueError('Общий размер выбранных данных превышен')
                digest, data = safe.consume(stream, size, keep)
                if any(safe.exact(stream, (-size) % 512)):
                    raise ValueError('Ненулевой padding TAR')
                records.append({'path': name, 'size': size, 'sha256': None if directory else digest, 'directory': directory, 'raw_mode': mode, 'typeflag_hex': kind.hex(), 'device_major': major, 'device_minor': minor, 'header_sha256': hashlib.sha256(header).hexdigest(), 'header_offset': offset, 'redundant_regular_type_bit': bool(redundant)})
                if keep:
                    selected[name] = data
            return {'entries': len(records), 'member_bytes': total, 'decompressed_bytes': stream.count, 'members': records}, selected
    finally:
        if stream is not None:
            aggregate.decompressed += stream.count
