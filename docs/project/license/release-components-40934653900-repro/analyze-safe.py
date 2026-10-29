import argparse
import base64
import gzip
import hashlib
import re
import io
import json
import os
import pathlib
import stat
import struct
import zipfile

CANDIDATE_SIZE = 853866809
CANDIDATE_HASH = '75a58bb9393525b64f083105113771680bb561e1ff2f28f337fa584954b847d4'
NESTED_HASH = 'c2787211e957ac6e1cac1d0b2fbf34e24cd0444b835febed8aef63e7e9dafa5e'
# Предполагается отсутствие конкурентного изменения входов; это не защита от атак гонки.
# Вложенный candidate около 120 МБ, выбранные данные до 150 МБ; копии при join
# и вложенных проходах дают ориентировочный пик около 600 МБ, не жёсткий RSS-лимит.
MEMORY_LIMIT = 150_000_000
TEXT_LIMIT = 10_000_000
OUTPUT_LIMIT = 40_000_000


def parser(description, binaries=False):
    p = argparse.ArgumentParser(description=description)
    p.add_argument('--candidate', required=True)
    if binaries:
        p.add_argument('--binary-dir', required=True)
    p.add_argument('--target-root', required=True)
    p.add_argument('--output', required=True)
    return p


def no_link(path):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or getattr(st, 'st_file_attributes', 0) & 0x400:
        raise ValueError('Ссылка или reparse point запрещены')
    return st


def check_chain(path):
    path = pathlib.Path(os.path.abspath(path))
    for part in (path, *path.parents):
        no_link(part)
    return path


def output_dir(args):
    expected = pathlib.Path(__file__).resolve().parents[4] / 'target'
    root = check_chain(args.target_root)
    if root != expected or not stat.S_ISDIR(no_link(root).st_mode):
        raise ValueError('Неверный каталог target')
    out = pathlib.Path(os.path.abspath(args.output))
    if out == root or not out.is_relative_to(root):
        raise ValueError('Результат должен быть внутри target')
    check_chain(out.parent)
    os.mkdir(out)
    no_link(out)
    return out


def evidence_file(path):
    p = check_chain(path)
    if not stat.S_ISREG(no_link(p).st_mode):
        raise ValueError('Вход не является обычным файлом')
    f = open(p, 'rb')
    st = os.fstat(f.fileno())
    if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (no_link(p).st_dev, no_link(p).st_ino):
        f.close()
        raise ValueError('Вход изменился при открытии')
    return f


def checked(f, size, digest):
    f.seek(0)
    before = os.fstat(f.fileno())
    if before.st_size != size:
        raise ValueError('Неверный размер входа')
    h = hashlib.sha256()
    count = 0
    while True:
        b = f.read(1024 * 1024)
        if not b:
            break
        count += len(b)
        if count > size:
            raise ValueError('Превышен размер входа')
        h.update(b)
    after = os.fstat(f.fileno())
    if (before.st_size, before.st_mtime_ns, before.st_ino, before.st_dev) != (after.st_size, after.st_mtime_ns, after.st_ino, after.st_dev):
        raise ValueError('Вход изменился при чтении')
    if count != size or h.hexdigest() != digest:
        raise ValueError('Неверный hash входа')
    f.seek(0)


class Names:
    def __init__(self):
        self.seen = {}
        self.parents = set()
        self.spelling = {}

    def check(self, name, directory):
        if not isinstance(name, str) or len(name) > 512 or '\\' in name or name.startswith('/'):
            raise ValueError('Недопустимое имя')
        name = name.rstrip('/') if directory else name
        parts = name.split('/')
        if len(parts) > 32 or any(not x or x in ('.', '..') or ':' in x or x[-1] in ' .' or any(ord(c) < 32 or ord(c) == 127 for c in x) for x in parts):
            raise ValueError('Недопустимый компонент имени')
        key = name.casefold()
        prefixes = ['/'.join(parts[:i]).casefold() for i in range(1, len(parts))]
        for i in range(1, len(parts) + 1):
            original = '/'.join(parts[:i])
            folded = original.casefold()
            if folded in self.spelling and self.spelling[folded] != original:
                raise ValueError('Неоднозначный регистр пути')
            self.spelling[folded] = original
        if key in self.seen or any(self.seen.get(p) == 'file' for p in prefixes) or (not directory and key in self.parents):
            raise ValueError('Коллизия имён')
        self.seen[key] = 'dir' if directory else 'file'
        self.parents.update(prefixes)


class Budget:
    def __init__(self, raw, limit):
        self.raw, self.limit, self.count = raw, limit, 0

    def read(self, n):
        if n < 0:
            raise ValueError('Неограниченное чтение запрещено')
        b = self.raw.read(min(n, self.limit - self.count + 1))
        self.count += len(b)
        if self.count > self.limit:
            raise ValueError('Превышен бюджет потока')
        return b


def exact(raw, n):
    chunks = []
    while n:
        b = raw.read(min(n, 1024 * 1024))
        if not b:
            raise ValueError('Обрезанный поток')
        chunks.append(b)
        n -= len(b)
    return b''.join(chunks)


def consume(raw, size, keep=False):
    if size < 0 or (keep and size > MEMORY_LIMIT):
        raise ValueError('Размер выбранных данных превышен')
    h, chunks, remaining = hashlib.sha256(), [], size
    while remaining:
        b = raw.read(min(remaining, 1024 * 1024))
        if not b:
            raise ValueError('Обрезанный член')
        remaining -= len(b)
        h.update(b)
        if keep:
            chunks.append(b)
    return h.hexdigest(), b''.join(chunks) if keep else None


def number(field):
    if field and field[0] & 0x80:
        raise ValueError('Двоичное число TAR запрещено')
    s = field.strip(b' \0')
    if not s:
        return 0
    if any(c not in b'01234567' for c in s):
        raise ValueError('Неверное число TAR')
    return int(s, 8)


def pax_path(data):
    pos, path = 0, None
    while pos < len(data):
        space = data.find(b' ', pos, min(len(data), pos + 20))
        if space < 0 or not data[pos:space].isdigit():
            raise ValueError('Неверная запись PAX')
        length = int(data[pos:space])
        end = pos + length
        if length <= space - pos + 2 or end > len(data) or data[end - 1:end] != b'\n':
            raise ValueError('Неверная длина PAX')
        item = data[space + 1:end - 1]
        if not item.startswith(b'path='):
            raise ValueError('Неподдерживаемый атрибут PAX')
        if path is not None:
            raise ValueError('Повтор path PAX')
        path = item[5:].decode('utf-8', 'strict')
        pos = end
    if path is None:
        raise ValueError('Отсутствует path PAX')
    return path


def tar_scan(raw, stream_limit, entry_limit, member_limit, select=None):
    names = Names()
    records, selected = [], {}
    total, headers, pending, selected_total = 0, 0, None, 0
    with gzip.GzipFile(fileobj=raw, mode='rb') as gz:
        stream = Budget(gz, stream_limit)
        while True:
            header = exact(stream, 512)
            if header == bytes(512):
                if exact(stream, 512) != bytes(512) or pending is not None:
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
            expected = number(header[148:156])
            if sum(header[:148]) + 8 * 32 + sum(header[156:]) != expected:
                raise ValueError('Неверная контрольная сумма TAR')
            if header[257:263] not in (b'ustar\0', b'ustar '):
                raise ValueError('Поддерживается только ustar')
            if number(header[100:108]) & ~0o777 or number(header[329:337]) or number(header[337:345]):
                raise ValueError('Недопустимые mode или device TAR')
            size = number(header[124:136])
            kind = header[156:157]
            if any(header[157:257]):
                raise ValueError('Linkname запрещён')
            if kind == b'L':
                if pending is not None or not 1 <= size <= 513:
                    raise ValueError('Недопустимый заголовок GNU longname')
                long_name = header[:100].split(b'\0', 1)[0].decode('utf-8', 'strict')
                long_prefix = header[345:500].split(b'\0', 1)[0].decode('utf-8', 'strict')
                # Служебный маркер GNU не является путём члена архива.
                if not (long_prefix == '' and long_name == '././@LongLink'):
                    Names().check(long_prefix + '/' + long_name if long_prefix else long_name, False)
                value = exact(stream, size)
                if value[-1:] != b'\0' or b'\0' in value[:-1]:
                    raise ValueError('Неверное завершение GNU longname')
                pending = value[:-1].decode('utf-8', 'strict')
                Names().check(pending, False)
                if any(exact(stream, (-size) % 512)):
                    raise ValueError('Ненулевой padding TAR')
                continue
            if kind == b'x':
                if pending is not None or size > 65536:
                    raise ValueError('Недопустимый заголовок PAX')
                pax_name = header[:100].split(b'\0', 1)[0].decode('utf-8', 'strict')
                pax_prefix = header[345:500].split(b'\0', 1)[0].decode('utf-8', 'strict')
                # Виртуальный маркер PAX не является путём члена архива.
                if not (pax_prefix == '' and pax_name == '././@PaxHeader'):
                    try:
                        Names().check(pax_prefix + '/' + pax_name if pax_prefix else pax_name, False)
                    except ValueError as exc:
                        raise ValueError('Недопустимое имя PAX: name=' + repr(pax_name[:512]) + ' prefix=' + repr(pax_prefix[:512])) from exc
                pending = pax_path(exact(stream, size))
                if any(exact(stream, (-size) % 512)):
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
                if selected_total > MEMORY_LIMIT:
                    raise ValueError('Общий размер выбранных данных превышен')
            digest, data = consume(stream, size, keep)
            if any(exact(stream, (-size) % 512)):
                raise ValueError('Ненулевой padding TAR')
            records.append({'path': name, 'size': size, 'sha256': None if directory else digest, 'directory': directory})
            if keep:
                selected[name] = data
        return {'entries': len(records), 'member_bytes': total, 'decompressed_bytes': stream.count, 'members': records}, selected


def zip_inventory(z, count_limit, member_limit, total_limit):
    entries = z.infolist()
    if len(entries) > count_limit:
        raise ValueError('Слишком много записей ZIP')
    names, total = Names(), 0
    for x in entries:
        if len(x.extra) > 65535 or len(x.comment) > 65535:
            raise ValueError('Метаданные ZIP слишком велики')
        mode = stat.S_IFMT(x.external_attr >> 16)
        directory = x.is_dir()
        if x.flag_bits & (1 | 64) or mode not in (0, stat.S_IFREG, stat.S_IFDIR) or (mode and (mode == stat.S_IFDIR) != directory) or x.file_size < 0 or x.file_size > member_limit or (directory and x.file_size):
            raise ValueError('Недопустимые metadata ZIP')
        names.check(x.filename, directory)
        total += x.file_size
        if total > total_limit:
            raise ValueError('Превышен бюджет ZIP')
    return entries


def zip_read(z, x, keep=False):
    with z.open(x) as f:
        digest, data = consume(f, x.file_size, keep)
        if f.read(1):
            raise ValueError('Превышен размер члена ZIP')
    return digest, data


def candidate_outer(f, select=None):
    f.seek(0)
    with zipfile.ZipFile(f) as z:
        entries = zip_inventory(z, 100, 1_000_000_000, 2_000_000_000)
        archives = [x for x in entries if not x.is_dir() and x.filename.lower().endswith(('.tar.gz', '.tgz'))]
        if len(archives) != 1:
            raise ValueError('Ожидается один outer TAR')
        for x in entries:
            if x.is_dir():
                continue
            if x is archives[0]:
                with z.open(x) as raw:
                    bounded = Budget(raw, x.file_size)
                    stats, selected = tar_scan(bounded, 2_000_000_000, 50000, 150_000_000, select)
                    while bounded.read(1024 * 1024):
                        pass
                    if bounded.count != x.file_size:
                        raise ValueError('Неверный фактический размер ZIP')
            else:
                zip_read(z, x)
        return stats, selected


def candidate_nested(f):
    outer, _ = candidate_outer(f)
    wanted = 'targets/aarch64-apple-darwin/candidate.tar.gz'
    _, selected = candidate_outer(f, lambda name, size: name == wanted)
    if set(selected) != {wanted}:
        raise ValueError('Вложенный candidate отсутствует')
    data = selected[wanted]
    if hashlib.sha256(data).hexdigest() != NESTED_HASH:
        raise ValueError('Неверный hash candidate')
    nested, _ = tar_scan(io.BytesIO(data), 512_000_000, 10000, 100_000_000)
    return outer, nested, data


def strict_json(data):
    if len(data) > TEXT_LIMIT:
        raise ValueError('JSON слишком велик')
    # Глубину проверяем до json.loads; скобки внутри строк не учитываются.
    depth = 0
    quoted = False
    escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 64:
                raise ValueError('Глубина JSON превышена')
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise ValueError('Неверная структура JSON')
    if quoted or depth:
        raise ValueError('Неверная структура JSON')
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError('Повтор ключа JSON')
            out[k] = v
        return out
    obj = json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Константа JSON')))
    stack = [(obj, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > 64:
            raise ValueError('Глубина JSON превышена')
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)
    return obj


def write_json(out, name, obj):
    data = (json.dumps(obj, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    if len(data) > OUTPUT_LIMIT:
        raise ValueError('Результат слишком велик')
    with open(out / name, 'xb') as f:
        f.write(data)


def public_text(value):
    return value if isinstance(value, str) and len(value) <= 512 and not any(c in value for c in ('\\\\', '/home/', '/Users/', 'file://')) and not re.search(r'[A-Za-z]:[\\\\/]', value) else None


def summarize_json(name, obj):
    result = {'root_type': type(obj).__name__, 'root_count': len(obj) if isinstance(obj, (dict, list)) else None}
    if name == 'BLOCKERS.json' and isinstance(obj, list):
        result['blocker_count'] = len(obj)
        result['blockers'] = [public_text(item) for item in obj]
        return result
    if not isinstance(obj, dict):
        return result
    if name == 'MANIFEST.json':
        components = obj.get('components', [])
        if isinstance(components, list):
            result['components'] = [{k: v for k in ('id', 'license', 'declared_license', 'source_digest') if (v := public_text(c.get(k))) is not None} for c in components if isinstance(c, dict)]
            result['component_count'] = len(components)
            for field in ('source_paths', 'candidates'):
                result[field + '_count'] = sum(len(c.get(field, [])) for c in components if isinstance(c, dict) and isinstance(c.get(field), (list, dict)))
    elif name == 'BLOCKERS.json':
        blockers = obj.get('blockers', [])
        if isinstance(blockers, list):
            result['blocker_count'] = len(blockers)
            result['blockers'] = [{k: v for k, raw in b.items() if (v := public_text(raw)) is not None} if isinstance(b, dict) else public_text(b) for b in blockers]
    elif name == 'REVIEWS.json':
        reviews = obj.get('components', {})
        result['component_reviews'] = len(reviews) if isinstance(reviews, (list, dict)) else None
    return result


def git_sources(obj):
    # Проверка объекта подтверждает только согласованность, не доверенность tree bytes.
    result = {'scope': 'self-consistency only; tree bytes and production authority unverified', 'sources': []}
    def visit(node, label, depth):
        if depth > 64:
            raise ValueError('Глубина Git metadata превышена')
        if isinstance(node, dict):
            declared = node.get('commit')
            encoded = node.get('commit_object')
            if isinstance(declared, str) and re.fullmatch(r'[0-9a-f]{40}', declared) and isinstance(encoded, str):
                if len(encoded) > 1_400_000:
                    raise ValueError('Git object слишком велик')
                raw = base64.b64decode(encoded, validate=True)
                if len(raw) > 1_000_000:
                    raise ValueError('Git object слишком велик')
                header, sep, _ = raw.partition(b'\n\n')
                lines = header.split(b'\n')
                trees = [x[5:].decode('ascii') for x in lines if x.startswith(b'tree ')]
                parents = [x[7:].decode('ascii') for x in lines if x.startswith(b'parent ')]
                if not sep or len(trees) != 1 or any(not re.fullmatch(r'[0-9a-f]{40}', x) for x in trees + parents):
                    raise ValueError('Неверный заголовок Git commit')
                digest = hashlib.sha1(b'commit ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest()
                if digest != declared:
                    raise ValueError('Git commit hash не совпадает')
                result['sources'].append({'kind': label if label in ('project', 'sdk') else None, 'commit': declared, 'tree': trees[0], 'parents': parents, 'commit_object_hash_match': True})
            for key, value in node.items():
                visit(value, key if key in ('project', 'sdk') else label, depth + 1)
        elif isinstance(node, list):
            for item in node:
                visit(item, label, depth + 1)
    visit(obj, None, 0)
    return result


def main():
    args = parser('Ограниченный inventory candidate').parse_args()
    out = output_dir(args)
    with evidence_file(args.candidate) as f:
        checked(f, CANDIDATE_SIZE, CANDIDATE_HASH)
        outer, nested, data = candidate_nested(f)
        def choose(name, size):
            return name in ('MANIFEST.json', 'BLOCKERS.json', 'REVIEWS.json', 'GIT-SOURCES.json') and size <= TEXT_LIMIT
        _, texts = tar_scan(io.BytesIO(data), 512_000_000, 10000, 100_000_000, choose)
        if set(texts) != {'MANIFEST.json', 'BLOCKERS.json', 'REVIEWS.json', 'GIT-SOURCES.json'}:
            raise ValueError('Отсутствуют выбранные JSON')
        summaries = {}
        for name, content in texts.items():
            obj = strict_json(content)
            summaries[name] = {'sha256': hashlib.sha256(content).hexdigest(), **(git_sources(obj) if name == 'GIT-SOURCES.json' else summarize_json(name, obj))}
        groups = {'registry': 0, 'candidates': 0, 'project': 0, 'sdk': 0}
        for member in nested['members']:
            parts = member['path'].split('/')
            if len(parts) > 2 and parts[:2] == ['sources', 'v0.0.0-license-ci'] and parts[2] in groups:
                groups[parts[2]] += 1
        source_info = next((m for m in nested['members'] if m['path'] == 'SOURCE-INFO.txt'), None)
        candidate_hashes = [m for m in outer['members'] if m['path'].endswith('/candidate.tar.gz')]
        targets = {'aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-pc-windows-msvc', 'aarch64-unknown-linux-musl', 'aarch64-unknown-linux-gnu', 'x86_64-unknown-linux-gnu', 'x86_64-unknown-linux-musl'}
        expected = {'targets/' + target + '/candidate.tar.gz' for target in targets}
        if {m['path'] for m in candidate_hashes} != expected or len(candidate_hashes) != 7 or any(m['sha256'] != NESTED_HASH for m in candidate_hashes):
            raise ValueError('Неверные candidate hashes или targets')
        if source_info is None or not source_info['sha256']:
            raise ValueError('Отсутствует SOURCE-INFO')
        checked(f, CANDIDATE_SIZE, CANDIDATE_HASH)
        write_json(out, 'inventory.json', {'candidate_sha256': CANDIDATE_HASH, 'nested_sha256': NESTED_HASH, 'outer': outer, 'nested': nested, 'source_path_counts': groups, 'candidate_hashes': candidate_hashes, 'source_info': source_info, 'selected_json': summaries})


if __name__ == '__main__':
    main()
