import hashlib
import importlib.util
import io
import pathlib
import re
import sys
import zipfile

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('trusted_analyze_safe', pathlib.Path(__file__).resolve().parent / 'analyze-safe.py')
safe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safe)

ARTS = [
    (12931773573, 12126824, 'bcf0edb870c0dfeb1ec71bf6262328885226ae489ddd81a6493277bde63b78f8', 'aarch64-apple-darwin'),
    (12930598391, 12678740, '351d145d890ee0d8a7de555af7a2e176c693c5a621636ba0a669e571cb7af8fd', 'x86_64-apple-darwin'),
    (12929435820, 12747241, '807a36536fc8c7558829dc3c1ba89a6f22579307c6a3a8e0e0d34cf76531b393', 'x86_64-pc-windows-msvc'),
    (12927756356, 12982288, '46861aea32f692039d5d5ce4286265a15c1adcf3244e2e8b4de0a8c78bbc9025', 'aarch64-unknown-linux-musl'),
    (12926432069, 13007952, '8d6909f2f42b902bdced58f91cd1a96559da5a0ed08b31f1835e88657d35803c', 'aarch64-unknown-linux-gnu'),
    (12925166590, 13223590, 'fd759bd0516de84edb2b3599fc3389d8240947fa228d10a27913ad4bc6506d87', 'x86_64-unknown-linux-gnu'),
    (12924449353, 13473713, 'bc92c80fa638e9ef5f1fe77b6f7dfcadc8f2b16ec5bc4a6e2777685cda2f4c44', 'x86_64-unknown-linux-musl'),
]
TARGETS = {a[3] for a in ARTS}


def graph(data):
    counts, kinds, libs = {}, {}, set()
    packages = set()
    selected = []
    directives = []
    for line in data.splitlines():
        if len(line) > 1_000_000:
            raise ValueError('Строка JSONL слишком велика')
        obj = safe.strict_json(line)
        if not isinstance(obj, dict):
            raise ValueError('Неверная строка JSONL')
        reason = obj.get('reason')
        if reason not in ('compiler-artifact', 'build-script-executed', 'build-finished', 'compiler-message'):
            continue
        counts[reason] = counts.get(reason, 0) + 1
        if reason == 'compiler-artifact':
            pid = obj.get('package_id')
            if isinstance(pid, str):
                packages.add(hashlib.sha256(pid.encode()).hexdigest())
            target = obj.get('target', {})
            if isinstance(target, dict):
                pid = obj.get('package_id', '')
                match = re.search(r'#([A-Za-z0-9_.+-]+)@([A-Za-z0-9_.+-]+)$', pid) if isinstance(pid, str) and pid.startswith('registry+') else None
                name = match.group(1) if match else None
                if name and any(k in name.lower() for k in ('ring', 'openssl', 'liblzma', 'zstd', 'colored', 'option-ext', 'priority-queue', 'webpki', 'async_executors', 'xxhash', 'notify')):
                    selected.append({'package': name + '@' + match.group(2), 'kind': [x for x in target.get('kind', []) if isinstance(x, str) and re.fullmatch(r'[a-z-]{1,30}', x)], 'features': [x for x in obj.get('features', []) if isinstance(x, str) and re.fullmatch(r'[A-Za-z0-9_.+-]{1,80}', x)]})
                for kind in target.get('kind', []):
                    if kind in ('lib', 'bin', 'custom-build', 'proc-macro', 'example', 'test', 'bench', 'staticlib', 'cdylib', 'rlib', 'dylib'):
                        kinds[kind] = kinds.get(kind, 0) + 1
        if reason == 'build-script-executed':
            for lib in obj.get('linked_libs', []):
                if isinstance(lib, str) and re.fullmatch(r'[A-Za-z0-9_=.+-]{1,150}', lib):
                    libs.add(lib)
                    pid = obj.get('package_id', '')
                    match = re.search(r'#([A-Za-z0-9_.+-]+@[A-Za-z0-9_.+-]+)$', pid) if isinstance(pid, str) and pid.startswith('registry+') else None
                    directives.append({'package': match.group(1) if match else None, 'linked_lib': lib})
    return {'reasons': counts, 'unique_package_ids': len(packages), 'target_kinds': kinds, 'linked_libs': sorted(libs), 'interested_artifacts': selected, 'directives_by_package': directives}


def linkage(data):
    text = data.decode('utf-8', 'replace')
    allowed = []
    for line in text.splitlines():
        match = re.search(r'\(NEEDED\).*?\[([A-Za-z0-9_.+-]+)\]', line)
        if match:
            allowed.append({'needed': match.group(1)})
        elif 'no dynamic section' in line.lower():
            allowed.append({'no_dynamic_section': True})
        elif 'not an elf' in line.lower() or 'not an elf file' in line.lower() or 'failed to read file header' in line.lower():
            allowed.append({'not_elf': True})
        else:
            match = re.search(r'(?:^|/)([A-Za-z0-9_.+-]+\.(?:dylib|framework))(?:/([A-Za-z0-9_.+-]+))?', line)
            if match:
                allowed.append({'darwin_basename': match.group(1)})
    return {'sha256': hashlib.sha256(data).hexdigest(), 'recognized': allowed}


def binary(path, artifact, receipt):
    artifact_id, size, digest, target = artifact
    archive = 'tor-socks5-v0.0.0-license-ci-' + target + ('.zip' if 'windows' in target else '.tar.gz')
    name = 'tor-socks5.exe' if 'windows' in target else 'tor-socks5'
    with safe.evidence_file(path) as f:
        safe.checked(f, size, digest)
        with zipfile.ZipFile(f) as z:
            entries = safe.zip_inventory(z, 100, 200_000_000, 200_000_000)
            chosen = [x for x in entries if not x.is_dir() and x.filename == archive]
            if len(chosen) != 1 or chosen[0].file_size > safe.MEMORY_LIMIT:
                raise ValueError('Вложенный binary archive отсутствует или слишком велик')
            for x in entries:
                if not x.is_dir():
                    _, data = safe.zip_read(z, x, x is chosen[0])
                    if x is chosen[0]:
                        payload = data
        if archive.endswith('.zip'):
            with zipfile.ZipFile(io.BytesIO(payload)) as nested:
                entries = safe.zip_inventory(nested, 100, 200_000_000, 200_000_000)
                members = []
                for x in entries:
                    if not x.is_dir():
                        h, _ = safe.zip_read(nested, x)
                        members.append({'path': x.filename, 'size': x.file_size, 'sha256': h})
        else:
            stats, _ = safe.tar_scan(io.BytesIO(payload), 200_000_000, 100, 200_000_000)
            members = stats['members']
        found = [m for m in members if m['path'] == name and m.get('sha256')]
        if len(found) != 1 or found[0]['sha256'] != receipt:
            raise ValueError('Binary не совпадает с receipt')
        safe.checked(f, size, digest)
        return {'artifact_id': artifact_id, 'target': target, 'zip_size': size, 'zip_sha256': digest, 'binary': found[0], 'receipt_match': True, 'members': members}


def main():
    args = safe.parser('Проверка семи binary и receipt', binaries=True).parse_args()
    out = safe.output_dir(args)
    binary_dir = safe.check_chain(args.binary_dir)
    receipts, graphs, links = {}, {}, {}
    with safe.evidence_file(args.candidate) as f:
        safe.checked(f, safe.CANDIDATE_SIZE, safe.CANDIDATE_HASH)
        outer, _ = safe.candidate_outer(f)
        def choose(name, size):
            p = name.split('/')
            return len(p) >= 3 and p[0] == 'targets' and p[1] in TARGETS and (p[2:] in (['receipt.json'], ['messages.jsonl'], ['native-evidence', 'linkage.txt'])) and size <= safe.TEXT_LIMIT
        _, selected = safe.candidate_outer(f, choose)
        for path, data in selected.items():
            parts = path.split('/')
            target = parts[1]
            if parts[2] == 'receipt.json':
                obj = safe.strict_json(data)
                if not isinstance(obj, dict):
                    raise ValueError('Неверный receipt')
                digest = obj.get('binary_sha256')
                if obj.get('target') != target or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
                    raise ValueError('Неверный receipt')
                receipts[target] = {k: obj[k] for k in ('binary_sha256', 'source_digest', 'sdk_commit', 'build_evidence_digest') if isinstance(obj.get(k), str) and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', obj[k])}
            elif parts[2] == 'messages.jsonl':
                graphs[target] = graph(data)
            else:
                links[target] = linkage(data)
        safe.checked(f, safe.CANDIDATE_SIZE, safe.CANDIDATE_HASH)
    if set(receipts) != TARGETS or set(graphs) != TARGETS or set(links) != TARGETS:
        raise ValueError('Отсутствуют данные target')
    results = [binary(binary_dir / ('binary-%s.zip' % a[0]), a, receipts[a[3]]['binary_sha256']) for a in ARTS]
    safe.write_json(out, 'summary.json', {'outer': outer, 'binaries': results, 'receipts': receipts, 'graphs': graphs, 'linkage': links, 'all_receipt_matches': True})


if __name__ == '__main__':
    main()
