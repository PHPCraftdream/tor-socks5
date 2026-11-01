#!/usr/bin/env python3
# CI-хелпер воркфлоу: выбор артефакта для job'а pt-proxy-contract (.github/workflows/ci.yml);
# файл перенесён из scripts/testing/pt_proxy/ и нужен именно этому job'у, а не произвольному потребителю.
"""Выбор единственного исполняемого артефакта Cargo с ограничением ввода."""
import json
import os
from pathlib import Path
import sys


def executable(path):
    found = []
    total = 0
    with open(path, 'rb') as stream:
        while True:
            line = stream.readline(4 * 1024 * 1024 + 1)
            if not line:
                break
            total += len(line)
            if len(line) > 4 * 1024 * 1024 or total > 128 * 1024 * 1024:
                raise ValueError('превышен предел сообщений Cargo')
            message = json.loads(line)
            if (message.get('reason') == 'compiler-artifact'
                    and message.get('target', {}).get('name') == 'pt_owner_contract'
                    and 'test' in message.get('target', {}).get('kind', [])
                    and message.get('executable')):
                found.append(message['executable'])
    if len(found) != 1 or not Path(found[0]).is_file() or not os.access(found[0], os.X_OK):
        raise ValueError('ожидался единственный исполняемый артефакт pt_owner_contract')
    return found[0]


if __name__ == '__main__':
    print(executable(sys.argv[1]))
