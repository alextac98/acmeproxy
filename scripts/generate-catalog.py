#!/usr/bin/env python3
"""Extract documented credential fields from the pinned acme.sh adapters."""
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '.local/acme.sh')
catalog = []
reserved = {'PATH', 'HOME', 'TMPDIR', 'ENV', 'BASH_ENV', 'SHELLOPTS', 'BASHOPTS', 'CDPATH',
            'IFS', 'USER', 'LOGNAME', 'SHELL', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DEBUG',
            'LOG_FILE', 'SYS_LOG', 'ACCOUNT_CONF_PATH', 'DOMAIN_CONF', 'LE_WORKING_DIR',
            'LE_CONFIG_HOME', 'CERT_HOME', 'HTTP_HEADER', 'USER_PATH'}
for path in sorted((root / 'dnsapi').glob('dns_*.sh')):
    if path.stem == 'dns_acmeproxy':
        continue  # Avoid routing the proxy back to itself.
    source = path.read_text()
    match = re.search(r"dns_\w+_info='(.*?)'", source, re.S)
    if not match:
        continue
    lines = match[1].splitlines()
    fields, docs = [], ''
    for line in lines[1:]:
        option = re.match(r'^ ([A-Za-z][A-Za-z0-9_]*) (.+)$', line)
        if option:
            key, label = option.groups()
            if key not in reserved and not key.startswith(('LD_', 'BASH_', 'ACME_', 'LE_', 'DYLD_')):
                if not any(f['key'] == key for f in fields):
                    fields.append({'key': key, 'label': label})
        if line.startswith('Docs: '):
            docs = 'https://' + line[6:].removeprefix('https://')
    if fields:
        catalog.append({'id': path.stem, 'name': lines[0], 'fields': fields,
                        'docs': docs or 'https://github.com/acmesh-official/acme.sh/wiki/dnsapi'})
pathlib.Path('docs/providers.json').write_text(json.dumps(catalog, indent=2) + '\n')
print(f'Generated {len(catalog)} provider definitions')
