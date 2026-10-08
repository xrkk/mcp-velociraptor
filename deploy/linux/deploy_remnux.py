#!/usr/bin/env python3
"""Exclusive, offline, root-local deployment of the pinned Linux VR release."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid

VERSION = '0.77.3'
BINARY_SHA256 = '93171158fa081c07e3dd6b2cfc194f1a1db3eb30861639ad16eae6092afa42f7'
UNIT_DIRECTORY = Path('/etc/systemd/system')
UNITS = ('velociraptor-server.service', 'velociraptor-client.service')


class Refused(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def secure_path(path, *, private=False, directory=False):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(str(path)), 'PATH_INVALID')
    for candidate in [*reversed(path.parents), path]:
        s = candidate.lstat()
        require(not stat.S_ISLNK(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'PATH_OWNER_OR_MODE')
    s = path.stat()
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode), 'PATH_TYPE')
    if private:
        require(stat.S_IMODE(s.st_mode) == (0o700 if directory else 0o600), 'PATH_PRIVATE')
    return path


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data if isinstance(data, bytes) else data.encode())
        f.flush()
        os.fsync(f.fileno())


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def run(argv, timeout=30):
    # Never propagate config material or exception text to stdout/stderr.
    try:
        r = subprocess.run([str(x) for x in argv], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Refused('COMMAND_TIMEOUT_UNKNOWN') from None
    require(r.returncode == 0, 'COMMAND_FAILED')
    return r.stdout


def json_stream(data):
    text = data.decode(); result = []; decoder = json.JSONDecoder()
    while text.strip():
        text = text.lstrip(); value, end = decoder.raw_decode(text); text = text[end:]
        require(isinstance(value, list), 'QUERY_FORMAT')
        result.extend(value)
    return result


def settings(root, datastore):
    return {
        'Client': {'server_urls': ['https://127.0.0.1:8000/'], 'use_self_signed_ssl': True,
                   'writeback_linux': str(root / 'client.writeback.yaml'),
                   'tempdir_linux': str(root / 'client-temp')},
        'Frontend': {'hostname': '127.0.0.1', 'bind_address': '127.0.0.1', 'bind_port': 8000},
        'API': {'hostname': '127.0.0.1', 'bind_address': '127.0.0.1', 'bind_port': 8001, 'bind_scheme': 'tcp'},
        'GUI': {'bind_address': '127.0.0.1', 'bind_port': 8889, 'public_url': 'https://127.0.0.1:8889/'},
        'Datastore': {'location': str(datastore), 'filestore_directory': str(datastore)},
        'Logging': {'output_directory': str(root / 'logs')},
        'Monitoring': None, 'ExtraFrontends': None, 'autocert_cert_cache': None,
    }


def validate_config(binary, config, expected, client=False):
    secure_path(config, private=True)
    value = json.loads(run([binary, '--config', config, 'config', 'show', '--json']))
    for section in (('Client',) if client else ('Client', 'Frontend', 'GUI', 'API', 'Datastore')):
        for k, v in expected[section].items():
            require(value.get(section, {}).get(k) == v, 'CONFIG_MISMATCH')
    require(not value.get('ExtraFrontends') and not value.get('autocert_cert_cache'), 'EXTRA_LISTENER')
    if not client:
        require(value.get('Monitoring') is None, 'EXTRA_LISTENER')
    require(bool(value['Client'].get('ca_certificate')) and bool(value['Client'].get('nonce')), 'CONFIG_MISSING')
    if not client:
        require(bool(value.get('CA', {}).get('private_key')), 'CONFIG_MISSING')
    return True


def unit_text(root, role):
    return ('[Unit]\nDescription=Velociraptor ' + role + ' (loopback Linux)\nAfter=network.target\n'
            '[Service]\nType=simple\nUser=root\nNoNewPrivileges=yes\nUMask=0077\n'
            f'ExecStart={root}/velociraptor --config {root}/{role}.config.yaml '
            + ('frontend' if role == 'server' else 'client') + '\n'
            'Restart=on-failure\nRestartSec=3\n[Install]\nWantedBy=multi-user.target\n')


def local_client_id(root):
    p = secure_path(root / 'client.writeback.yaml', private=True)
    matches = re.findall(r'^client_id: (C\.[0-9a-f]+)\s*$', p.read_text(), re.M)
    require(len(matches) == 1, 'WRITEBACK_ID_MISSING')
    return matches[0]


def identity(expected_uuid, expected_boot):
    require(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() == expected_uuid, 'VM_MISMATCH')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == expected_boot, 'BOOT_MISMATCH')


def ready(root, expected_uuid, expected_boot):
    identity(expected_uuid, expected_boot)
    for unit in UNITS:
        value = run(['systemctl', 'show', unit, '--property=ActiveState,SubState,MainPID,NoNewPrivileges,User']).decode()
        require('ActiveState=active\n' in value and 'SubState=running\n' in value and
                'NoNewPrivileges=yes\n' in value and 'User=root\n' in value, 'SERVICE_NOT_READY')
    client_id = local_client_id(root)
    rows = json_stream(run([root / 'velociraptor', '--api_config', root / 'api-access/api_client.yaml',
                            'query', 'SELECT client_id, os_info FROM clients()', '--format', 'json', '--timeout', '10'], timeout=15))
    matches = [r for r in rows if r.get('client_id') == client_id]
    require(len(matches) == 1 and matches[0].get('os_info', {}).get('system', '').lower() == 'linux', 'ENROLLMENT_NOT_READY')
    listeners = run(['ss', '-H', '-lntp']).decode().splitlines()
    owned = [line.split()[3] for line in listeners if '"velociraptor"' in line]
    require(set(owned) == {'127.0.0.1:8000', '127.0.0.1:8001', '127.0.0.1:8889'}, 'EXTRA_LISTENER')
    for port in (8000, 8001, 8889):
        found = [line for line in listeners if len(line.split()) > 3 and line.split()[3].rsplit(':', 1)[-1] == str(port)]
        require(len(found) == 1 and found[0].split()[3] == f'127.0.0.1:{port}', 'LISTENER_MISMATCH')
    return {'client_id': client_id, 'os': 'linux', 'vm_uuid': expected_uuid, 'boot_id': expected_boot,
            'api_ready': True, 'services_ready': True, 'loopback_ports': [8000, 8001, 8889]}


def deploy(binary, root, datastore, transaction, expected_uuid, expected_boot, ready_seconds=90):
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    require(str(uuid.UUID(transaction)) == transaction, 'TRANSACTION_INVALID')
    require(5 <= ready_seconds <= 180, 'DEADLINE_INVALID')
    os.umask(0o077)
    identity(expected_uuid, expected_boot)
    root, datastore, binary = Path(root), Path(datastore), Path(binary)
    for p in (root, datastore):
        require(re.fullmatch(r'/[A-Za-z0-9_./-]+', str(p)) and '..' not in p.parts, 'PATH_INVALID')
        secure_path(p.parent, directory=True)
    require(root != datastore and root not in datastore.parents and datastore not in root.parents, 'PATH_OVERLAP')
    secure_path(binary)
    require(digest(binary) == BINARY_SHA256, 'BINARY_HASH')
    require(b'version: 0.77.3\n' in run([binary, 'version']), 'BINARY_VERSION')
    unit_dir = secure_path(UNIT_DIRECTORY, directory=True)
    params = {'transaction': transaction, 'root': str(root), 'datastore': str(datastore),
              'vm_uuid': expected_uuid, 'boot_id': expected_boot, 'binary_sha256': BINARY_SHA256}
    if root.exists() or root.is_symlink():
        secure_path(root, private=True, directory=True)
        complete = secure_path(root / 'deployment-complete.json', private=True)
        record = json.loads(complete.read_text())
        require(record['parameters'] == params, 'EXISTING_CONFLICT')
        require(digest(secure_path(root / 'velociraptor')) == BINARY_SHA256, 'BINARY_DRIFT')
        for role, unit in zip(('server', 'client'), UNITS):
            require(secure_path(unit_dir / unit).read_text() == unit_text(root, role), 'UNIT_DRIFT')
            validate_config(root / 'velociraptor', root / (role + '.config.yaml'), settings(root, datastore), role == 'client')
        secure_path(root / 'api-access', private=True, directory=True)
        secure_path(root / 'api-access/api_client.yaml', private=True)
        require(ready(root, expected_uuid, expected_boot)['client_id'] == record['ready']['client_id'], 'CLIENT_DRIFT')
        return record
    require(not datastore.exists() and not datastore.is_symlink(), 'DATASTORE_CONFLICT')
    for unit in UNITS:
        require(not os.path.lexists(unit_dir / unit), 'UNIT_CONFLICT')
        require(run(['systemctl', 'show', unit, '--property=LoadState', '--value']).strip() == b'not-found', 'UNIT_CONFLICT')
    for port in (8000, 8001, 8889):
        with socket.socket() as sock:
            try:
                sock.bind(('127.0.0.1', port))
            except OSError:
                raise Refused('PORT_CONFLICT') from None
    root.mkdir(mode=0o700)
    stage = root / ('deployment-' + transaction); stage.mkdir(mode=0o700)
    phase = 'reserved'; started = []; unit_files = []
    write_new(stage / 'parameters.json', json_bytes(params))
    try:
        phase = 'binary'; target = root / 'velociraptor'
        with binary.open('rb') as src:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
            with os.fdopen(fd, 'wb') as dst:
                shutil.copyfileobj(src, dst); dst.flush(); os.fsync(dst.fileno())
        require(digest(target) == BINARY_SHA256, 'BINARY_COPY')
        datastore.mkdir(mode=0o700)
        for name in ('logs', 'client-temp', 'api-access'):
            (root / name).mkdir(mode=0o700)
        phase = 'config'; expected = settings(root, datastore)
        generated = stage / 'generated.config.yaml'
        write_new(generated, run([target, 'config', 'generate', '--nobanner', '--merge', json.dumps(expected)]))
        # v0.77.3 restores omitted Monitoring from defaults. Explicit JSON null
        # survives its YAML loader and is the upstream no-monitoring condition.
        config = json.loads(run([target, '--config', generated, 'config', 'show', '--json']))
        config['Monitoring'] = None
        write_new(root / 'server.config.yaml', json_bytes(config))
        validate_config(target, root / 'server.config.yaml', expected)
        write_new(root / 'client.config.yaml', run([target, '--config', root / 'server.config.yaml', 'config', 'client']))
        validate_config(target, root / 'client.config.yaml', expected, client=True)
        run([target, '--config', root / 'server.config.yaml', 'config', 'api_client', '--name', 'linux-triage',
             '--role', 'administrator,api', root / 'api-access/api_client.yaml'])
        secure_path(root / 'api-access/api_client.yaml', private=True)
        phase = 'units'
        for role, unit in zip(('server', 'client'), UNITS):
            write_new(unit_dir / unit, unit_text(root, role), 0o644); unit_files.append(unit)
        run(['systemctl', 'daemon-reload'])
        phase = 'start'
        for unit in UNITS:
            started.append(unit)  # A command timeout still owns this new unit.
            run(['systemctl', 'enable', '--now', unit])
        phase = 'ready'; deadline = time.monotonic() + ready_seconds
        while True:
            try:
                status = ready(root, expected_uuid, expected_boot); break
            except (Refused, FileNotFoundError):
                if time.monotonic() >= deadline:
                    raise Refused('READY_TIMEOUT') from None
                time.sleep(1)
        record = {'parameters': params, 'ready': status, 'status': 'READY', 'version': VERSION,
                  'source_sha256': digest(Path(__file__)), 'units': {u: digest(unit_dir / u) for u in UNITS}}
        write_new(root / 'deployment-complete.json', json_bytes(record))
        write_new(stage / 'result.json', json_bytes({'phase': 'complete', 'status': 'READY'}))
        return record
    except BaseException as error:
        cleanup = {}
        for unit in reversed(started):
            try:
                require((unit_dir / unit).read_text() == unit_text(root, 'server' if unit == UNITS[0] else 'client'), 'UNIT_DRIFT')
                run(['systemctl', 'disable', '--now', unit]); cleanup[unit] = 'STOPPED_DISABLED'
            except BaseException:
                cleanup[unit] = 'UNKNOWN'
        write_new(stage / 'failure.json', json_bytes({'phase': phase, 'code': str(error) if isinstance(error, Refused) else type(error).__name__,
                   'unit_files': unit_files, 'cleanup': cleanup, 'retry': 'REFUSE_PARTIAL_PRESERVE_ORIGINALS'}))
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True); p.add_argument('--root', required=True)
    p.add_argument('--datastore', required=True); p.add_argument('--transaction', required=True)
    p.add_argument('--expected-uuid', required=True); p.add_argument('--expected-boot', required=True)
    p.add_argument('--ready-seconds', type=int, default=90)
    a = p.parse_args()
    try:
        result = deploy(a.binary, a.root, a.datastore, a.transaction, a.expected_uuid, a.expected_boot, a.ready_seconds)
    except Exception as e:
        print(json.dumps({'status': 'FAILED', 'code': str(e) if isinstance(e, Refused) else type(e).__name__}))
        return 1
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__':
    sys.exit(main())
