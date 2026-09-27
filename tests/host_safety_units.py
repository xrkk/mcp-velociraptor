"""Review renderer and separately gated, uninvoked host safety unit installer.

Nothing is installed or enabled by importing this module or by review mode.
The production installer requires a distinct, protected approval file.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from tests.host_safety_guard import GuardError, approval_binding, no_symlink_chain, strict_json


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _plain(path: Path, *, mode: int | None = None) -> bytes:
    no_symlink_chain(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError(f'{path}: not a plain file')
    if mode is not None and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode):
        raise ValueError(f'{path}: owner/mode differs')
    return path.read_bytes()


def _parent(path: Path) -> None:
    no_symlink_chain(path.parent)
    info = path.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError(f'{path.parent}: untrusted parent')


def render(manifest: dict, manifest_sha: str, *, review: bool) -> tuple[bytes, bytes]:
    import uuid
    attempt = manifest['attempt_id']
    if str(uuid.UUID(attempt)) != attempt or len(manifest_sha) != 64:
        raise ValueError('attempt/manifest SHA differs')
    root = f'/var/lib/velo-g14-guard/{attempt}'
    code = f'/usr/local/libexec/velo-g14-guard-{attempt}.py'
    service_path = f'/etc/systemd/system/velo-g14-guard@{attempt}.service'
    timer_path = f'/etc/systemd/system/velo-g14-guard@{attempt}.timer'
    if (manifest['test_mode'] is not False or manifest['state_dir'] != root
            or manifest['controller_install_path'] != code
            or manifest['unit_service_path'] != service_path
            or manifest['unit_timer_path'] != timer_path
            or manifest['vmrun_path'] != '/usr/bin/vmrun'
            or not Path(manifest['vmx']).is_absolute()
            or manifest['checkpoint_name'] != f'Snapshot G14-SAFETY-{attempt}'):
        raise ValueError('production unit object differs')
    interpreter = manifest['interpreter_path']
    if not Path(interpreter).is_absolute() or any(char.isspace() for char in interpreter):
        raise ValueError('unit interpreter path is unsafe')
    vm_dir = str(Path(manifest['vmx']).parent)
    if '"' in vm_dir or '\n' in vm_dir or '\\' in vm_dir:
        raise ValueError('VM directory cannot be rendered safely')
    deadline = datetime.datetime.fromisoformat(manifest['deadline_utc'].replace('Z', '+00:00'))
    if deadline.tzinfo is None or deadline.utcoffset() != datetime.timedelta(0):
        raise ValueError('deadline must be absolute UTC')
    calendar = deadline.strftime('%Y-%m-%d %H:%M:%S UTC')
    note = 'ConditionPathExists=/nonexistent/VELO-G14-REVIEW-ONLY\n' if review else ''
    service = f'''[Unit]
Description=Velo G14 exact safety deadline {attempt}
After=local-fs.target
{note}[Service]
Type=oneshot
User=root
Group=root
UMask=0077
WorkingDirectory={root}
ExecStart={interpreter} {code} --manifest {root}/approval-manifest.json --approval-sha {manifest_sha} deadline
TimeoutStartSec=900
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={root} "{vm_dir}"
'''
    timer = f'''[Unit]
Description=Velo G14 persistent deadline {attempt}
[Timer]
OnCalendar={calendar}
OnBootSec=1min
Persistent=true
AccuracySec=1s
Unit=velo-g14-guard@{attempt}.service
[Install]
WantedBy=timers.target
'''
    return service.encode(), timer.encode()


def _write_exclusive(path: Path, data: bytes, mode: int, created: list[Path] | None = None) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    if created is not None:
        created.append(path)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, mode)
    dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _approved_decision(manifest: dict, decision_path: Path) -> None:
    raw = _plain(decision_path, mode=0o600)
    if sha(raw) != manifest['approval_decision_sha256']:
        raise ValueError('decision byte identity differs')
    decision = strict_json(raw)
    expected = {'kind': 'velo-g14-safety-approval-v1', 'status': 'APPROVED',
                'attempt_id': manifest['attempt_id'], 'vmx': manifest['vmx'],
                'vmx_sha256': manifest['vmx_sha256'],
                'checkpoint_name': manifest['checkpoint_name'],
                'actions': ['bootstrap', 'qualify', 'confirm-guest', 'arm', 'deadline', 'commit'],
                'manifest_binding': approval_binding(manifest)}
    if decision != expected or decision_path != Path(manifest['approval_decision_path']):
        raise ValueError('decision scope/path differs')


def install(manifest_path: Path, manifest_sha: str, decision_path: Path) -> dict:
    """Explicit root-only install; never called in tests or this task."""
    if os.geteuid() != 0:
        raise ValueError('root required for installer')
    raw = _plain(manifest_path, mode=0o600)
    if sha(raw) != manifest_sha:
        raise ValueError('manifest byte identity differs')
    manifest = strict_json(raw)
    if manifest['test_mode'] is not False:
        raise ValueError('test mode cannot install')
    if sha(_plain(Path(__file__))) != manifest['installer_sha256']:
        raise ValueError('installer code identity differs')
    _approved_decision(manifest, decision_path)
    code = _plain(Path(__file__).with_name('host_safety_guard.py'))
    if sha(code) != manifest['code_sha256']:
        raise ValueError('controller code identity differs')
    if sha(_plain(Path(manifest['interpreter_path']))) != manifest['interpreter_sha256']:
        raise ValueError('interpreter identity differs')
    if sha(_plain(Path(manifest['vmrun_path']))) != manifest['vmrun_sha256']:
        raise ValueError('vmrun identity differs')
    vmx_path = Path(manifest['vmx'])
    if (sha(_plain(vmx_path)) != manifest['vmx_sha256']
            or vmx_path.stat().st_dev != manifest['vmx_device']
            or vmx_path.stat().st_ino != manifest['vmx_inode']):
        raise ValueError('VMX identity differs')
    if sha(_plain(Path(manifest['canonical_path']))) != manifest['canonical_sha256']:
        raise ValueError('canonical identity differs')
    service, timer = render(manifest, manifest_sha, review=False)
    attempt_root = Path(manifest['state_dir'])
    code_path = Path(manifest['controller_install_path'])
    service_path = Path(manifest['unit_service_path'])
    timer_path = Path(manifest['unit_timer_path'])
    targets = [attempt_root, code_path, service_path, timer_path]
    for path in targets:
        _parent(path)
        if path.exists() or path.is_symlink():
            raise ValueError(f'{path}: exclusive target already exists')
    # Validate bytes in a private temporary review leaf before any production write.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='velo-g14-unit-check-') as temporary:
        review_service = Path(temporary) / service_path.name
        review_timer = Path(temporary) / timer_path.name
        review_service.write_bytes(service)
        review_timer.write_bytes(timer)
        subprocess.run(['/usr/bin/systemd-analyze', 'verify', str(review_service), str(review_timer)],
                       check=True, timeout=30, capture_output=True)
    created: list[Path] = []
    activation_started = False
    try:
        attempt_root.mkdir(mode=0o700)
        created.append(attempt_root)
        _write_exclusive(attempt_root / 'approval-manifest.json', raw, 0o600, created)
        _write_exclusive(code_path, code, 0o700, created)
        _write_exclusive(service_path, service, 0o644, created)
        _write_exclusive(timer_path, timer, 0o644, created)
        activation_started = True
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, timeout=30)
        subprocess.run(['/usr/bin/systemctl', 'enable', '--now', timer_path.name], check=True, timeout=30)
    except BaseException:
        if not activation_started:
            for path in reversed(created):
                if path.is_dir():
                    path.rmdir()
                else:
                    path.unlink()
        # Once activation starts, its outcome can be unknown. Preserve only
        # this attempt's artifacts for explicit inspection, never touch others.
        raise
    return {'installed': True, 'attempt_id': manifest['attempt_id'],
            'service_sha256': sha(service), 'timer_sha256': sha(timer)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--approval-sha', required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--review-output', type=Path)
    modes.add_argument('--execute-install', action='store_true')
    parser.add_argument('--decision', type=Path)
    args = parser.parse_args()
    if args.execute_install:
        if args.decision is None:
            parser.error('install needs separate decision file')
        result = install(args.manifest, args.approval_sha, args.decision)
    else:
        raw = args.manifest.read_bytes()
        if sha(raw) != args.approval_sha:
            raise ValueError('manifest SHA differs')
        manifest = strict_json(raw)
        if sha(Path(__file__).read_bytes()) != manifest['installer_sha256']:
            raise ValueError('installer code SHA differs')
        code = Path(__file__).with_name('host_safety_guard.py').read_bytes()
        if sha(code) != manifest['code_sha256']:
            raise ValueError('controller code SHA differs')
        service, timer = render(manifest, args.approval_sha, review=True)
        output = args.review_output
        if not output.is_dir() or output.is_symlink():
            raise ValueError('review output must already be an isolated directory')
        name = f"velo-g14-guard@{manifest['attempt_id']}"
        _write_exclusive(output / (name + '.service'), service, 0o600)
        _write_exclusive(output / (name + '.timer'), timer, 0o600)
        result = {'review_only': True, 'service_sha256': sha(service), 'timer_sha256': sha(timer)}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (GuardError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({'error': str(exc)}), file=sys.stderr)
        raise SystemExit(3)
