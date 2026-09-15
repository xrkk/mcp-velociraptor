"""P05-only persistent parents for the frozen test backend and fixture.

This is not a service installer, restart policy, or product entry point. It
starts one explicitly selected existing component, with no command/config/PID
override. The outer P05 workflow must verify and stop any exact predecessor
before using a backend role, and must require an absent fixture for that role.
"""
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
from contextlib import contextmanager
import subprocess
import sys
import time
import uuid

REPO = Path(__file__).resolve().parents[1]
BACKEND = Path(r'C:\VelociraptorMCP\bin\velociraptor-v0.77.2-windows-amd64.exe')
DATASTORE = Path(r'C:\VelociraptorMCP\datastore')
WORKFLOW = 'wf-01a05d1d-9e2b-7f41-b936-536d20ce55a2'
FIXTURE_ATTEMPT = 'p05-attempt-010'
FIXTURE_INSTANCE = Path(r'C:\VelociraptorMCP\fixtures-p05\fixture-instance-v1.json')


def command(role: str) -> list[str]:
    if role in {'frontend','client'}:
        config = DATASTORE/('server.config.yaml' if role=='frontend' else 'client.config.yaml')
        return [str(BACKEND),'-v',role,'--config',str(config)]
    if role=='fixture':
        script = str(REPO/'tests/p05_prepare_fixtures.ps1').replace("'","''")
        # A Python parent forwards its pwsh-era PSModulePath verbatim; the PS7
        # module directory in it breaks Windows PowerShell module
        # auto-loading (Get-FileHash et al. stop resolving). Reset to the
        # stock 5.1 module path before invoking the fixture script.
        reset_modules = (
            '$env:PSModulePath="$env:ProgramFiles\\WindowsPowerShell\\Modules;'
            '$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\Modules"; '
        )
        # The PowerShell executor must remain alive after the dedicated fixture
        # is killed, so that the post-kill protected-identity check can succeed.
        ps = (f"$ErrorActionPreference='Stop'; {reset_modules}"
              f"& '{script}' -WorkflowId '{WORKFLOW}' "
              f"-AttemptId '{FIXTURE_ATTEMPT}'; if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) "
              "{throw 'fixture preparation failed'}; Start-Sleep -Seconds 86400")
        return ['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command',ps]
    raise ValueError('P05 parent role must be frontend, client or fixture')


def require_plain_path(path: Path) -> None:
    for component in reversed((path,*path.parents)):
        info=component.lstat()
        if component.is_symlink() or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('P05 parent path contains a link or reparse point')


@contextmanager
def role_lock(root: Path, role: str):
    command(role)
    require_plain_path(root)
    path=root/(role+'.active.lock')
    identity=str(uuid.uuid4())
    with path.open('x',encoding='utf-8') as stream:
        stream.write(identity)
        stream.flush()
        os.fsync(stream.fileno())
    completed=False
    try:
        yield
        completed=True
    finally:
        # Only a normal return proves launch completed its child wait. Any
        # exception leaves a conservative lock, even if the child did exit.
        if completed:
            require_plain_path(path)
            if path.read_text(encoding='utf-8')!=identity:
                raise ValueError('P05 role lock identity changed')
            path.unlink()


def require_absent_predecessor(role: str) -> None:
    from tests.p05_real_acceptance import powershell, process_snapshot
    if role=='fixture':
        path=FIXTURE_INSTANCE
        require_plain_path(path)
        fixture=json.loads(path.read_text(encoding='utf-8-sig'))
        if fixture['workflow_id']!=WORKFLOW or fixture['attempt_id']!=FIXTURE_ATTEMPT:
            raise ValueError('fixture belongs to another preparation')
        if any(row['ProcessId']==fixture['process']['pid'] for row in process_snapshot(fixture['process']['pid'])):
            raise ValueError('fixture process already exists; parent may not replace it')
        return
    argv=command(role)
    executable=argv[0].replace("'","''")
    # Observe in the guest without returning other processes' command lines.
    count=powershell("$ErrorActionPreference='Stop'; "
        f"@(Get-CimInstance Win32_Process | Where-Object {{ $_.ExecutablePath -eq '{executable}' "
        f"-and $_.CommandLine -match '\\s{role}\\s' }}).Count")
    if int(count)!=0:
        raise ValueError('backend predecessor still exists; no duplicate launch permitted')


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role',required=True,choices=('frontend','client','fixture'))
    args=parser.parse_args()
    if os.name!='nt' or os.environ.get('COMPUTERNAME')!='DESKTOP-3FI41GR':
        raise RuntimeError('P05 parent can run only in the approved Windows VM')
    argv=command(args.role)
    parent_root=REPO/'Logs/P05/process-parents'
    parent_root.mkdir(parents=True,exist_ok=True)
    require_plain_path(parent_root)
    with role_lock(parent_root,args.role):
        require_absent_predecessor(args.role)
        return launch(args.role,argv,parent_root)


def verify_child_binding(parent: dict, child: dict, pid: int, argv: list[str]) -> None:
    from tests.p05_real_acceptance import process_instant
    if (parent['ProcessId']!=os.getpid() or child['ProcessId']!=pid
            or child['ParentProcessId']!=parent['ProcessId']
            or child['CommandLine']!=subprocess.list2cmdline(argv)
            or process_instant(parent['CreationDate'])>process_instant(child['CreationDate'])):
        raise ValueError('P05 child does not match the persistent launcher identity')
    expected=Path(argv[0])
    if not expected.is_absolute():
        expected=Path(os.environ['SYSTEMROOT'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    if Path(child['ExecutablePath'])!=expected:
        raise ValueError('P05 child executable differs')


def await_fixture_binding(child: dict) -> dict:
    from tests.p05_real_acceptance import process_identity, process_instant, verify_fixture_process
    deadline=time.monotonic()+30
    while True:
        require_plain_path(FIXTURE_INSTANCE)
        instance_bytes=FIXTURE_INSTANCE.read_bytes()
        instance=json.loads(instance_bytes.decode('utf-8-sig'))
        if instance['workflow_id']!=WORKFLOW or instance['attempt_id']!=FIXTURE_ATTEMPT:
            raise ValueError('P05 fixture preparation ownership differs')
        observed=process_identity(instance['process']['pid'])
        if observed is not None:
            verify_fixture_process(instance['process'],observed,workflow_id=WORKFLOW,
                                   attempt_id=FIXTURE_ATTEMPT,protected=[child])
            if (observed['ParentProcessId']!=child['ProcessId']
                    or process_instant(child['CreationDate'])>process_instant(observed['CreationDate'])):
                raise ValueError('P05 fixture was not created by this persistent preparer')
            current_preparer=process_identity(child['ProcessId'])
            if current_preparer!=child:
                raise ValueError('P05 persistent preparer identity changed during readiness')
            return {'instance_sha256':hashlib.sha256(instance_bytes).hexdigest(),
                    'process_identity':observed,'preparer_identity':child}
        if time.monotonic()>=deadline:
            raise RuntimeError('P05 fixture readiness deadline exceeded')
        time.sleep(0.2)


def launch(role: str, argv: list[str], parent_root: Path) -> int:
    from tests.p05_real_acceptance import process_identity
    output=parent_root/str(uuid.uuid4())
    output.mkdir(parents=True,exist_ok=False)
    record={'role':role,'parent_pid':os.getpid(),'parent_parent_pid':os.getppid(),
            'argv':argv,'started_at':datetime.now(UTC).isoformat(),
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    with (output/'child.stdout').open('xb') as stdout,(output/'child.stderr').open('xb') as stderr:
        process=subprocess.Popen(argv,cwd=REPO,stdout=stdout,stderr=stderr)
        try:
            record['child_pid']=process.pid
            record['parent_identity']=process_identity(os.getpid())
            record['child_identity']=process_identity(process.pid)
            record['identity_observed']=record['parent_identity'] is not None and record['child_identity'] is not None
            if not record['identity_observed']:
                raise RuntimeError('P05 parent startup identity was not observed')
            verify_child_binding(record['parent_identity'],record['child_identity'],process.pid,argv)
            if role=='fixture':
                record['fixture_binding']=await_fixture_binding(record['child_identity'])
            with (output/'started.json').open('x',encoding='utf-8') as stream:
                json.dump(record,stream,ensure_ascii=False,indent=2)
        finally:
            # Observation or evidence-write failure cannot abandon a live child
            # or release the enclosing role lock. Do not kill it as a fallback.
            result=process.wait()
    with (output/'exited.json').open('x',encoding='utf-8') as stream:
        json.dump({'child_pid':process.pid,'exit_code':result,'ended_at':datetime.now(UTC).isoformat()},stream,indent=2)
    return result


if __name__=='__main__':
    raise SystemExit(main())
