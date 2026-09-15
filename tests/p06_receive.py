"""Append-only host receipt for sealed P06 attempts; never edits old evidence."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from tests.p06_evidence import plain_file
from tests.p06_package import canonical_bytes, file_identity, verify_manifest


def receive(run_dir: Path, root: Path) -> dict:
    from tests.p06_aggregate_reports import ledger_identity, load_ledger
    report_path = plain_file(run_dir, 'report.json')
    report = json.loads(report_path.read_bytes())
    if report['status'] not in {'success', 'failed'}:
        raise ValueError('only completed attempts can be received')
    if report['status']=='failed' and (not report.get('failure') or report.get('coverage')):
        raise ValueError('failed attempts require a cause and empty coverage')
    package_sha = verify_manifest(run_dir,root)
    relative = report_path.relative_to(root).as_posix()
    ledger_path = root/'接收清单.jsonl'
    lock_path = root/'.receive.lock'
    # A crash leaves a visible lock; never silently bypass concurrent writers.
    with lock_path.open('x',encoding='utf-8') as lock:
        lock.write(str(os.getpid()))
    try:
        rows = load_ledger(ledger_path,root) if ledger_path.exists() else []
        if any(row['report_relative_path']==relative for row in rows):
            raise ValueError('attempt is already received; receipt is immutable')
        row = {'monotonic_attempt':len(rows)+1,'scenario':report['scenario'],
               'status':report['status'],'report_relative_path':relative,
               'report_sha256':file_identity(report_path)[1],
               'manifest_relative_path':(run_dir/'package-manifest.json').relative_to(root).as_posix(),
               'manifest_sha256':package_sha,'package_sha256':package_sha,
               **ledger_identity(report),'received_at':datetime.now(UTC).isoformat()}
        with ledger_path.open('ab') as stream:
            stream.write(canonical_bytes(row))
            stream.flush()
            os.fsync(stream.fileno())
        return row
    finally:
        lock_path.unlink()


def initialize_history(root: Path) -> None:
    """Freeze references to both superseded epochs without touching either."""
    root.mkdir(parents=True,exist_ok=True)
    path = root/'historical-roots.json'
    rows = []
    for name in ('wf-01a05d1d-p06','wf-01a05d1d-p06-r2'):
        for filename in ('接收清单.jsonl','final-selection.json','aggregate.json'):
            source = root.parent/name/filename
            row = {'path':f'{name}/{filename}','exists':source.exists()}
            if source.exists():
                original = plain_file(root.parent,row['path'])
                row['size'],row['sha256'] = file_identity(original)
            else:
                row['reason'] = 'absent when the new evidence epoch was initialized'
            rows.append(row)
    raw = canonical_bytes({'schema_version':1,'roots':rows,
                           'open_chk':['CHK-024','CHK-025','CHK-026','CHK-027']})
    if path.exists():
        if plain_file(root,'historical-roots.json').read_bytes()!=raw:
            raise ValueError('historical evidence changed after epoch initialization')
        return
    with path.open('xb') as stream:
        stream.write(raw)
