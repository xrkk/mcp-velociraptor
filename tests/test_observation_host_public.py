"""Public consumption of retained, actually acquired isolated SDK originals.

The fixture root is a test input, never a production authority selector. Every
public load still runs the full fixed governance and selector qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch
import zipfile

from tests import p05_pc026_governance as gov, scenario_runner as runner
from tests import p06_package as package, p06_receive as receive, p06_pc026_binding as binding
from velociraptor_observation_cut import canonical
import velociraptor_observation_host as host


class RetainedPublic(unittest.TestCase):
    def test_public_positive_and_missing_original_matrix(self):
        root=Path(os.environ['PC026_HOST_CONSUMER_INPUT'])
        report_root=root/'Logs/P06/model'
        runs=list((report_root/'resource-qualification').glob('*/report.json'))
        self.assertEqual(len(runs),1);run=runs[0].parent
        evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT']);evidence.mkdir(parents=True,exist_ok=True)
        with patch.object(gov,'REPOSITORY',root),patch.object(runner,'P06_REPORT_ROOT',report_root):
            report=json.loads((run/'report.json').read_bytes())
            # Actual public inventory and ZIP readback, with their current gate.
            payload=package.member_inventory(run,report_root,payload=True)
            (run/package.PAYLOAD_MANIFEST).write_bytes(canonical(payload))
            sources=package.member_sources(run,report_root)
            with zipfile.ZipFile(run/'qualification-payload.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
                for row in payload['members']:archive.write(sources[row['path']],row['path'])
                archive.write(run/package.PAYLOAD_MANIFEST,package.PAYLOAD_MANIFEST)
            package.verify_payload_zip(run,report_root)
            (run/package.FINAL_MANIFEST).write_bytes(canonical(package.member_inventory(run,report_root)))
            self.assertEqual(package.source_for_member(run,report_root,'run/'+host.SIDECAR),run/host.SIDECAR)
            @gov.consumption
            def admitted():return binding.load().report(report,run,report_root)
            admitted()
            originals={p.relative_to(run).as_posix():p.read_bytes() for p in run.rglob('*') if p.is_file()}
            sidecar=json.loads(originals[host.SIDECAR]);ledger=json.loads(originals['maintenance/ledger.json'])
            join=json.loads(originals['mcp-raw-join.json'])
            targets={'sidecar':host.SIDECAR,'archive_cut':'archive/cut.json','maintenance_ledger':'maintenance/ledger.json',
                'business_capture':'raw-mcp/capture.json',
                'business_body':'raw-mcp/'+join['calls'][0]['request_location']['body_ref']['path'],
                'full_sdk':next(r['result_ref']['path'] for r in ledger['calls'] if r['work_kind']=='sdk_tool'),
                'receipt':ledger['transfer_receipts'][0]['path']}
            entries={'Admission.report':admitted,
                'member_inventory':lambda:package.member_inventory(run,report_root),
                'member_sources':lambda:package.member_sources(run,report_root),
                'source_for_member':lambda:package.source_for_member(run,report_root,'run/report.json'),
                'verify_manifest':lambda:package.verify_manifest(run,report_root),
                'verify_payload_zip':lambda:package.verify_payload_zip(run,report_root),
                'receive':lambda:receive.receive(run,report_root)}
            outcomes=[]
            def snapshot():return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
            def restore():
                for p in run.rglob('*'):
                    if p.is_file() and p.relative_to(run).as_posix() not in originals:p.unlink()
                for name,data in originals.items():(run/name).write_bytes(data)
            chosen=os.environ.get('PC026_HOST_PUBLIC_ENTRY')
            for entry,consume in entries.items():
                if chosen and chosen!=entry:continue
                for name,relative in targets.items():
                    with self.subTest(entry=entry,missing=name):
                        (run/relative).unlink()
                        # Rebind every present fixed sidecar Ref and the full
                        # package inventory. No stale package SHA is the refusal.
                        if name!='sidecar':
                            rebound=dict(sidecar)
                            for key,path in host.REFS.items():
                                if (run/path).exists():rebound[key]=host.ref(path,(run/path).read_bytes())
                            (run/host.SIDECAR).write_bytes(canonical(rebound))
                        (run/package.FINAL_MANIFEST).write_bytes(canonical(package._member_inventory(run,report_root)))
                        (run/package.PAYLOAD_MANIFEST).write_bytes(canonical(package._member_inventory(run,report_root,payload=True)))
                        before=snapshot();start=time.monotonic()
                        try:
                            try:consume()
                            except Exception as error:
                                import traceback
                                trace=''.join(traceback.format_exception(error))
                                message=str(error)
                            else:self.fail('public consumer accepted an incomplete current run')
                            # Require the host readback path, not duplicate
                            # receipt or package-inventory mismatch precedence.
                            self.assertIn('velociraptor_observation_host.py',trace)
                            self.assertNotIn('package manifest differs',message)
                            self.assertNotIn('already received',message)
                            self.assertEqual(snapshot(),before)
                            outcomes.append(dict(entry=entry,missing=name,path=str(run/relative),
                                error=message,traceback=trace,seconds=time.monotonic()-start,writes=0))
                            (evidence/'public-matrix.json').write_bytes(canonical(outcomes))
                        finally:restore()
            self.assertEqual(len(outcomes),7 if chosen else 49)
            (evidence/'public-positive.json').write_bytes(canonical(dict(run=str(run),registry=137,
                qualification='fixed load + selector C8, historical original coordinates',
                sdk='retained actual dual SDK; no new networking',entries=list(entries),
                payload_members=len(payload['members']))))
