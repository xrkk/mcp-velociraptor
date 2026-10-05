"""Actual acquired selected-member mechanism and ledger read, not P07 completion."""
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import p05_pc026_governance as gov,scenario_runner as runner
from tests import p06_package as package,p06_pc026_binding as binding,p06_aggregate_reports as aggregate,p07_handoff as handoff
from velociraptor_observation_cut import canonical
import velociraptor_observation_host as host


class RetainedSelected(unittest.TestCase):
    def test_actual_selected_member_core_and_ledger_then_missing_original_refusals(self):
        root=Path(os.environ['PC026_HOST_CONSUMER_INPUT']);reports=root/'Logs/P06/model'
        run=next((reports/'resource-qualification').glob('*/report.json')).parent
        evidence=Path(os.environ['PC026_MAINTENANCE_EVIDENCE_ROOT']);evidence.mkdir(parents=True,exist_ok=True)
        originals={p.relative_to(run).as_posix():p.read_bytes() for p in run.rglob('*') if p.is_file()}
        report=json.loads(originals['report.json']);sidecar=json.loads(originals[host.SIDECAR])
        ledger=json.loads(originals['maintenance/ledger.json']);join=json.loads(originals['mcp-raw-join.json'])
        targets={ 'sidecar':host.SIDECAR,'cut':'archive/cut.json','ledger':'maintenance/ledger.json',
            'capture':'raw-mcp/capture.json','body':'raw-mcp/'+join['calls'][0]['request_location']['body_ref']['path'],
            'SDK':next(r['result_ref']['path'] for r in ledger['calls'] if r['work_kind']=='sdk_tool'),
            'receipt':ledger['transfer_receipts'][0]['path']}
        def snapshot():return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
        def restore():
            for name,data in originals.items():(run/name).write_bytes(data)
        @gov.consumption
        def selected():
            admission=binding.load();added=[]
            def add(path):
                value=handoff._ref(admission,path);added.append(value);return value
            manifest=handoff._selected_run_members(admission,run,reports,add)
            admission.recheck();return manifest,added
        with patch.object(gov,'REPOSITORY',root),patch.object(runner,'P06_REPORT_ROOT',reports):
            before=snapshot();manifest,members=selected();self.assertEqual(snapshot(),before)
            paths={m['path'] for m in members};prefix=run.relative_to(root).as_posix()+'/'
            for path in (host.SIDECAR,'archive/cut.json','maintenance/ledger.json'):self.assertIn(prefix+path,paths)
            rows=aggregate.load_ledger(reports/'接收清单.jsonl',reports);self.assertEqual(len(rows),1)
            outcomes=[]
            for entry,consume in (('selected_run_members',selected),('load_ledger',lambda:aggregate.load_ledger(reports/'接收清单.jsonl',reports))):
                for name,path in targets.items():
                    with self.subTest(entry=entry,missing=name):
                        (run/path).unlink()
                        if name!='sidecar':
                            value=dict(sidecar)
                            for key,relative in host.REFS.items():
                                if (run/relative).exists():value[key]=host.ref(relative,(run/relative).read_bytes())
                            (run/host.SIDECAR).write_bytes(canonical(value))
                        inventory=package.canonical_bytes(package._member_inventory(run,reports))
                        (run/package.FINAL_MANIFEST).write_bytes(inventory)
                        # Rebind the host ledger package identity too, so its
                        # old digest does not preempt the independent gate.
                        changed=[dict(row) for row in rows];sha=hashlib.sha256(inventory).hexdigest()
                        changed[0].update(package_sha256=sha,manifest_sha256=sha)
                        ledger_path=reports/'接收清单.jsonl';old=ledger_path.read_bytes()
                        ledger_path.write_bytes(b''.join(canonical(row) for row in changed))
                        try:
                            before=snapshot()
                            try:consume()
                            except Exception as error:
                                import traceback
                                trace=''.join(traceback.format_exception(error));message=str(error)
                            else:self.fail('selected consumer accepted an incomplete run')
                            self.assertIn('velociraptor_observation_host.py',trace)
                            self.assertEqual(snapshot(),before)
                            outcomes.append(dict(entry=entry,missing=name,path=str(run/path),error=message,traceback=trace,writes=0))
                            (evidence/'selected-matrix.json').write_bytes(canonical(outcomes))
                        finally:ledger_path.write_bytes(old);restore()
            self.assertEqual(len(outcomes),14)
            # Historical/baseline public readers cannot alias the current root.
            for consume in (lambda:aggregate.aggregate_historical(evidence_root=reports),
                    lambda:aggregate.verify_baseline_evidence(report,run)):
                before=snapshot()
                with self.assertRaisesRegex(Exception,'historical.*current'):consume()
                self.assertEqual(snapshot(),before)
            (evidence/'selected-positive.json').write_bytes(canonical(dict(manifest=manifest,members=members,
                ledger_rows=len(rows),nature='selected member mechanism + public current ledger; no completion or handoff minted')))


def load_tests(loader,tests,pattern):return loader.loadTestsFromTestCase(RetainedSelected)
