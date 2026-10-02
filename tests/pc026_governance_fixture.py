"""Synthetic 191 governance/content fixture, never a producer or VM executor.

Inputs are explicitly supplied historical originals; outputs require a new
isolated root. Windows observations, business transcripts and COMMITTED outputs
here are synthetic test construction and confer no real execution qualification.
"""
from __future__ import annotations
import json
import shutil
import copy
import uuid
from pathlib import Path
from unittest.mock import patch
from tests import p05_pc020_evidence as ev, p05_pc020_activation as graph
from tests import p05_pc026_governance as gov, p05_pc026_profile as profiles
from tests.pc020_activation_fixture import ActivationFixture, write, refresh_ref, build_issuance_receipt
from tests.test_p05_pc026_governance import ApprovalFixture, reference
from tests.p05_pc021_transition_evidence import INTENT_KIND, RECEIPT_KIND


def build(root: Path, bootstrap: Path, values: dict, repo: Path):
    """Populate a caller-created isolated fixture directory and return its A."""
    if root == repo or any(root.iterdir()):
        raise ValueError("current fixture requires a new empty isolated directory")
    fixture=ApprovalFixture(root,bootstrap)
    A=root/gov.EVIDENCE/'activation-191'/str(uuid.uuid4())
    payload={'schema_version':1,'observer_ipv4':'192.168.204.1','endpoint':'http://192.168.204.1:28786/','interface_ipv4':['192.168.204.1'],'rows':[]}
    with patch('tests.test_p05_pc020_evidence.receiver_document',return_value=(0,json.dumps(payload)+'\n','')):
     old=ActivationFixture(A,Path(values['PC020_ACTIVATION188_FIXTURE']),Path(values['PC020_PREDECESSOR_FIXTURE']).read_bytes(),Path(values['PC020_BASELINE_DIR_FIXTURE']),Path(values['PC020_ACTIVATION_DIR_FIXTURE']),Path(values['PC020_REAL_SOURCE_ROOT']),repo)
    # All generated business originals are explicitly synthetic. Replace only their
    # historical layer with the original pinned C7/448+4 and keep its policy intact.
    C7=(root/gov.CANONICAL).read_bytes(); c7=json.loads(C7)
    for namespace in ('pc020-preparation','pc020-migration'):
     shutil.rmtree(A/namespace)
     shutil.copytree(root/gov.EVIDENCE/namespace,A/namespace)
    creation=A/'creation-189/creation.json'; cd=json.loads(creation.read_bytes());cd['candidate']=profiles.CURRENT.snapshot
    retained=list(profiles.CURRENT.retained)
    for key in ('tree_before','tree_after','create_operation','metadata_readback'):
     p=creation.parent/cd[key]['path'];v=json.loads(p.read_bytes())
     if key.startswith('tree_'):
      names=retained+([profiles.CURRENT.snapshot] if key=='tree_after' else [])
      stdout=f'Total snapshots: {len(names)}\n'+'\n'.join(names)+'\n'
     elif key=='create_operation':
      v['request']['argv'][-1]=profiles.CURRENT.snapshot;v['request']['command_line']=' '.join(v['request']['argv']);stdout=''
     else:
      stdout='\n'.join(['snapshot.numSnapshots = "5"','snapshot.lastUID = "27"','snapshot.current = "27"']+[
       line for i,(name,uid,parent,marker) in enumerate([(retained[0],'3',None,ev.MARKER_187),(retained[1],'4','3','Win10MalBox-Velo-Snapshot4.vmsn'),(retained[2],'8','3','Win10MalBox-Velo-Snapshot8.vmsn'),(retained[3],'26','3','Win10MalBox-Velo-Snapshot26.vmsn'),(profiles.CURRENT.snapshot,'27','3',cd['checkpoint_marker'])])
       for line in [f'snapshot{i}.displayName = "{name}"',f'snapshot{i}.uid = "{uid}"',f'snapshot{i}.filename = "{marker}"']+([] if parent is None else [f'snapshot{i}.parent = "{parent}"'])])+ '\n'
     v['response']['stdout']=stdout;v['response']['stdout_size']=len(stdout.encode());v['response']['stdout_sha256']=ev._sha(stdout.encode());write(p,v);refresh_ref(creation.parent,cd[key])
    write(creation,cd)
    # Freeze current resources in this isolated repository, including 191 scenario
    # and source index bytes. Historical scenario bytes inside bootstrap stay intact.
    for path in {graph.INDEX,graph.FIXTURE,*(row[0] for row in graph.SCENARIOS.values())}:
     target=root/path;target.write_bytes((A/'source'/path).read_bytes())
    candidate_path=graph.SCENARIOS['p05-flow-triage-repair-candidate'][0]
    scenario=json.loads((root/candidate_path).read_bytes());scenario['required_snapshot']=profiles.CURRENT.snapshot;write(root/candidate_path,scenario)
    idx=json.loads((root/graph.INDEX).read_bytes())
    for row in idx['scenarios']:
     if row['snapshot_stage']=='P05_REPAIR_CANDIDATE':row['required_snapshot']=profiles.CURRENT.snapshot
     row['sha256']=ev._sha((root/graph.SCENARIOS[row['scenario_id']][0]).read_bytes())
    write(root/graph.INDEX,idx)
    # Current P06 source resources are separately rebound in this synthetic
    # repository; historical frozen bootstrap bytes are never relabelled.
    p06_index = root / 'tests/data/p06_scenario_index.json'
    index = json.loads(p06_index.read_bytes())
    for row in index['scenarios']:
     path = root / 'tests/scenarios' / row['path']
     scenario = json.loads(path.read_bytes())
     scenario['required_snapshot'] = profiles.CURRENT.snapshot
     write(path, scenario)
     row['required_snapshot'] = profiles.CURRENT.snapshot
     row['sha256'] = ev._sha(path.read_bytes())
    write(p06_index, index)
    for path in gov.RESOURCES:fixture.freeze[path]=reference(root,path);fixture.refs[path]=fixture.freeze[path]
    # Independent current policy exactly mirrors the loader's explicit partition.
    source_paths={p for p in fixture.normative if p!=gov.BOOTSTRAP}|{gov.NORMATIVE,gov.CONTRACT}|set(gov.SOURCE_RESOURCES)
    impl_paths=set(fixture.freeze)-source_paths
    shutil.rmtree(A/'source')
    for key,paths in [('source_inputs',source_paths),('implementation_sources',impl_paths)]:
     for p in sorted(paths):
      target=A/'source'/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((root/p).read_bytes())
    rootdoc=json.loads((A/'activation-evidence.json').read_bytes());rootdoc.update(kind='snapshot191-activation-evidence-v1',candidate=profiles.CURRENT.snapshot)
    for key,path in [('preparation_evidence',c7['preparation_evidence']['evidence_path']),('migration_evidence',c7['migration_evidence']['evidence_path'])]:rootdoc[key]=reference(A,path)
    rootdoc['creation_metadata']=reference(A,str(creation.relative_to(A)))
    for key,paths in [('source_inputs',source_paths),('implementation_sources',impl_paths)]:
     rootdoc[key]=[{'repo_path':p,'blob':ev._blob((root/p).read_bytes()),'content':reference(A,'source/'+p)} for p in sorted(paths)]
    for i,phase in enumerate([rootdoc['initial'],*rootdoc['candidate_cycles']]):
     report_path=A/phase['report']['path'];report=json.loads(report_path.read_bytes())
     scenario_path=graph.SCENARIOS[report['scenario']][0]
     report['source_sha256']=ev._sha((root/scenario_path).read_bytes());report['index_sha256']=ev._sha((root/graph.INDEX).read_bytes())
     snapshot_path=A/phase['snapshot_evidence']['path'];snapshot=json.loads(snapshot_path.read_bytes());snapshot.update(source_sha256=report['source_sha256'],index_sha256=report['index_sha256'])
     restore=snapshot['restore'];restore['canonical_sha256']=ev._sha(C7)
     if i:restore['snapshot_name']=profiles.CURRENT.snapshot
     for row in restore['restore_records']:
      kind=row['kind'];p=A/row['path']
      if kind=='canonical_readback':p.write_bytes(C7)
      elif kind in ('pc020_preparation','pc020_migration'):
       original=c7['preparation_evidence' if kind=='pc020_preparation' else 'migration_evidence'];row['path']=original['evidence_path'];p=A/row['path']
      elif kind=='snapshot_metadata':
       v=json.loads(p.read_bytes());names=retained+([profiles.CURRENT.snapshot] if i else []);stdout=f'Total snapshots: {len(names)}\n'+'\n'.join(names)+'\n';v['response'].update(stdout=stdout,stdout_size=len(stdout.encode()),stdout_sha256=ev._sha(stdout.encode()));write(p,v)
      elif kind=='revert_operation' and i:
       v=json.loads(p.read_bytes());v['request']['argv'][-1]=profiles.CURRENT.snapshot;v['request']['command_line']=' '.join(v['request']['argv']);write(p,v)
      row['sha256']=ev._sha(p.read_bytes())
     write(snapshot_path,snapshot);report['snapshot_evidence_sha256']=ev._sha(snapshot_path.read_bytes());write(report_path,report)
     ready_path=A/phase['ready']['path'];ready=json.loads(ready_path.read_bytes())
     if i:ready['snapshot_name']=profiles.CURRENT.snapshot
     write(ready_path,ready)
     for key in graph.PHASE_KEYS-{'run_id','restore_attempt_id','package_manifest'}:refresh_ref(A,phase[key])
     old._manifest(['initial','cycle-1','cycle-2'][i],phase);refresh_ref(A,phase['package_manifest'])
    write(A/'activation-evidence.json',rootdoc)
    S=build_issuance_receipt(A,rootdoc,C7);S['kind']='snapshot191-activation-issuance-receipt-v2';write(A/'issuance-receipt.json',S)
    c8=copy.deepcopy(c7);c8.update(epoch=8,phase='NETWORK_ACTIVE');c8['active_snapshot'].update(name=profiles.CURRENT.snapshot,checkpoint_marker=rootdoc['checkpoint_marker']);c8['automatic_restore_allowlist']=[profiles.CURRENT.snapshot];c8['retired_snapshots'].extend({'name':n,'status':ev.MANUAL_ONLY} for n in profiles.CURRENT.retired_append);c8['activation_evidence']={'source':'snapshot191-activation','evidence_path':str((A/'activation-evidence.json').relative_to(root/gov.EVIDENCE)),'evidence_sha256':ev._sha((A/'activation-evidence.json').read_bytes()),'activated_at':rootdoc['issued_at']};write(root/gov.CANONICAL,c8);C8=(root/gov.CANONICAL).read_bytes()
    hashes={'from_sha256':ev._sha(C7),'to_sha256':ev._sha(C8),'next_sha256':ev._sha(C8),'activation_root_sha256':ev._sha((A/'activation-evidence.json').read_bytes()),'issuance_receipt_sha256':ev._sha((A/'issuance-receipt.json').read_bytes())}
    common={'workflow_id':ev.WORKFLOW_ID,'transition_id':str(uuid.uuid4()),**hashes}
    write(A/'epoch8-transition-intent.json',{'schema_version':2,'kind':INTENT_KIND,**common,'created_at':'2026-10-02T00:00:00Z'})
    write(A/'epoch8-transition-receipt.json',{'schema_version':3,'kind':RECEIPT_KIND,**common,'started_at':'2026-10-02T00:00:00Z','replaced_at':'2026-10-02T00:00:01Z','directory_fsynced_at':'2026-10-02T00:00:02Z','readback_at':'2026-10-02T00:00:03Z','status':'COMMITTED','error':None})
    for p in A.rglob('*'):
     if p.is_file():
      coordinate=p.relative_to(root).as_posix();fixture.refs[coordinate]=reference(root,coordinate)
    fixture.refresh()
    return A
