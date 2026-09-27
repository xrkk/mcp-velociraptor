#!/usr/bin/env python3
"""Isolated VMware command fake: never imports or executes real vmrun."""
import json,os,sys,time
from pathlib import Path
state=Path(os.environ['FAKE_VMRUN_STATE']);log=Path(os.environ['FAKE_VMRUN_LOG'])
args=sys.argv[1:]
if args[:2]!=['-T','ws']:raise SystemExit(2)
action=args[2];row=json.loads(state.read_bytes())
with log.open('a') as f:f.write(json.dumps({'action':action,'args':args[3:]})+'\n')
if action=='list':
    print('Total running VMs: 1' if row['running'] else 'Total running VMs: 0')
    if row['running']:print(row['vmx'])
elif action=='listSnapshots':
    print('Total snapshots:',3+len(row['snapshots']))
    for name in row['base_snapshots']+row['snapshots']:
        print(('\t' if row.get('indented_tree') else '')+name)
elif action=='snapshot':
    if args[3]!=row['vmx'] or args[4] in row['snapshots']:raise SystemExit(2)
    row['snapshots'].append(args[4]);state.write_text(json.dumps(row))
    marker='fake-safety-'+args[4].split('-')[-1]+'.vmsn'
    Path(row['vmx']).with_suffix('.vmsd').write_text(f'snapshot0.displayName = \"{args[4]}\"\nsnapshot0.uid = \"99\"\nsnapshot0.parent = \"5\"\nsnapshot0.filename = \"{marker}\"\nsnapshot0.disk0.fileName = \"fake-disk.vmdk\"\n')
    (Path(row['vmx']).parent/marker).write_bytes(b'fake-snapshot-marker')
    (Path(row['vmx']).parent/(marker[:-5]+'.vmem')).write_bytes(b'fake-memory')
elif action=='stop':
    row['running']=False;state.write_text(json.dumps(row))
elif action=='revertToSnapshot':
    if args[4] not in row['snapshots']:raise SystemExit(2)
    if os.environ.get('FAKE_VMRUN_TIMEOUT')=='1':time.sleep(4)
    row['reverts']+=1
    if row.get('running_after_revert'):row['running']=True
    state.write_text(json.dumps(row))
elif action=='start':
    row['running']=True;state.write_text(json.dumps(row))
else:raise SystemExit(2)
