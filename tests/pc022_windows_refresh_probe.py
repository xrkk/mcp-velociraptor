"""Strict PC022 isolated Windows acceptance probe; never deploys or issues.

Native API observations, native refusals and injected API faults are separated.
Each case checks its exact expected stage and side effects; counts alone never
make an unexpected rejection pass. Injected close failures still close the
actual owned handle once before reporting the simulated failure, avoiding leaks.
"""
from __future__ import annotations

import ctypes
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pc022_windows_refresh as refresh
import p05_pc021_readback as reader


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def persist(path, data):
    with path.open('xb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())


def audit_refresh(directory, *, fault=None, before_open=None):
    """Observe actual calls; only named injected cases alter API outcomes."""
    create, info, flush, close = (refresh.CreateFileW, refresh.GetFileInformationByHandleEx,
                                 refresh.FlushFileBuffers, refresh.CloseHandle)
    events, handles, acquired, actual_closed = [], {}, [], []
    def opened(*args):
        role = ('main','pre','post')[len(acquired)]
        if before_open:before_open(role)
        handle=create(*args);value=refresh._handle_value(handle)
        events.append({'action':'open_'+role,'return':value,'GetLastError':ctypes.get_last_error(),
                       'access':args[1],'share':args[2],'disposition':args[4],'flags':args[5]})
        if value is not None and value != refresh.INVALID_HANDLE_VALUE:
            handles[value]=role;acquired.append((value,role))
        return handle
    def queried(handle, code, pointer, size):
        ok=info(handle,code,pointer,size);error=ctypes.get_last_error()
        events.append({'action':('tag_' if code==9 else 'id_')+handles[handle],
                       'class':code,'size':size,'return':int(ok),'GetLastError':error})
        if fault=='post_id' and code==18 and handles[handle]=='post' and ok:
            ctypes.cast(pointer,ctypes.POINTER(refresh.FILE_ID_INFO)).contents.file_id[0] ^= 1
        return ok
    def flushed(handle):
        if fault in ('flush','flush_and_close_main'):
            ctypes.set_last_error(777);ok=0
        else:ok=flush(handle)
        events.append({'action':'flush_main','return':int(ok),'GetLastError':ctypes.get_last_error()})
        return ok
    def closed(handle):
        ok=close(handle);error=ctypes.get_last_error();role=handles[handle]
        if ok:actual_closed.append((handle,role))
        item={'action':'close_'+role,'actual_return':int(ok),'actual_GetLastError':error}
        events.append(item)
        selected=fault in ('close_'+role,'close_'+role+'_raise') or (fault=='flush_and_close_main' and role=='main')
        if selected:
            item['injected']=fault;ctypes.set_last_error(888)
            if fault.endswith('_raise'):
                failure=OSError('injected close exception after actual close');failure.winerror=888;raise failure
            return 0
        return ok
    error=None;observation=None
    with patch.object(refresh,'CreateFileW',opened),patch.object(refresh,'GetFileInformationByHandleEx',queried), \
         patch.object(refresh,'FlushFileBuffers',flushed),patch.object(refresh,'CloseHandle',closed):
        try:observation=refresh.windows_refresh_directory(directory)
        except refresh.Pc022WindowsRefreshError as exc:error=exc
    assert sorted(acquired)==sorted(actual_closed), 'actual owned handle not successfully closed exactly once'
    assert all(e['access']==refresh.GENERIC_WRITE and e['share']==7 and e['flags']==0x02200000
               and e['disposition']==3 for e in events if e['action'].startswith('open_'))
    actions=[e['action'] for e in events]
    assert len([a for a in actions if a.startswith('open_')])<=3
    return observation,error,events


def make_probe(root: Path, cross_root: Path | None = None) -> int:
    if os.name != 'nt':raise RuntimeError('Windows-only probe')
    root=root.resolve(strict=True)
    assert not any(root.iterdir()), 'probe case directory must be new and empty'
    sentinel=root.parent/'external-sentinel.bin'
    persist(sentinel,b'T005 sentinel outside all case directories')
    sentinel_sha=digest(sentinel)
    canonical=root.parent/'snapshot-recovery-state.json';assert not canonical.exists()
    results=[]
    def case(name, category, fn, stage=None, reader_match=None):
        item={'case':name,'category':category,'expected_stage':stage,'passed':False}
        try:
            detail=fn()
            if stage or reader_match:raise AssertionError('expected refusal did not occur')
            item.update(detail or {});item['passed']=True
        except refresh.Pc022WindowsRefreshError as exc:
            item.update(stage=exc.stage,winerror=exc.winerror,aggregated=exc.aggregated,error=str(exc))
            item['passed']=stage is not None and exc.stage==stage
        except reader.ReadbackError as exc:
            item.update(error=str(exc),notes=getattr(exc,'__notes__',[]))
            item['passed']=reader_match is not None and reader_match in str(exc)
        except Exception as exc:item.update(error=type(exc).__name__+': '+str(exc))
        item['sentinel_unchanged']=digest(sentinel)==sentinel_sha
        item['canonical_absent']=not canonical.exists()
        item['passed']=item['passed'] and item['sentinel_unchanged'] and item['canonical_absent']
        results.append(item)
    def directory(name):
        path=root/name;path.mkdir(exist_ok=False);return path
    def audited_success():
        observation,error,events=audit_refresh(directory('refresh'))
        if error:raise error
        assert [e['action'] for e in events]==['open_main','tag_main','id_main','open_pre','id_pre',
                'close_pre','flush_main','close_main','open_post','id_post','close_post']
        return {'observation':observation,'events':events}
    case('refresh_plain_three_handles','real_api_success',audited_success)
    def identities():
        path=directory('identities');file=path/'ordinary.bin';persist(file,b'FileIdInfo 128-bit')
        first=refresh.handle_directory_identity(path);second=refresh.handle_directory_identity(path)
        f1=refresh.handle_file_identity(file);f2=refresh.handle_file_identity(file)
        assert first==second and f1==f2 and first[0]==f1[0]
        return {'directory_identity':first,'file_identity':f1,'stable':True}
    case('directory_and_file_FileIdInfo_stable','real_api_success',identities)
    def hierarchy():
        base=directory('hierarchy');events=[];real=refresh.windows_refresh_directory
        def observed(path):events.append(str(path.relative_to(base)));return real(path)
        with patch.object(refresh,'windows_refresh_directory',observed):
            deepest=refresh.create_hierarchy_and_refresh(base,('A','B','C'))
        assert deepest==base/'A'/'B'/'C'
        assert events==['A','.','A\\B','A','A\\B\\C','A\\B']
        return {'refresh_order':events,'deepest':str(deepest)}
    case('hierarchy_three_levels','real_api_success',hierarchy)
    def file_control():
        path=root/'ordinary-control.bin';persist(path,b'durable ordinary control');refresh.windows_refresh_directory(root)
        assert path.read_bytes()==b'durable ordinary control';return {'sha256':digest(path)}
    case('ordinary_file_fsync_then_parent','real_api_success',file_control)
    def hardlink():
        path=directory('hardlink');source=path/'source';target=path/'target';persist(source,b'hardlink bytes')
        outcome=refresh.windows_publish_hard_link(source,target)
        assert source.exists() and target.read_bytes()==b'hardlink bytes'
        assert refresh.handle_file_identity(source)==refresh.handle_file_identity(target)
        return {'observation':outcome,'equal_identity':True}
    case('same_volume_hardlink','real_api_success',hardlink)
    def replaced():
        path=directory('replace');source=path/'source';target=path/'target'
        persist(source,b'new bytes');persist(target,b'old bytes');outcome=refresh.windows_replace_file(source,target)
        assert not source.exists() and target.read_bytes()==b'new bytes';return {'observation':outcome}
    case('same_volume_replace_flags9','real_api_success',replaced)
    def type_refusal():
        path=root/'type.bin';persist(path,b'type negative')
        try:refresh.windows_refresh_directory(path)
        finally:assert path.read_bytes()==b'type negative'
    case('ordinary_file_as_directory','real_api_rejection',type_refusal,stage='type')
    target=directory('junction-target');link=root/'junction'
    subprocess.run(['cmd','/c','mklink','/J',str(link),str(target)],check=True,capture_output=True,timeout=10)
    case('junction_directory','real_api_rejection',lambda:refresh.windows_refresh_directory(link),stage='reparse')
    def moved_identity():
        path=directory('moved');before=refresh.handle_directory_identity(path)
        moved=root/'moved-original';os.rename(path,moved);path.mkdir();after=refresh.handle_directory_identity(path)
        assert before!=after;return {'before':before,'after':after,'different':True}
    case('real_path_replacement_FileIdInfo','real_api_success',moved_identity)
    for role in ('pre','post'):
        def drift(role=role):
            path=directory('live-drift-'+role);moved=root/('live-original-'+role)
            def swap(current_role):
                if current_role==role:os.rename(path,moved);path.mkdir()
            observation,error,events=audit_refresh(path,before_open=swap)
            assert error and error.stage=='compare_'+role
            assert path.is_dir() and moved.is_dir()
            actions=[e['action'] for e in events]
            assert 'flush_main' not in actions if role=='pre' else 'flush_main' in actions
            return {'stage':error.stage,'winerror':error.winerror,'events':events,'both_objects_preserved':True}
        case('live_path_swap_'+role,'real_api_rejection',drift)
    case('missing_directory','real_api_rejection',lambda:refresh.windows_refresh_directory(root/'missing'),stage='open')
    def denied():
        path=directory('acl-negative');user=subprocess.check_output(['whoami'],text=True).strip()
        subprocess.run(['icacls',str(path),'/deny',user+':(W)'],check=True,capture_output=True,timeout=10)
        try:refresh.windows_refresh_directory(path)
        finally:
            subprocess.run(['icacls',str(path),'/remove:d',user],check=True,capture_output=True,timeout=10)
            # Restore verified through the required real write-access path.
            try:refresh.windows_refresh_directory(path)
            except Exception as exc:raise AssertionError('ACL restoration verification failed') from exc
    case('owned_acl_write_denial_restored','real_api_rejection',denied,stage='open')
    def collision():
        base=directory('collision');(base/'A').mkdir()
        try:refresh.create_hierarchy_and_refresh(base,('A','B'))
        finally:assert not (base/'A'/'B').exists()
    case('hierarchy_collision_no_child','real_api_rejection',collision,stage='mkdir')
    def hardlink_collision():
        base=directory('hardlink-collision');s=base/'source';t=base/'target';persist(s,b'new');persist(t,b'old')
        try:refresh.windows_publish_hard_link(s,t)
        finally:assert s.read_bytes()==b'new' and t.read_bytes()==b'old'
    case('hardlink_collision_preserves_bytes','real_api_rejection',hardlink_collision,stage='hard_link')
    if cross_root:
        cross_root=cross_root.resolve(strict=True);assert not any(cross_root.iterdir())
        first=refresh.handle_directory_identity(root);second=refresh.handle_directory_identity(cross_root)
        assert first[0]!=second[0], 'actual two volumes must differ'
        for operation in ('replace','hardlink'):
            def cross(operation=operation):
                s=root/('cross-'+operation);t=cross_root/('cross-'+operation);persist(s,b'cross source')
                if operation=='replace':persist(t,b'cross target')
                function=refresh.windows_replace_file if operation=='replace' else refresh.windows_publish_hard_link
                native_name='MoveFileExW' if operation=='replace' else 'CreateHardLinkW'
                actual=getattr(refresh,native_name);calls=[]
                def observed(*args):calls.append(args);return actual(*args)
                try:
                    with patch.object(refresh,native_name,observed):function(s,t)
                finally:
                    assert not calls and s.read_bytes()==b'cross source'
                    assert t.read_bytes()==b'cross target' if operation=='replace' else not t.exists()
            case('actual_cross_volume_'+operation,'real_api_rejection',cross,stage='cross_volume')
    else:results.append({'case':'actual_cross_volume','category':'not_run','passed':None,'reason':'no independently verified second volume supplied'})
    # Fault cases call actual native open/info/close but alter specified results.
    for fault,stage in [('close_pre','close_pre'),('close_pre_raise','close_pre'),('close_main','close_main'),
                        ('close_main_raise','close_main'),('close_post','close_post'),('close_post_raise','close_post'),
                        ('flush','flush_main'),('flush_and_close_main','flush_main'),('post_id','compare_post')]:
        def injected(fault=fault,stage=stage):
            observation,error,events=audit_refresh(directory('injected-'+fault),fault=fault)
            assert error and error.stage==stage
            actions=[e['action'] for e in events]
            if stage=='close_pre':assert 'flush_main' not in actions and 'open_post' not in actions
            if stage in ('close_main','flush_main'):assert 'open_post' not in actions
            if stage=='close_post':assert actions.count('open_post')==1
            if fault=='flush_and_close_main':assert [e['stage'] for e in error.aggregated]==['close_main']
            return {'stage':error.stage,'winerror':error.winerror,'aggregated':error.aggregated,'events':events,'actual_handles_closed':True}
        case('fault_'+fault,'injected_fault',injected)
    file=root/'reader.bin';persist(file,b'actual ReadFile no-follow bytes')
    def read_plain():
        before=refresh.handle_file_identity(file)
        assert reader._read_no_follow(file)==file.read_bytes()
        assert reader._read_no_follow(file)==file.read_bytes()
        assert refresh.handle_file_identity(file)==before
        return {'file_identity':before,'sha256':digest(file)}
    case('T004_reader_plain_stable','real_api_success',read_plain)
    case('T004_reader_directory','real_api_rejection',lambda:reader._read_no_follow(target),reader_match='type differs')
    case('T004_reader_junction_leaf','real_api_rejection',lambda:reader._read_no_follow(link),reader_match='reparse')
    persist(target/'member',b'junction target preserved')
    case('T004_reader_junction_ancestor','real_api_rejection',lambda:reader._read_no_follow(link/'member'),reader_match='reparse')
    def reader_share():
        # The real writer handle makes the actual readback open fail with sharing violation.
        writer_handle=refresh._open_directory_handle(file,refresh.GENERIC_WRITE)
        try:
            try:reader._read_no_follow(file)
            except reader.ReadbackError as exc:
                assert 'CreateFileW failed: 32' in str(exc);return {'stage':'sharing_open','winerror':32,'file_preserved':file.read_bytes()==b'actual ReadFile no-follow bytes'}
            raise AssertionError('reader allowed existing write access')
        finally:assert refresh.CloseHandle(writer_handle)
    case('T004_reader_write_sharing_refusal','real_api_rejection',reader_share)
    def reader_swap():
        replacement=root/'reader-replacement';persist(replacement,b'replacement bytes')
        actual=reader._WindowsIO.read;attempts=[]
        def observed(self,handle):
            data=actual(self,handle)
            if data and not attempts:
                ctypes.set_last_error(0);ok=refresh.MoveFileExW(str(replacement),str(file),9);error=ctypes.get_last_error()
                attempts.append({'return':int(ok),'GetLastError':error})
                assert not ok and error in (5,32)
            return data
        with patch.object(reader._WindowsIO,'read',observed):assert reader._read_no_follow(file)==b'actual ReadFile no-follow bytes'
        assert len(attempts)==1 and replacement.read_bytes()==b'replacement bytes'
        assert file.read_bytes()==b'actual ReadFile no-follow bytes'
        return {'actual_replace_attempt':attempts,'source_and_target_preserved':True}
    case('T004_reader_replace_while_handle_open','real_api_success',reader_swap)
    sources=[Path(refresh.__file__),Path(reader.__file__),Path(__file__)]
    output={'schema_version':2,'probe':'T005-PC022-strict-native','time':datetime.now().astimezone().isoformat(),
            'runtime':{'python':sys.version,'executable':sys.executable,'platform':platform.platform(),'root':str(root)},
            'source_sha256':{p.name:digest(p) for p in sources},'durability_claim':False,
            'results':results,'counts':{category:sum(r['category']==category for r in results) for category in ('real_api_success','real_api_rejection','injected_fault','not_run')},
            'failures':sum(r['passed'] is False for r in results),'sentinel_unchanged':digest(sentinel)==sentinel_sha,
            'canonical_absent':not canonical.exists()}
    (root.parent/'native-results.json').write_text(json.dumps(output,ensure_ascii=True,indent=2))
    print(json.dumps(output,ensure_ascii=True,separators=(',',':')))
    return 0 if not output['failures'] and output['sentinel_unchanged'] and output['canonical_absent'] else 1


if __name__=='__main__':
    if len(sys.argv) not in (2,3):raise RuntimeError('owned empty case directory plus optional verified cross-volume directory required')
    raise SystemExit(make_probe(Path(sys.argv[1]),Path(sys.argv[2]) if len(sys.argv)==3 else None))
