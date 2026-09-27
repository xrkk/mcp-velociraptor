"""Uninstalled, separately approved host safety checkpoint controller.

Test mode accepts only the local fake vmrun; this module is not wired into any
runtime and importing it has no side effects.
"""
from __future__ import annotations
import argparse,datetime,fcntl,hashlib,json,os,re,signal,stat,subprocess,sys,time,uuid
from pathlib import Path

VMRUN='/usr/bin/vmrun'
HEX=re.compile('[0-9a-f]{64}\\Z')
WINDOW_ACTIONS={
    'SAFETY_REHEARSAL':['bootstrap','qualify','confirm-guest','arm','finish-rehearsal','deadline'],
    'EPOCH8_BUSINESS':['bootstrap','qualify','confirm-guest','arm','deadline','commit'],
}

class GuardError(RuntimeError):pass

def digest(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def encoded(obj)->bytes:return (json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()
def strict_json(data:bytes):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise GuardError('duplicate JSON key')
            result[key]=value
        return result
    try:value=json.loads(data.decode('utf-8'),object_pairs_hook=pairs,
                         parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (UnicodeError,ValueError,RecursionError) as exc:raise GuardError('invalid JSON') from exc
    if type(value) is not dict:raise GuardError('JSON object required')
    return value
def fsync_dir(path:Path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def write_new(path:Path,obj):
    data=encoded(obj);fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        fsync_dir(path.parent)
    except BaseException:
        raise
def replace(path:Path,obj):
    tmp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    write_new(tmp,obj);os.replace(tmp,path);fsync_dir(path.parent)
def read(path:Path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):raise GuardError('non-plain guard file')
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise GuardError('guard file mode differs')
    return strict_json(path.read_bytes())
def no_symlink_chain(path:Path):
    if not path.is_absolute():raise GuardError('absolute protected path required')
    current=Path(path.anchor)
    for part in path.parts[1:]:
        current=current/part
        if stat.S_ISLNK(current.lstat().st_mode):raise GuardError('symlink in protected path')
def vmrun_bytes(path:Path,target):
    no_symlink_chain(path.parent)
    if target is None:
        no_symlink_chain(path);executable=path
    else:
        if type(target) is not str or not Path(target).is_absolute() or not stat.S_ISLNK(path.lstat().st_mode) or os.readlink(path)!=target:
            raise GuardError('vmrun link target differs')
        executable=Path(target);no_symlink_chain(executable)
    info=executable.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
        raise GuardError('vmrun executable identity differs')
    return executable.read_bytes()
def identity(pid:int):
    proc=Path('/proc')/str(pid)
    try:
        parts=(proc/'stat').read_text().rsplit(')',1)[1].split()
        if parts[0]=='Z':return None
        return {'pid':pid,'start_tick':int(parts[19]),'exe':os.readlink(proc/'exe'),
                'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'argv_sha256':digest((proc/'cmdline').read_bytes()),'cgroup_sha256':digest((proc/'cgroup').read_bytes())}
    except (OSError,ValueError,IndexError):return None

def snapshot_names(tree:str):
    lines=tree.splitlines()
    if not lines or not re.fullmatch(r'Total snapshots: [0-9]+',lines[0]):
        raise GuardError('snapshot tree header differs')
    names=[line.lstrip(' \t') for line in lines[1:]]
    if len(names)!=int(lines[0].split(': ',1)[1]) or any(not name or name!=name.strip() for name in names):
        raise GuardError('snapshot tree count/entry differs')
    return names

def running_count(output:str,vmx:str):
    lines=output.splitlines()
    if not lines or not re.fullmatch(r'Total running VMs: [0-9]+',lines[0]):
        raise GuardError('running VM list header differs')
    if len(lines)-1!=int(lines[0].split(': ',1)[1]):
        raise GuardError('running VM list count differs')
    return lines[1:].count(vmx)

def approval_binding(manifest):
    fields=('test_mode','window_scope','authorized_actions','vmx_sha256','vmx_device','vmx_inode','vmx_identity','vmx_transitions','vmrun_path','vmrun_target','vmrun_sha256','canonical_path',
            'canonical_sha256','epoch7_active_snapshot_name','epoch7_phase','state_dir','deadline_utc','min_free_bytes',
            'vmrun_timeout_seconds','max_actions','approved_guest_collector_sha256',
            'code_sha256','installer_sha256','interpreter_path','interpreter_sha256',
            'controller_install_path','unit_service_path','unit_timer_path')
    return {name:manifest[name] for name in fields}

def validate_action_scope(manifest):
    scope=manifest.get('window_scope')
    if type(scope) is not str or scope not in WINDOW_ACTIONS or manifest.get('authorized_actions')!=WINDOW_ACTIONS[scope]:
        raise GuardError('window/action scope differs')
    return scope

class Guard:
    def __init__(self,manifest_path:Path,approval_sha:str):
        no_symlink_chain(manifest_path.absolute())
        self.manifest_path=manifest_path.resolve(strict=True)
        self.manifest_sha=approval_sha
        raw=self.manifest_path.read_bytes()
        if digest(raw)!=approval_sha or not HEX.fullmatch(approval_sha):raise GuardError('manifest approval SHA differs')
        self.m=strict_json(raw);m=self.m
        required={'schema_version','kind','attempt_id','test_mode','window_scope','vmx','vmx_sha256','vmx_identity','vmx_transitions','vmrun_path','vmrun_target','canonical_path',
                  'canonical_sha256','epoch7_active_snapshot_name','epoch7_phase','state_dir','checkpoint_name','deadline_utc','min_free_bytes',
                  'vmrun_timeout_seconds','approved_guest_collector_sha256','code_sha256','retention','max_actions',
                  'approval_decision_sha256','approval_decision_path','authorized_actions',
                  'interpreter_path','interpreter_sha256','vmrun_sha256',
                  'controller_install_path','unit_service_path','unit_timer_path','vmx_device','vmx_inode',
                  'installer_sha256'}
        if set(m)!=required or type(m['schema_version']) is not int or m['schema_version']!=1 or m['kind']!='velo-g14-safety-guard-v1' or m['retention']!='KEEP_UNTIL_SEPARATE_DELETE_APPROVAL':
            raise GuardError('manifest shape/retention differs')
        try:canonical_attempt=str(uuid.UUID(m['attempt_id']))
        except (ValueError,TypeError,AttributeError) as exc:raise GuardError('attempt ID differs') from exc
        if canonical_attempt!=m['attempt_id']:raise GuardError('attempt UUID must be canonical')
        if not HEX.fullmatch(m['approval_decision_sha256']) or m['approval_decision_sha256']=='0'*64:
            raise GuardError('independent approval identity/action scope absent')
        validate_action_scope(m)
        if m['checkpoint_name']!='Snapshot G14-SAFETY-'+m['attempt_id']:
            raise GuardError('checkpoint name differs')
        if type(m['epoch7_active_snapshot_name']) is not str or not m['epoch7_active_snapshot_name']:
            raise GuardError('epoch7 active snapshot identity missing')
        if m['epoch7_phase'] not in ('PREPARATION_BASELINE','NETWORK_ACTIVE'):
            raise GuardError('epoch7 phase differs')
        if m['test_mode'] is True:
            if (not Path(m['state_dir']).resolve().is_relative_to(Path(__file__).resolve().parent)
                    or m['vmrun_path']!=str(Path(__file__).with_name('fake_vmrun_guard.py').resolve())
                    or m['vmrun_target'] is not None
                    or not Path(m['vmx']).resolve().is_relative_to(Path(__file__).resolve().parent)
                    or not Path(m['canonical_path']).resolve().is_relative_to(Path(__file__).resolve().parent)):
                raise GuardError('test paths escape isolated candidate root')
        elif m['test_mode'] is False:
            if (m['vmrun_path']!=VMRUN or m['vmrun_target']!='/usr/lib/vmware/bin/appLoader' or not Path(m['vmx']).is_absolute()
                    or not Path(m['canonical_path']).is_absolute()
                    or m['state_dir']!=f"/var/lib/velo-g14-guard/{m['attempt_id']}"
                    or m['controller_install_path']!=f"/usr/local/libexec/velo-g14-guard-{m['attempt_id']}.py"
                    or m['unit_service_path']!=f"/etc/systemd/system/velo-g14-guard@{m['attempt_id']}.service"
                    or m['unit_timer_path']!=f"/etc/systemd/system/velo-g14-guard@{m['attempt_id']}.timer"):
                raise GuardError('production target/adapter/storage differs')
            if os.geteuid()!=0:
                raise GuardError('production manifest requires root/0600')
        else:raise GuardError('test_mode must be bool')
        for name in ('approval_decision_sha256','interpreter_sha256','vmrun_sha256','code_sha256','installer_sha256','vmx_sha256','canonical_sha256','approved_guest_collector_sha256'):
            if type(m[name]) is not str or not HEX.fullmatch(m[name]):raise GuardError(f'{name} invalid')
        if type(m['min_free_bytes']) is not int or m['min_free_bytes']<0 or type(m['max_actions']) is not int or not 1<=m['max_actions']<=8 or type(m['vmrun_timeout_seconds']) is not int or not 1<=m['vmrun_timeout_seconds']<=90:
            raise GuardError('resource/action bounds invalid')
        if not m['test_mode'] and m['min_free_bytes']<32*1024**3:
            raise GuardError('production safety free-space budget too small')
        if type(m['vmx_device']) is not int or m['vmx_device']<0 or type(m['vmx_inode']) is not int or m['vmx_inode']<=0:
            raise GuardError('VMX file identity invalid')
        if (type(m['vmx_identity']) is not dict or set(m['vmx_identity'])!={'uuid.bios','displayName'}
                or any(type(value) is not str or not value for value in m['vmx_identity'].values())):
            raise GuardError('VMX stable identity approval differs')
        transitions=m['vmx_transitions']
        if type(transitions) is not list or len(transitions)>8:
            raise GuardError('VMX transition approval shape differs')
        for edge in transitions:
            if (type(edge) is not dict or set(edge)!={'action','from_sha256','to_sha256'}
                    or edge['action'] not in ('snapshot','stop','revertToSnapshot','start')
                    or any(type(edge[key]) is not str or not HEX.fullmatch(edge[key]) for key in ('from_sha256','to_sha256'))
                    or edge['from_sha256']==edge['to_sha256']):
                raise GuardError('VMX transition approval differs')
        if len({(edge['action'],edge['from_sha256']) for edge in transitions})!=len(transitions):
            raise GuardError('ambiguous VMX transition approval')
        try:due=datetime.datetime.fromisoformat(m['deadline_utc'].replace('Z','+00:00'))
        except (TypeError,AttributeError,ValueError) as exc:raise GuardError('deadline format invalid') from exc
        if due.tzinfo is None or due.utcoffset()!=datetime.timedelta(0):
            raise GuardError('deadline must be absolute UTC')
        self._approved_file(self.manifest_path,raw,approval_sha,'manifest')
        self.verify_approval()
        if Path(m['interpreter_path']).resolve()!=Path(sys.executable).resolve() or digest(Path(sys.executable).read_bytes())!=m['interpreter_sha256']:
            raise GuardError('interpreter identity differs')
        if digest(vmrun_bytes(Path(m['vmrun_path']),m['vmrun_target']))!=m['vmrun_sha256']:
            raise GuardError('vmrun code identity differs')
        self.root=Path(m['state_dir'])
        self.state_path=self.root/'state.json';self.owner_path=self.root/'owner.json';self.lock_path=self.root/'controller.lock'
    def require_action(self,action):
        if action not in self.m['authorized_actions']:
            raise GuardError('action outside approved window scope')
    def _approved_file(self,path,raw,expected,label):
        no_symlink_chain(path)
        info=path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or digest(raw)!=expected or (not self.m['test_mode'] and
                (info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600))):
            raise GuardError(f'{label} protected byte identity differs')
    def verify_approval(self):
        path=Path(self.m['approval_decision_path'])
        if not path.is_absolute():raise GuardError('approval path is not absolute')
        raw=path.read_bytes();self._approved_file(path,raw,self.m['approval_decision_sha256'],'decision')
        decision=strict_json(raw)
        expected={'kind':'velo-g14-safety-approval-v1','status':'APPROVED','attempt_id':self.m['attempt_id'],
                  'vmx':self.m['vmx'],'vmx_sha256':self.m['vmx_sha256'],
                  'checkpoint_name':self.m['checkpoint_name'],
                  'window_scope':self.m['window_scope'],'actions':self.m['authorized_actions'],
                  'manifest_binding':approval_binding(self.m)}
        if decision!=expected:raise GuardError('approval scope differs')
    def verify_external(self,path,expected_sha,*,kind,scope,receipt_path):
        if path is None or expected_sha is None or not HEX.fullmatch(expected_sha):
            raise GuardError('independent qualification approval missing')
        path=Path(path).absolute();no_symlink_chain(path)
        if path.is_relative_to(self.root):raise GuardError('qualification approval cannot come from state root')
        raw=path.read_bytes();self._approved_file(path,raw,expected_sha,'qualification approval')
        decision=strict_json(raw)
        expected={'kind':kind,'status':'APPROVED','attempt_id':self.m['attempt_id'],
                  'vmx':self.m['vmx'],'checkpoint_name':self.m['checkpoint_name'],
                  'collector_sha256':self.m['approved_guest_collector_sha256'],
                  'receipt_sha256':digest(receipt_path.read_bytes()),'scope':scope}
        if decision!=expected:raise GuardError('qualification approval scope/receipt differs')
    def require_root(self):
        info=self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or (not self.m['test_mode'] and info.st_uid!=0):
            raise GuardError('state root permissions differ')
    def check_vmx(self,action=None):
        path=Path(self.m['vmx']);no_symlink_chain(path);info=path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_dev!=self.m['vmx_device'] or info.st_ino!=self.m['vmx_inode']):
            raise GuardError('VMX byte identity differs')
        state=self.load();expected=state.get('vmx_current_sha256',self.m['vmx_sha256']) if state else self.m['vmx_sha256']
        raw=path.read_bytes();actual=digest(raw)
        try:
            vmx_text=raw.decode('utf-8')
        except UnicodeError as exc:raise GuardError('VMX text encoding differs') from exc
        values={}
        for line in vmx_text.splitlines():
            match=re.fullmatch(r'\s*([^=\s]+)\s*=\s*"([^"]*)"\s*',line)
            if match and match.group(1) in self.m['vmx_identity']:
                if match.group(1) in values:raise GuardError('duplicate VMX stable identity')
                values[match.group(1)]=match.group(2)
        if values!=self.m['vmx_identity']:raise GuardError('VMX stable identity differs')
        if actual==expected:return
        edge={'action':action,'from_sha256':expected,'to_sha256':actual}
        if action is None or edge not in self.m['vmx_transitions'] or not state or state.get('pending_operation')!=action:
            raise GuardError('unapproved VMX byte transition')
        state['vmx_current_sha256']=actual;self.save(state)
        self.append('APPROVED_VMX_TRANSITION',**edge)
    def check_fixed(self,canonical_sha=None):
        m=self.m
        vmx=Path(m['vmx']);canonical=Path(m['canonical_path']);no_symlink_chain(canonical)
        self.verify_approval();self.check_vmx()
        info=canonical.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):raise GuardError('canonical is not plain')
        if digest(canonical.read_bytes())!=(canonical_sha or m['canonical_sha256']) or canonical.with_name(canonical.name+'.next').exists():
            raise GuardError('canonical drift or .next')
        disk=os.statvfs(vmx.parent)
        if disk.f_bavail*disk.f_frsize<m['min_free_bytes']:
            raise GuardError('insufficient host free space')
        if digest(Path(__file__).read_bytes())!=m['code_sha256']:raise GuardError('guard code SHA differs')
        if digest(vmrun_bytes(Path(m['vmrun_path']),m['vmrun_target']))!=m['vmrun_sha256']:raise GuardError('vmrun code identity differs')
    def verify_journal(self):
        folder=self.root/'events'
        if not folder.exists():
            if self.state_path.exists():raise GuardError('event journal missing for state')
            return 0,'0'*64
        if folder.is_symlink() or stat.S_IMODE(folder.stat().st_mode)!=0o700:
            raise GuardError('event journal directory differs')
        files=sorted(folder.iterdir())
        previous='0'*64
        for index,path in enumerate(files,1):
            if path.name!=f'{index:06d}.json':raise GuardError('event sequence/gap differs')
            row=read(path)
            if set(row)!={'sequence','previous_sha256','event','facts','at_utc'} or row['sequence']!=index or row['previous_sha256']!=previous:
                raise GuardError('event chain differs')
            previous=digest(path.read_bytes())
        return len(files),previous
    def append(self,event,**facts):
        folder=self.root/'events';folder.mkdir(mode=0o700,exist_ok=True)
        count,previous=self.verify_journal();index=count+1
        write_new(folder/f'{index:06d}.json',{'sequence':index,'previous_sha256':previous,'event':event,'facts':facts,'at_utc':datetime.datetime.now(datetime.UTC).isoformat()})
        fsync_dir(folder)
    def load(self):
        if not self.state_path.exists():return None
        state=read(self.state_path)
        if (state.get('attempt_id')!=self.m['attempt_id'] or state.get('manifest_sha256')!=self.manifest_sha
                or state.get('test_mode') is not self.m['test_mode'] or state.get('checkpoint_name')!=self.m['checkpoint_name']):
            raise GuardError('state scope differs')
        return state
    def save(self,state):replace(self.state_path,state) if self.state_path.exists() else write_new(self.state_path,state)
    def acquire(self,takeover=False):
        self.require_root()
        if self.state_path.exists() and not self.lock_path.exists():
            raise GuardError('persistent lock missing for existing state')
        fd=os.open(self.lock_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            if not takeover:os.close(fd);raise GuardError('guard lock held')
            owner=read(self.owner_path) if self.owner_path.exists() else None
            current=identity(owner['identity']['pid']) if owner and owner.get('attempt_id')==self.m['attempt_id'] and owner.get('role')=='controller' else None
            state=self.load()
            if not owner or current!=owner['identity'] or not state or state.get('pending_operation') is not None or state.get('child_identity') is not None or self._restore_open(state) or not self._owner_matches(owner['identity']['pid']):
                os.close(fd);raise GuardError('INDETERMINATE_LOCK_OWNER_OR_CHILD')
            if identity(owner['identity']['pid'])!=owner['identity']:
                os.close(fd);raise GuardError('INDETERMINATE_OWNER_CHANGED')
            os.kill(owner['identity']['pid'],signal.SIGTERM)
            for _ in range(30):
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:time.sleep(.1)
            else:
                if identity(owner['identity']['pid'])==owner['identity']:
                    os.kill(owner['identity']['pid'],signal.SIGKILL)
                for _ in range(30):
                    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                    except BlockingIOError:time.sleep(.1)
                else:os.close(fd);raise GuardError('INDETERMINATE_LOCK_STUCK')
        self.fd=fd
        self.verify_journal()
        replace(self.owner_path,{'attempt_id':self.m['attempt_id'],'role':'deadline' if takeover else 'controller','identity':identity(os.getpid())}) if self.owner_path.exists() else write_new(self.owner_path,{'attempt_id':self.m['attempt_id'],'role':'deadline' if takeover else 'controller','identity':identity(os.getpid())})
    def _owner_matches(self,pid):
        try:argv=(Path('/proc')/str(pid)/'cmdline').read_bytes().split(b'\0')[:-1]
        except OSError:return False
        expected=[self.m['interpreter_path'],str(Path(__file__).resolve()),'--manifest',str(self.manifest_path),'--approval-sha',self.manifest_sha]
        return [x.decode(errors='replace') for x in argv[:len(expected)]]==expected and len(argv)>len(expected)
    def release(self):
        fcntl.flock(self.fd,fcntl.LOCK_UN);os.close(self.fd)
    @staticmethod
    def _restore_open(state):
        txn=state.get('restore_transaction')
        return txn is not None and (type(txn) is not dict or txn.get('stage')!='COMPLETE')
    def _restore_stage(self,stage):
        state=self.load();txn=state['restore_transaction'];txn['stage']=stage
        self.save(state);self.append('RESTORE_TRANSACTION_STAGE',transaction_id=txn['id'],stage=stage)
    def _crash_point(self,point):
        if self.m['test_mode'] and os.environ.get('FAKE_GUARD_CRASH_RESTORE_AT')==point:os._exit(98)
    def vmrun(self,action,*args):
        allowed={'list','listSnapshots','snapshot','stop','revertToSnapshot','start'}
        if action not in allowed:raise GuardError('vmrun action not allowlisted')
        vmx=self.m['vmx'];name=self.m['checkpoint_name']
        argv={'list':['list'],'listSnapshots':['listSnapshots',vmx,'showTree'],
              'snapshot':['snapshot',vmx,name],'stop':['stop',vmx,'soft'],
              'revertToSnapshot':['revertToSnapshot',vmx,name],
              'start':['start',vmx,'nogui']}[action]
        state=self.load()
        self.verify_approval();self.check_vmx()
        if action not in ('list','listSnapshots'):
            if action=='snapshot':
                self.require_action('bootstrap')
                if not state or state['status']!='BOOTSTRAP_PENDING':raise GuardError('snapshot outside bootstrap')
            elif action in ('stop','revertToSnapshot','start'):
                scope_action={'CREATED_UNQUALIFIED':'qualify','ARMED':'deadline'}.get(state.get('status') if state else None)
                if scope_action is None:raise GuardError('restore outside approved state')
                self.require_action(scope_action)
            if not state or state.get('pending_operation') is not None:raise GuardError('pending/unknown operation')
            if state['action_count']>=self.m['max_actions']:raise GuardError('action budget exhausted')
            state['pending_operation']=action;state['action_count']+=1;self.save(state);self.append('VMRUN_INTENT',action=action,argv=argv)
        proc=subprocess.Popen([self.m['vmrun_path'],'-T','ws',*argv],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        if action not in ('list','listSnapshots'):
            state=self.load();state['child_identity']=identity(proc.pid);self.save(state)
        try:stdout,stderr=proc.communicate(timeout=self.m['vmrun_timeout_seconds'])
        except subprocess.TimeoutExpired:
            proc.kill();proc.communicate()
            self.append('VMRUN_TIMEOUT_UNKNOWN',action=action,pid=proc.pid)
            raise GuardError('INDETERMINATE_VMRUN_TIMEOUT')
        result={'action':action,'argv':argv,'exit_code':proc.returncode,'stdout':stdout.decode(errors='replace'),
                'stderr':stderr.decode(errors='replace'),'stdout_sha256':digest(stdout),'stderr_sha256':digest(stderr)}
        self.append('VMRUN_RESPONSE',**result)
        self.check_vmx(action if action not in ('list','listSnapshots') else None)
        if proc.returncode!=0:raise GuardError('INDETERMINATE_VMRUN_NONZERO')
        if action not in ('list','listSnapshots'):
            state=self.load();state['pending_operation']=None;state['child_identity']=None;self.save(state)
        return result['stdout']
    def preflight(self):
        self.check_fixed()
        if running_count(self.vmrun('list'),self.m['vmx'])!=1:raise GuardError('VMX not uniquely running')
        return self.vmrun('listSnapshots')
    def checkpoint_metadata(self):
        path=Path(self.m['vmx']).with_suffix('.vmsd')
        lines=path.read_text().splitlines();values={}
        for line in lines:
            if ' = ' in line:
                key,value=line.split(' = ',1);values[key.strip()]=value.strip().strip('"')
        matches=[]
        for key,value in values.items():
            found=re.fullmatch(r'snapshot([0-9]+)\.displayName',key)
            if found and value==self.m['checkpoint_name']:matches.append(found.group(1))
        if len(matches)!=1:raise GuardError('safety checkpoint metadata not unique')
        n=matches[0];uid=values.get(f'snapshot{n}.uid');marker=values.get(f'snapshot{n}.filename')
        if not uid or not marker or '/' in marker or '\\' in marker or not marker.endswith('.vmsn'):
            raise GuardError('safety marker/UID differs')
        vm_dir=Path(self.m['vmx']).parent
        memory=vm_dir/(marker[:-5]+'.vmem')
        marker_path=vm_dir/marker
        for item in (memory,marker_path):
            info=item.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size==0:
                raise GuardError('safety memory/marker image absent')
        if not values.get(f'snapshot{n}.disk0.fileName') or not values.get(f'snapshot{n}.parent'):
            raise GuardError('safety parent/disk-chain metadata absent')
        return {'uid':uid,'marker':marker,'parent':values.get(f'snapshot{n}.parent'),
                'disk0':values[f'snapshot{n}.disk0.fileName'],
                'marker_sha256':digest(marker_path.read_bytes()),'memory_bytes':memory.stat().st_size}
    def bootstrap(self):
        self.require_action('bootstrap')
        if self.load() is not None:raise GuardError('attempt already exists')
        self.check_fixed()
        self.save({'status':'BOOTSTRAP_PENDING','pending_operation':None,'child_identity':None,'action_count':0,
                   'attempt_id':self.m['attempt_id'],'manifest_sha256':self.manifest_sha,
                   'test_mode':self.m['test_mode'],'checkpoint_name':self.m['checkpoint_name']})
        self.append('BOOTSTRAP_INTENT',checkpoint=self.m['checkpoint_name'])
        tree=self.preflight()
        if snapshot_names(tree).count(self.m['checkpoint_name'])!=0:raise GuardError('checkpoint name already exists')
        self.vmrun('snapshot')
        self.check_fixed()
        tree=self.vmrun('listSnapshots')
        if snapshot_names(tree).count(self.m['checkpoint_name'])!=1:raise GuardError('INDETERMINATE_CHECKPOINT_READBACK')
        metadata=self.checkpoint_metadata()
        state=self.load();state['status']='CREATED_UNQUALIFIED';state['checkpoint_metadata']=metadata;self.save(state);self.append('CHECKPOINT_CREATED_UNQUALIFIED',tree_sha256=digest(tree.encode()),metadata=metadata)
        return state['status']
    def revert_once(self):
        prior=self.load()
        if not prior or self._restore_open(prior):
            raise GuardError('restore transaction already recorded')
        if prior.get('restore_transaction') is not None and prior['status']!='ARMED':
            raise GuardError('prior restore transaction cannot be replaced')
        self.check_fixed()
        tree=self.preflight()
        if snapshot_names(tree).count(self.m['checkpoint_name'])!=1:raise GuardError('checkpoint not unique')
        state=self.load()
        if state.get('restore_transaction') is not None:
            state.setdefault('restore_history',[]).append(state['restore_transaction'])
        state['restore_transaction']={'id':str(uuid.uuid4()),'attempt_id':self.m['attempt_id'],
            'checkpoint_name':self.m['checkpoint_name'],'scope':state['status'],
            'stage':'BEFORE_STOP','action_count_at_start':state['action_count']}
        self.save(state);self.append('RESTORE_TRANSACTION_INTENT',transaction=state['restore_transaction'])
        self._crash_point('after_transaction_intent')
        self.vmrun('stop');self._crash_point('after_stop_response')
        self._restore_stage('STOP_CONFIRMED');self._crash_point('after_stop_stage')
        self._restore_stage('BEFORE_REVERT');self._crash_point('before_revert')
        self.vmrun('revertToSnapshot');self._crash_point('after_revert_response')
        self._restore_stage('REVERT_CONFIRMED');self._crash_point('after_revert_stage')
        running=running_count(self.vmrun('list'),self.m['vmx'])
        if running>1:raise GuardError('VMX running list ambiguous after revert')
        if running==0:
            self._restore_stage('BEFORE_START');self._crash_point('before_start')
            self.vmrun('start');self._crash_point('after_start_response')
        else:
            self._restore_stage('RUNNING_AFTER_REVERT');self._crash_point('before_start')
        self._restore_stage('START_CONFIRMED');self._crash_point('after_start_stage')
        tree=self.preflight()
        if snapshot_names(tree).count(self.m['checkpoint_name'])!=1:raise GuardError('INDETERMINATE_POST_RESTORE')
        metadata=self.checkpoint_metadata()
        state=self.load()
        if state.get('checkpoint_metadata')!=metadata:raise GuardError('checkpoint metadata drift')
        self._restore_stage('READBACK_CONFIRMED');self._crash_point('before_final_state')
        state=self.load();state['status']='HOST_RESTORED_PENDING_GUEST'
        state['restore_transaction']['stage']='COMPLETE';self.save(state)
        self.append('HOST_RESTORE_VERIFIED',tree_sha256=digest(tree.encode()))
        return state['status']
    def qualify(self):
        self.require_action('qualify')
        state=self.load()
        if not state or state['status']!='CREATED_UNQUALIFIED':raise GuardError('checkpoint not newly created')
        return self.revert_once()
    def confirm_guest(self,decision_path=None,decision_sha=None):
        self.require_action('confirm-guest')
        state=self.load();path=self.root/'guest-reentry.json'
        if not state or state['status']!='HOST_RESTORED_PENDING_GUEST':raise GuardError('host restore not verified')
        receipt=read(path)
        self.verify_external(decision_path,decision_sha,kind='velo-g14-guest-qualification-approval-v1',
                             scope='GUEST_REENTRY_ONLY',receipt_path=path)
        expected={'kind':'velo-g14-guest-reentry-v1','attempt_id':self.m['attempt_id'],
                  'checkpoint_name':self.m['checkpoint_name'],'vmx':self.m['vmx'],
                  'collector_sha256':self.m['approved_guest_collector_sha256'],
                  'service_and_frontend_healthy':True,'secrets_file_readback':True}
        original_keys=('management_reentry_original_sha256','health_original_sha256',
                       'secrets_readback_original_sha256')
        if any(type(receipt.get(key)) is not str or not HEX.fullmatch(receipt[key]) or receipt[key]=='0'*64 for key in original_keys):
            raise GuardError('guest original identities absent')
        if {key:value for key,value in receipt.items() if key not in original_keys}!=expected or set(receipt)!=set(expected)|set(original_keys):
            raise GuardError('guest reentry receipt differs')
        state['status']='QUALIFIED';self.save(state);self.append('QUALIFIED_GUEST_READBACK',receipt_sha256=digest(path.read_bytes()))
        return state['status']
    def arm(self):
        self.require_action('arm')
        state=self.load()
        if not state or state['status']!='QUALIFIED':raise GuardError('checkpoint not qualified')
        self.check_fixed();state['status']='ARMED';self.save(state);self.append('ARMED',deadline=self.m['deadline_utc'])
        return state['status']
    def finish_rehearsal(self,decision_path=None,decision_sha=None):
        self.require_action('finish-rehearsal')
        state=self.load();finish_path=self.root/'safety-finish-receipt.json'
        if state and state['status']=='SAFETY_REHEARSAL_COMPLETE':
            if not finish_path.exists() or digest(finish_path.read_bytes())!=state.get('finish_receipt_sha256'):
                raise GuardError('safety finish receipt lost or changed')
            return state['status']
        if not state or state['status']!='ARMED' or self._restore_open(state) or state.get('pending_operation') is not None or state.get('child_identity') is not None:
            raise GuardError('safety rehearsal is not ready to finish')
        health_path=self.root/'safety-finish-health.json'
        health=read(health_path)
        self.verify_external(decision_path,decision_sha,kind='velo-g14-safety-finish-approval-v1',
                             scope='SAFETY_REHEARSAL_FINISH_ONLY',receipt_path=health_path)
        expected={'kind':'velo-g14-safety-finish-health-v1','attempt_id':self.m['attempt_id'],
                  'checkpoint_name':self.m['checkpoint_name'],'vmx':self.m['vmx'],
                  'collector_sha256':self.m['approved_guest_collector_sha256'],
                  'service_and_frontend_healthy':True,'secrets_file_readback':True}
        original_keys=('management_reentry_original_sha256','health_original_sha256','secrets_readback_original_sha256')
        if (set(health)!=set(expected)|set(original_keys)
                or {key:health[key] for key in expected}!=expected
                or any(type(health[key]) is not str or not HEX.fullmatch(health[key]) or health[key]=='0'*64 for key in original_keys)):
            raise GuardError('safety finish health receipt differs')
        self.check_fixed()
        canonical=strict_json(Path(self.m['canonical_path']).read_bytes())
        active=canonical.get('active_snapshot')
        if type(canonical.get('epoch')) is not int or canonical['epoch']!=7 or canonical.get('phase')!=self.m['epoch7_phase'] or type(active) is not dict or active.get('name')!=self.m['epoch7_active_snapshot_name']:
            raise GuardError('epoch7 canonical readback differs')
        finish={'kind':'velo-g14-safety-finish-receipt-v1','attempt_id':self.m['attempt_id'],
                'checkpoint_name':self.m['checkpoint_name'],'manifest_sha256':self.manifest_sha,
                'health_receipt_sha256':digest(health_path.read_bytes()),
                'external_decision_sha256':decision_sha,'epoch7_canonical_sha256':self.m['canonical_sha256'],
                'timer_disarm_eligible':True}
        if finish_path.exists():
            if read(finish_path)!=finish:raise GuardError('pending safety finish receipt differs')
        else:write_new(finish_path,finish)
        if self.m['test_mode'] and os.environ.get('FAKE_GUARD_CRASH_AFTER_FINISH_RECEIPT')=='1':os._exit(97)
        state['status']='SAFETY_REHEARSAL_COMPLETE';state['timer_disarm_eligible']=True
        state['finish_receipt_sha256']=digest(finish_path.read_bytes());self.save(state)
        self.append('SAFETY_REHEARSAL_COMPLETE',receipt_sha256=state['finish_receipt_sha256'])
        return state['status']
    def deadline(self):
        self.require_action('deadline')
        state=self.load()
        if not state:raise GuardError('no attempt')
        if self._restore_open(state):
            if state['status']!='INDETERMINATE':
                state['status']='INDETERMINATE';self.save(state);self.append('INDETERMINATE_RESTORE_TRANSACTION')
            return 'INDETERMINATE'
        if state['status']=='SAFETY_REHEARSAL_COMPLETE':
            finish_path=self.root/'safety-finish-receipt.json'
            if not finish_path.exists() or digest(finish_path.read_bytes())!=state.get('finish_receipt_sha256'):
                raise GuardError('safety finish receipt lost or changed')
            return state['status']
        if state['status'] in ('COMMITTED','HOST_RESTORED_PENDING_GUEST','INDETERMINATE'):return state['status']
        if (self.root/'safety-finish-receipt.json').exists():return 'FINISH_PENDING_RECONCILIATION'
        if state['status']!='ARMED':raise GuardError('UNQUALIFIED_SAFETY_IMAGE')
        due=datetime.datetime.fromisoformat(self.m['deadline_utc'].replace('Z','+00:00'))
        if datetime.datetime.now(datetime.UTC)<due:return 'NOT_EXPIRED'
        if state['pending_operation'] is not None or state['child_identity'] is not None:
            state['status']='INDETERMINATE';self.save(state);self.append('INDETERMINATE_PRIOR_OPERATION');return state['status']
        try:return self.revert_once()
        except GuardError as exc:
            state=self.load();state['status']='INDETERMINATE';self.save(state);self.append('INDETERMINATE_RECOVERY',reason=str(exc));return state['status']
    def commit(self,decision_path=None,decision_sha=None):
        self.require_action('commit')
        if (self.root/'safety-finish-receipt.json').exists():raise GuardError('safety finish precludes business commit')
        state=self.load();receipt=read(self.root/'commit-qualification.json')
        if not state or state['status']!='ARMED' or self._restore_open(state) or state['pending_operation'] is not None:
            raise GuardError('not eligible to commit')
        expected={'kind','attempt_id','collector_sha256','epoch8_committed','guest_and_host_healthy',
                  'epoch8_canonical_sha256','transition_receipt_sha256','vmx','active_snapshot_name',
                  'guest_health_original_sha256','host_health_original_sha256'}
        if set(receipt)!=expected or receipt['kind']!='velo-g14-commit-qualification-v1' or receipt['attempt_id']!=self.m['attempt_id'] or receipt['collector_sha256']!=self.m['approved_guest_collector_sha256'] or receipt['vmx']!=self.m['vmx'] or receipt['epoch8_committed'] is not True or receipt['guest_and_host_healthy'] is not True or not HEX.fullmatch(receipt['epoch8_canonical_sha256']) or not HEX.fullmatch(receipt['transition_receipt_sha256']) or type(receipt['active_snapshot_name']) is not str or not receipt['active_snapshot_name'] or any(type(receipt[key]) is not str or not HEX.fullmatch(receipt[key]) or receipt[key]=='0'*64 for key in ('guest_health_original_sha256','host_health_original_sha256')):
            raise GuardError('commit qualification differs')
        self.verify_external(decision_path,decision_sha,kind='velo-g14-commit-approval-v1',
                             scope='EPOCH8_COMMIT_ONLY',receipt_path=self.root/'commit-qualification.json')
        state['pending_operation']='commit';self.save(state);self.append('COMMIT_INTENT')
        self.check_fixed(canonical_sha=receipt['epoch8_canonical_sha256'])
        canonical=strict_json(Path(self.m['canonical_path']).read_bytes())
        active=canonical.get('active_snapshot')
        if canonical.get('epoch')!=8 or canonical.get('phase')!='NETWORK_ACTIVE' or type(active) is not dict or active.get('name')!=receipt['active_snapshot_name']:
            raise GuardError('epoch8 canonical identity differs')
        state['status']='COMMITTED';state['pending_operation']=None;self.save(state)
        self.append('COMMITTED',receipt_sha256=digest((self.root/'commit-qualification.json').read_bytes()))
        return state['status']

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--manifest',type=Path,required=True);ap.add_argument('--approval-sha',required=True)
    ap.add_argument('command',choices=['check','bootstrap','qualify','confirm-guest','arm','finish-rehearsal','deadline','commit','hold'])
    ap.add_argument('--hold-seconds',type=int,default=0)
    ap.add_argument('--external-decision',type=Path);ap.add_argument('--external-sha')
    args=ap.parse_args()
    guard=Guard(args.manifest,args.approval_sha)
    if args.command=='check':
        guard.check_fixed()
        if guard.root.exists():guard.require_root();guard.verify_journal()
        print(json.dumps({'state':guard.load(),'check':'PASS'}));return 0
    if args.command!='hold':guard.require_action(args.command)
    if args.command=='deadline':
        due=datetime.datetime.fromisoformat(guard.m['deadline_utc'].replace('Z','+00:00'))
        if datetime.datetime.now(datetime.UTC)<due:
            print(json.dumps({'result':'NOT_EXPIRED'}));return 0
    guard.acquire(takeover=args.command=='deadline')
    try:
        if args.command=='hold':
            if not guard.m['test_mode'] or not 0<args.hold_seconds<=10:raise GuardError('hold only bounded fake test')
            time.sleep(args.hold_seconds);result='HELD'
        elif args.command=='confirm-guest':result=guard.confirm_guest(args.external_decision,args.external_sha)
        elif args.command=='finish-rehearsal':result=guard.finish_rehearsal(args.external_decision,args.external_sha)
        elif args.command=='commit':result=guard.commit(args.external_decision,args.external_sha)
        else:result=getattr(guard,args.command.replace('-','_'))()
        print(json.dumps({'result':result}));return 0
    finally:guard.release()
if __name__=='__main__':
    try:raise SystemExit(main())
    except (GuardError,OSError,ValueError,subprocess.SubprocessError) as exc:
        print(json.dumps({'error':str(exc)}),file=sys.stderr);raise SystemExit(3)
