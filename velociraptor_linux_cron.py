"""Bounded single-definition trusted crond source, never a boot-transition claim.

A frozen caller-controlled daemon, actual leased definition read, daemon dispatch
log and live executed inode bind one ordinary job. This collector never launches
or installs the daemon/job. Scope admission reuses the shared professional path.
"""
import base64
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import threading
import time
from velociraptor_linux_scheduler import FollowingCollector, need, process, sha

SOURCE = 'MalTrace.Cron.v1'


def validate_profile(c):
    fields={'directory','payload','crontab','mechanism','schedule','manager','launcher',
            'daemon_argv','manager_unit','manager_unit_file','manager_unit_sha256',
            'log','window_seconds','reboot_marker_absent'}
    need(set(c)==fields and c['mechanism']=='cron' and c['schedule'] in ('calendar','@reboot'), 'cron profile fields')
    need(type(c['window_seconds']) is int and 1<=c['window_seconds']<=(85 if c['schedule']=='calendar' else 30), 'cron observation bound')
    directory=Path(c['directory']);need(directory.is_absolute() and not directory.is_symlink(), 'cron directory')
    need(re.fullmatch(r'[a-zA-Z0-9_-]{1,30}',c['crontab']) and c['crontab']!=c['payload']
         and re.fullmatch(r'[a-zA-Z0-9_-]{1,30}',c['payload']), 'cron flat names')
    m,l=c['manager'],c['launcher']
    need(m['pid']==l['pid'] and m['birth']==l['birth'] and m['uids']==l['uids']==[0]*4
         and m['gids']==l['gids']==[0]*4 and m['pid']>1, 'trusted daemon launcher identity')
    need(c['daemon_argv']==[m['image'],'crond','-f','-l','0','-L',c['log'],'-c',c['directory']], 'bounded private crond argv')
    need(re.fullmatch(r'[a-zA-Z0-9_-]{1,24}\.service',c['manager_unit'])
         and c['manager_unit_file']=='/run/systemd/system/'+c['manager_unit']
         and re.fullmatch(r'[a-f0-9]{64}',c['manager_unit_sha256'])
         and re.fullmatch(r'[a-f0-9]{64}',m['image_sha256']), 'managed daemon pin')
    need(Path(c['log']).parent==directory.parent and c['reboot_marker_absent'] is True, 'private log/startup marker required')


def protected(path):
    p=Path(path)
    for parent in [p,*p.parents]:
        s=parent.lstat();need(not stat.S_ISLNK(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'unprotected cron source')
    return p


class CronCollector(FollowingCollector):
    def __init__(self,c,output,binding,root,credentials,client):
        validate_profile(c)
        self.config,self.binding,self.root=c,binding,root
        self.credentials,self.client=credentials,client
        self.follow_attempted=False
        self.directory=Path(c['directory']);need(not list(self.directory.iterdir()),'cron spool starts empty')
        self.directory_stat=self.directory.stat()
        before=process(c['launcher']['pid'])
        need(before==c['launcher'],'cron launcher drift')
        state=(Path('/proc')/str(before['pid'])/'status').read_text()
        need(re.search(r'^State:\s+T ',state,re.M),'daemon launcher must be stopped before exec')
        unit=protected(c['manager_unit_file'])
        need(sha(unit.read_bytes())==c['manager_unit_sha256'],'managed daemon unit drift')
        log=protected(c['log']);need(log.stat().st_size==0,'old daemon log')
        need(not Path('/var/run/crond.reboot').exists() and not Path('/var/run/crond.pid').exists(),'foreign cron marker/pidfile')
        self.log_stat=log.stat()
        self.output=Path(output);self.output.mkdir(mode=0o700)
        self.stream=(self.output/'raw.ndjson').open('xb',buffering=0);os.chmod(self.output/'raw.ndjson',0o600)
        self.lock=threading.Lock();self.records,self.leases,self.execs=[],{},[]
        self.error,self.closed,self.lease_broken=None,False,False
        self.finish_event=threading.Event();self.manager=None;self.fd=-1;self.thread=None
        self.old_sigio=signal.getsignal(signal.SIGIO);self.deadline=time.monotonic()+90
        self.invocation=None;self.last_tick=0
        self.record('intent',source=SOURCE,config=c,binding=binding,root=root,
                    directory_inode=self.directory_stat.st_ino,directory_device=self.directory_stat.st_dev)
        self.record('fresh',launcher=before,empty_spool=True,log_inode=self.log_stat.st_ino,
                    log_device=self.log_stat.st_dev,reboot_marker_absent=True,pidfile_absent=True)
        try:
            libc=C.CDLL(None,use_errno=True)
            libc.fanotify_init.argtypes=[C.c_uint,C.c_uint]
            libc.fanotify_mark.argtypes=[C.c_int,C.c_uint,C.c_uint64,C.c_int,C.c_char_p]
            self.fd=libc.fanotify_init(0x4|0x1|0x2,os.O_RDONLY|os.O_CLOEXEC|os.O_LARGEFILE)
            if self.fd<0:raise OSError(C.get_errno(),'fanotify_init')
            if libc.fanotify_mark(self.fd,0x1,0x10000|0x40000|0x8|0x8000000,-100,str(self.directory).encode())<0:
                raise OSError(C.get_errno(),'fanotify_mark')
            signal.signal(signal.SIGIO,lambda *_:setattr(self,'lease_broken',True))
            self.thread=threading.Thread(target=self.drain,name='bounded-cron-evidence');self.thread.start()
            self.record('ready',deadline_ns=time.monotonic_ns()+90*10**9)
        except BaseException:
            self.close();raise

    def tick(self):
        need(not self.error,self.error or 'cron source failed')
        if time.monotonic()-self.last_tick<.05:return
        self.last_tick=time.monotonic()
        c=self.config
        for old,file in list(self.execs):
            if old['parent_pid']!=c['manager']['pid'] or file['path']!=str(self.directory/c['payload']):continue
            try:actor=process(old['pid'])
            except FileNotFoundError:continue
            if actor['birth']!=old['birth']:raise ValueError('cron payload PID reused')
            if actor['image']!=file['path'] or actor['cmdline']!=[file['path']]:continue
            if self.invocation is not None:
                need((actor['pid'],actor['birth'])==self.invocation,'second cron invocation');continue
            daemon=process(c['manager']['pid'])
            need(all(daemon[k]==c['manager'][k] for k in ('pid','birth','uids','gids','groups','image','image_sha256'))
                 and daemon['cmdline']==c['daemon_argv'],'daemon image/argv drift')
            log=protected(c['log']);s=log.stat()
            need((s.st_ino,s.st_dev)==(self.log_stat.st_ino,self.log_stat.st_dev) and s.st_size<=1024*1024,'daemon log replaced')
            raw=log.read_bytes();line='USER '+c['crontab']+' pid '+str(actor['pid'])+' cmd exec '+file['path']
            # BusyBox pads the PID field; normalize spaces only, preserve command.
            matches=[v for v in raw.decode().splitlines() if re.sub(r'\s+',' ',v).endswith(line)]
            if not matches:continue
            need(len(matches)==1,'ambiguous daemon dispatch')
            marker=protected('/run/crond.reboot');ms=marker.stat()
            need(ms.st_size==0 and ms.st_mode&0o777==0,'foreign reboot marker')
            pidfile=protected('/run/crond.pid');need(pidfile.read_text().strip()==str(daemon['pid']),'foreign cron PID file')
            table=self.directory/c['crontab'];ts=table.stat()
            need(ts.st_uid==0 and ts.st_mode&0o777==0o600,'daemon-loaded table owner/mode')
            self.invocation=(actor['pid'],actor['birth'])
            self.record('cron-invocation',actor=actor,daemon=daemon,log_base64=base64.b64encode(raw).decode(),
                        log_inode=s.st_ino,log_device=s.st_dev,dispatch_line=matches[0],
                        marker=dict(inode=ms.st_ino,device=ms.st_dev,uid=ms.st_uid,size=ms.st_size,mode=ms.st_mode),
                        table_owner=ts.st_uid,table_mode=ts.st_mode&0o777,wall_ns=time.time_ns())
        self.admit()

    def close(self):
        if self.closed:return
        try:
            if self.thread is not None:
                c=self.config;live=process(c['manager']['pid'])
                # A failure before daemon exec may leave the exact trusted launcher.
                expected=c['manager'] if live['image']==c['manager']['image'] else c['launcher']
                need(all(live[k]==expected[k] for k in ('pid','birth','uids','gids','groups','image','image_sha256')),'cleanup daemon drift')
                unit=protected(c['manager_unit_file']);need(sha(unit.read_bytes())==c['manager_unit_sha256'],'cleanup unit drift')
                r=subprocess.run(['/usr/bin/systemctl','show',c['manager_unit'],'-p','MainPID,FragmentPath'],capture_output=True,text=True,timeout=5)
                props=dict(x.split('=',1) for x in r.stdout.splitlines())
                need(r.returncode==0 and props==dict(MainPID=str(live['pid']),FragmentPath=c['manager_unit_file']),'cleanup ownership unknown')
                r=subprocess.run(['/usr/bin/systemctl','stop',c['manager_unit']],capture_output=True,text=True,timeout=10)
                self.record('owned-daemon-stop',rc=r.returncode,stdout=r.stdout,stderr=r.stderr)
                need(r.returncode==0,'owned cron stop unknown')
        except BaseException as e:self.error=self.error or 'CLEANUP_UNKNOWN:'+str(e)
        self.finish_event.set()
        if self.thread:self.thread.join(2);need(not self.thread.is_alive(),'cron drain stop unknown')
        elif self.fd>=0:os.close(self.fd);self.fd=-1
        signal.signal(signal.SIGIO,self.old_sigio)
        self.record('closed',error=self.error,lease_broken=self.lease_broken);os.fsync(self.stream.fileno());self.stream.close();self.closed=True


def qualify(rows,*,config,binding,root,credentials,kernel,boundary_ns):
    c=config;validate_profile(c)
    need(rows and [r['monotonic_ns'] for r in rows]==sorted(r['monotonic_ns'] for r in rows),'cron order')
    kinds={}
    for i,r in enumerate(rows):kinds.setdefault(r['kind'],[]).append((i+1,r))
    for k in ('intent','fresh','ready','cron-invocation'):need(len(kinds.get(k,[]))==1,'missing/duplicate '+k)
    intent,fresh,fire=[kinds[k][0][1] for k in ('intent','fresh','cron-invocation')]
    need(intent['source']==SOURCE and intent['config']==c and intent['binding']==binding and intent['root']==root,'cron independent expectation mismatch')
    need(root['boot_id']==binding['boot_id'] and fresh['launcher']==c['launcher'] and fresh['empty_spool']
         and fresh['reboot_marker_absent'] and fresh['pidfile_absent'],'cron startup expectation mismatch')
    need(credentials['uids'][1]>0 and len(set(credentials['uids']))==len(set(credentials['gids']))==1,'ordinary cron identity required')
    root_key=(root['pid'],root['start_time'])
    def key(a):return a['pid'],a['birth']
    def live(a,ns):
        members,seen={root_key},{root_key}
        for e in kernel:
            if e['monotonic_ns']>ns:break
            k=(e['pid'],e['birth']);need(k in members and (e['root_pid'],e['root_birth'])==root_key,'foreign cron author source')
            if e['kind']=='fork':
                child=(e['detail'][0],str(e['detail'][1]));need(child not in seen,'reused cron author');seen.add(child);members.add(child)
            elif e['kind']=='exit':members.remove(k)
        return key(a) in members
    files,writes={},{}
    need(len(kinds.get('closed-write',[]))==2,'one exact cron table and payload version required')
    for n,r in kinds['closed-write']:
        f,a=r['file'],r['actor'];name=Path(f['path']).name
        need(name in (c['payload'],c['crontab']) and name not in files and f['path']==str(Path(c['directory'])/name),'foreign cron artifact')
        raw=base64.b64decode(f['content'],validate=True)
        need(len(raw)==f['size'] and sha(raw)==f['sha256'] and r['lease']=='F_RDLCK','unbound cron content')
        need(live(a,r['monotonic_ns']) and all(a[k]==credentials[k] for k in ('uids','gids','groups')),'dead/unknown cron author')
        dev=(os.major(f['device'])<<20)|os.minor(f['device'])
        need(any(e['kind']=='modify' and (e['pid'],e['birth'])==key(a) and e['monotonic_ns']<r['monotonic_ns']
                 and not e['strings_may_be_truncated'] and e['detail'][:3]==[name,intent['directory_inode'],dev] and e['detail'][3]>0 for e in kernel),'actual cron definition write missing')
        files[name]=(f,raw);writes[name]=(n,r)
    payload,table=files[c['payload']],files[c['crontab']]
    need(payload[1].startswith(b'\x7fELF'),'native cron payload required')
    text=table[1].decode();suffix=' exec '+payload[0]['path']+'\n'
    need(text.startswith('MAILTO=\n') and text.endswith(suffix) and text.count('\n')==2,'one no-mail exact cron command')
    schedule=text.splitlines()[1][:-len(suffix)+1]
    if c['schedule']=='@reboot':need(schedule=='@reboot','startup schedule mismatch')
    else:
        fields=schedule.split();need(len(fields)==5 and all(re.fullmatch(r'\d{1,2}',v) for v in fields),'one-shot calendar required')
        vals=list(map(int,fields));need(0<=vals[0]<60 and 0<=vals[1]<24 and 1<=vals[2]<=31 and 1<=vals[3]<=12 and 0<=vals[4]<=6,'invalid calendar')
    daemon,actor=fire['daemon'],fire['actor'];m=c['manager']
    need(all(daemon[k]==m[k] for k in ('pid','birth','uids','gids','groups','image','image_sha256')) and daemon['cmdline']==c['daemon_argv'],'foreign daemon invocation')
    need(actor['parent_pid']==m['pid'] and all(actor[k]==credentials[k] for k in ('uids','gids','groups'))
         and actor['image']==payload[0]['path'] and actor['cmdline']==[payload[0]['path']]
         and actor['image_sha256']==payload[0]['sha256'] and all(actor[k]==payload[0][k] for k in ('inode','device')),'cron execution identity mismatch')
    loads=[(n,r) for n,r in kinds.get('manager-open',[]) if r['file']['path']==table[0]['path']]
    need(loads and all(key(r['actor'])==key(m) and r['actor']['uids']==[0]*4 and r['actor']['image']==m['image']
         and all(r['file'][k]==table[0][k] for k in ('path','inode','device','sha256','content','size')) for _,r in loads),'actual cron table load missing')
    opens=[(n,r) for n,r in kinds.get('exec-open',[]) if key(r['actor'])==key(actor)]
    need(len(opens)==1 and opens[0][1]['actor']['parent_pid']==m['pid'] and all(opens[0][1]['file'][k]==payload[0][k] for k in ('path','inode','device','sha256','content','size')),'actual cron exec open missing')
    need(fire['table_owner']==0 and fire['table_mode']==0o600 and (fire['log_inode'],fire['log_device'])==(fresh['log_inode'],fresh['log_device']),'unprotected dispatch log/table')
    log=base64.b64decode(fire['log_base64'],validate=True).decode();wanted='USER '+c['crontab']+' pid '+str(actor['pid'])+' cmd exec '+payload[0]['path']
    matches=[v for v in log.splitlines() if re.sub(r'\s+',' ',v).endswith(wanted)]
    need(matches==[fire['dispatch_line']] and 'crond (busybox 1.36.1)' in log,'actual trusted daemon dispatch missing')
    marker=fire['marker'];need(marker['uid']==0 and marker['size']==0 and marker['mode']&0o777==0 and marker['inode']>0,'startup marker not bound')
    if c['schedule']=='@reboot':need('wakeup dt=' not in log,'startup dispatch was a calendar tick')
    trigger=opens[0][1]['monotonic_ns'];ready=kinds['ready'][0][1]
    root_exec=[e for e in kernel if e['kind']=='exec' and (e['pid'],e['birth'])==root_key]
    exits=[e for e in kernel if e['kind']=='exit' and (e['pid'],e['birth'])==root_key]
    need(len(root_exec)==len(exits)==1 and ready['monotonic_ns']<root_exec[0]['monotonic_ns']
         and exits[0]['monotonic_ns']<trigger<=fire['monotonic_ns']<boundary_ns
         and fire['monotonic_ns']<min(ready['deadline_ns'],exits[0]['monotonic_ns']+c['window_seconds']*10**9),'cron fire outside qualified window')
    a,d=writes[c['payload']],writes[c['crontab']]
    need(a[1]['monotonic_ns']<d[1]['monotonic_ns']<rows[loads[0][0]-1]['monotonic_ns']<trigger,'cron write/load/exec order')
    version=sha(json.dumps([table[0]['sha256'],payload[0]['sha256']],separators=(',',':')).encode())
    identity='cron:'+c['crontab']+':'+table[0]['path']+':'+c['schedule']
    def instance(a):return dict(boot_id=binding['boot_id'],pid=a['pid'],start_time=a['birth'])
    return [dict(kind='artifact',instance=instance(a[1]['actor']),artifact_path=payload[0]['path'],artifact_sha256=payload[0]['sha256'],monotonic_ns=a[1]['monotonic_ns'],source_rows=[a[0]]),
            dict(kind='definition',instance=instance(d[1]['actor']),artifact_path=payload[0]['path'],definition_id=identity,definition_mechanism='cron',definition_schedule=c['schedule'],definition_version=version,definition_binds_sha256=payload[0]['sha256'],monotonic_ns=d[1]['monotonic_ns'],source_rows=[d[0],*[n for n,_ in loads]]),
            dict(kind='scheduler-fire',fired_instance=instance(actor),image=payload[0]['path'],executable_sha256=payload[0]['sha256'],fire_definition_id=identity,fire_definition_version=version,monotonic_ns=trigger,execution_identity=actor,invocation_id='cron:'+str(actor['pid'])+':'+actor['birth'],schedule=c['schedule'],startup_semantics='same-boot managed daemon startup, not a VM boot transition' if c['schedule']=='@reboot' else 'actual one-shot calendar dispatch',source_rows=[kinds['fresh'][0][0],opens[0][0],kinds['cron-invocation'][0][0]])]


def normalize(rows,**args):
    ends=[r for r in rows if r['kind']=='closed'];need(len(ends)==1 and not ends[0]['error'] and not ends[0]['lease_broken'],'incomplete cron originals')
    return qualify(rows,boundary_ns=ends[0]['monotonic_ns'],**args)
