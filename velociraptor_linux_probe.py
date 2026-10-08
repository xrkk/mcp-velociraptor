"""MalTrace.ScopedKernel.v1: custom BTF/bpftrace source, not an upstream artifact.

Map keys include kernel process birth ticks. The predicate is applied before
emitting events, including inherited children and autonomous kernel expiry.
File evidence is basename + filesystem/parent inode, never an invented full path.
"""
import json

SOURCE_ID = 'MalTrace.ScopedKernel.v1'
BPFTRACE_SHA = 'd2846f3400bb129b1a569aae64adf548de99ff41f247823ff8caf1fbde40ff1e'


def program(targets, deadline, tick_ns):
    seed = []
    for t in targets:
        key = f"{t['pid']}, {t['birth']}"
        seed += [f"@until[{key}] = (uint64){t['until_ns']};",
                 f"@origin[{key}] = ({t['root_pid']}, {t['root_birth']});"]
    birth = f'((struct task_struct*)curtask)->group_leader->start_boottime / {tick_ns}'
    predicate = f'@until[pid, {birth}] > nsecs && nsecs < {deadline}'
    common = f'nsecs, pid, {birth}, uid, @origin[pid, {birth}].0, @origin[pid, {birth}].1'
    pieces = ['BEGIN { ' + ' '.join(seed) + ' print(("ready", nsecs)); }']
    pieces.append(f"""
rawtracepoint:sched_process_fork /{predicate}/ {{
    $child = (struct task_struct*)arg1;
    $cpid = (uint64)$child->tgid;
    $cbirth = $child->group_leader->start_boottime / {tick_ns};
    if ($cpid != pid) {{
        @until[$cpid, $cbirth] = @until[pid, {birth}];
        @origin[$cpid, $cbirth] = @origin[pid, {birth}];
        print(("fork", {common}, $cpid, $cbirth));
    }}
}}
tracepoint:sched:sched_process_exec /{predicate}/ {{
    print(("exec", {common}, str(args.filename)));
}}
tracepoint:sched:sched_process_exit /{predicate} && tid == pid/ {{
    print(("exit", {common}, ((struct task_struct*)curtask)->exit_code));
    delete(@until[pid, {birth}]); delete(@origin[pid, {birth}]);
}}
""")
    # open lookup may call the filesystem create operation directly, bypassing
    # vfs_create. FMODE_CREATED on a successful returned file is a kernel fact;
    # O_CREAT alone also opens existing files and is not evidence of creation.
    pieces.append(f"""
kretfunc:do_filp_open /{predicate}/ {{
    $f = (struct file*)retval;
    if ((uint64)$f != 0 && (uint64)$f < (uint64)-4095 && ($f->f_mode & 0x100000)) {{
        print(("create", {common}, str($f->f_path.dentry->d_name.name),
               $f->f_path.dentry->d_parent->d_inode->i_ino, $f->f_inode->i_sb->s_dev));
    }}
}}
""")
    # Store entry facts because rename/unlink mutate the dentries before return.
    for operation, function, entry, output, success in (
        ('create', 'vfs_create',
         '@file[tid] = (str(args.dentry->d_name.name), args.dir->i_ino, args.dir->i_sb->s_dev);',
         '$f.0, $f.1, $f.2', 'retval == 0'),
        ('delete', 'vfs_unlink',
         '@file[tid] = (str(args.dentry->d_name.name), args.dir->i_ino, args.dir->i_sb->s_dev);',
         '$f.0, $f.1, $f.2', 'retval == 0'),
        ('modify', 'vfs_write',
         '@file[tid] = (str(args.file->f_path.dentry->d_name.name), args.file->f_path.dentry->d_parent->d_inode->i_ino, args.file->f_inode->i_sb->s_dev);',
         '$f.0, $f.1, $f.2, retval', 'retval > 0'),
    ):
        pieces.append(f"""
kfunc:{function} /{predicate}/ {{ {entry} @pending[tid] = 1; }}
kretfunc:{function} /@pending[tid]/ {{
    $f = @file[tid];
    if ({predicate} && {success}) {{ print(("{operation}", {common}, {output})); }}
    delete(@pending[tid]); delete(@file[tid]);
}}
""")
    pieces.append(f"""
kfunc:vfs_rename /{predicate}/ {{
    @rename[tid] = (str(args.rd->old_dentry->d_name.name), str(args.rd->new_dentry->d_name.name),
                   args.rd->old_dir->i_ino, args.rd->new_dir->i_ino, args.rd->old_dir->i_sb->s_dev);
    @renaming[tid] = 1;
}}
kretfunc:vfs_rename /@renaming[tid]/ {{
    $r = @rename[tid];
    if ({predicate} && retval == 0) {{
        print(("rename", {common}, $r.0, $r.1, $r.2, $r.3, $r.4));
    }}
    delete(@rename[tid]); delete(@renaming[tid]);
}}
kretfunc:tcp_v4_connect /{predicate} && retval == 0/ {{
    print(("connect", {common}, ntop(args.sk->__sk_common.skc_daddr),
           args.sk->__sk_common.skc_dport, args.sk->__sk_common.skc_num));
}}
interval:s:1 {{ if (nsecs >= {deadline}) {{ exit(); }} }}
END {{ clear(@until); clear(@origin); clear(@file); clear(@pending); clear(@rename); clear(@renaming); print(("end", nsecs)); }}
""")
    return '\n'.join(pieces)


def decode(line, generation):
    value = json.loads(line)
    if value.get('type') != 'value':
        raise ValueError('unexpected bpftrace diagnostic or lost-event record')
    data = value['data']
    if data[0] in ('ready', 'end'):
        return dict(kind=data[0], monotonic_ns=data[1], generation=generation)
    return dict(kind=data[0], monotonic_ns=data[1], pid=data[2], birth=str(data[3]),
                uid=data[4], root_pid=data[5], root_birth=str(data[6]),
                detail=data[7:], generation=generation,
                source=SOURCE_ID,
                strings_may_be_truncated=any(isinstance(x, str) and len(x.encode()) >= 31 for x in data[7:]))
