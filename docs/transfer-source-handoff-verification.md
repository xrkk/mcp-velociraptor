# Cross-account source handoff — .149 verification, 2026-10-08

The repaired eight-file pull completed on the existing `.149` Windows VM through
the formal service, with physical host content checks and both owned cleanups.
This is scoped acceptance of source permission handoff and worker diagnostics.

## Environment and deployment

- Guest: `192.168.204.149`, UUID `b3e04d56-3db2-9f3d-4d52-3ec22c4cfdc0`.
- Formal account: `NT SERVICE\mcp-velociraptor`; listener: port 28790.
- Runtime fix: `d1ffd16`, plus the native compatibility fixes described below.
- Four deployed Python files matched the exact pre-fix revision before mutation.
  All six staged/deployed files were checked against local SHA-256 values.
- Original files were backed up under the deployment's
  `mcp/Logs/velo-acl149-e6a2915425a0/backup/`. The existing keepalive task was
  temporarily disabled for the controlled service update and restored enabled.
  The formal service restarted from PID 2520 to PID 6856 and owned its listener.
- The active policy and environment file hashes remained unchanged. The ACL
  handoff used an isolated policy copy naming only the benign fixture as its
  exact read root, while the real service continued using its original policy.
  No broad ACL change was applied to the active data root or work root.

## Native defects found and corrected

The first native test exposed an environment issue: Python inherited PowerShell
7's module search path when launching Windows PowerShell 5.1, whose Security
module then failed with duplicate type-data members. The native test now sets
its child module path to the Windows PowerShell system modules.

With that environment corrected, the same test failed under strict mode because
`DirectoryInfo.Parent` returns an ordinary CLR object without the provider's
`PSIsContainer` property. Directory checks now use `-is [IO.DirectoryInfo]`.
The original native test went from red to green after this correction.

The deployed native ACL test passed, covering owner-only grants, eight existing
outputs, repeat configure, newly created nested outputs, protected DACL repair,
Read-only service file grants, preserved group deny ACEs, and outside-policy
root refusal. Three source diagnostic tests also passed on Windows. Python
compilation and native PowerShell parsing completed successfully.

## Real service cases

All case IDs below use prefix `velo-acl149-e6a2915425a0-`. Three originals were
created by a completed formal-service push; five were created by an elevated
administrator, including a moved file, a protected file and a nested file.
Their owners were respectively the service account and Builtin Administrators.
The isolated directory initially used OWNER RIGHTS without service content Read
on the administrator files. Directory traversal was granted separately so the
negative request reached the worker's content-open operation.

| Case suffix | Observed result |
| --- | --- |
| `service-only2` | Three service-owned files: COMPLETE, exit 0, before handoff. |
| `denied-eight2` | Worker stopped in SOURCE_PREPARING with source_unavailable; no host publication. |
| Source ACL configure/verify | Ten objects checked; repeat configure preserved root SDDL; all original hashes/owners preserved. |
| `repaired-eight` | Eight files: COMPLETE, exit 0; every destination's bytes and SHA-256 independently matched expected content. |
| `repaired-eight` cleanup | Host and guest cleanup true; guest SOURCE_RELEASED, no error, temporary_files_removed/workers_stopped true. |
| New administrator file after handoff | Inherited service FR ACE; verify checked eleven objects without repair. |
| `inherited-ready` | Formal service read and packaged that new file: SOURCE_READY, no error, worker stopped. Probe then explicitly aborted. |

The source originals remained present, with unchanged hashes and owners. The
five administrator files' service SID grants had no write, delete or execute
bits. Existing owner rights and broader grants on service-owned originals were
preserved.

The native worker error was retained at the negative task's
`worker-error-cd553cebe7c85dafb2259feeeaa1a514.json`, binding request digest,
worker nonce, PID 6872 and process birth. Its context contained the complete
fixture `admin-1.txt` path, `operation=open`, `errno=13`,
`os_error_type=PermissionError` and the original `[Errno 13] Permission denied`
message. This actual exception had `winerror=null`; no WinError value was
invented. The failed task and log survived the successful fresh-ID pull.

## Retained evidence and limits

Local raw records, native-test outputs, host journals, result documents and
downloaded originals are in the ignored repository directory
`Logs/velo-acl149-e6a2915425a0/`, including
`host-evidence/eight-file-verification.json`. Guest deployment, fixture, denial,
handoff and final-state records remain in the deployment-relative
`mcp/Logs/velo-acl149-e6a2915425a0/` directory. These records contain no bearer
tokens or environment file contents.

All preliminary failures remain in the journals: one staging request hit
`windows_acl_path_changed` and succeeded under a fresh ID; an early control
BEGIN hit `worker_busy`; the initial negative request lacked nested-directory
traversal and failed before creating a task. They are not counted as passing
source cases and their unrelated recovery behavior was not changed.

Automatic approval review timed out for an optional worker-account sampling
command and for the additional new-file full-transfer CLI (including its one
retry). Those commands were not assumed to have run. The already connected MCP
service supplied the bounded new-file SOURCE_READY proof instead. That probe
does not claim host publication or COMPLETE; abort preserves its small package
and task evidence according to the existing contract, with its worker stopped.
The eight-file case's full publication and both cleanups were verified separately.

The local regression rerun passed 68 tests with three Windows-only skips.
This run used small benign files; it does not qualify large-file performance,
power-loss durability or the broader forensic scenario suite. The bounded next
step is to apply the documented producer-close/configure/verify sequence to the
actual administrative output workflow and repeat its eight-file pull.
