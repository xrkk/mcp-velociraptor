# Cross-account handoff source audit (2026-10-08)

This is an independent source/documentation audit of the implementation in
progress, not a deployment or transfer acceptance report. It covers the Velo
shared exporter/private-file helper and the candidate Windows-MCP/FakeNet
producer wrappers. The authoritative acceptance state remains the
[implementation checklist](cross-account-permission-implementation.md).
No VM, process lifecycle, transfer, reboot or snapshot operation was performed
for this audit. The user's no-reboot/no-snapshot constraint supersedes any
historical VM-reset instructions in another repository.

## Required omission: HTTP POST dump publication

The initial FakeNet source reviewed here was based on `3ed8592`. Its
[`HTTPListener.do_POST`](../../flare-fakenet-ng/fakenet/listeners/HTTPListener.py#L589)
logs the request and collects report data, then, when `DumpHTTPPosts=Yes`, writes
`<DumpHTTPPostsFilePrefix>_<YYYYMMDD_HHMMSS>.txt` and closes it
([lines 607–617](../../flare-fakenet-ng/fakenet/listeners/HTTPListener.py#L607)).
The managed child starts with the isolated run directory as its working
directory ([managed.py:125](../../flare-fakenet-ng/fakenet/mcp/managed.py#L125)).
The stop path calls artifact registration after the managed process/exit owner
and restoration audit finish
([supervisor.py:525](../../flare-fakenet-ng/fakenet/mcp/supervisor.py#L525),
[supervisor.py:559](../../flare-fakenet-ng/fakenet/mcp/supervisor.py#L559)).
The diagnostic worker registers only `artifacts/runs/<run_id>` with an empty
copy prefix
([diagnostic_tasks.py:108](../../flare-fakenet-ng/fakenet/mcp/diagnostic_tasks.py#L108)).

Initially,
[`register_fakenet_outputs`](../../flare-fakenet-ng/fakenet/mcp/artifacts.py#L131)
selected `*.pcap`, `*.log`, `*report*.html`, `*.json` and fixed run-evidence
filenames ([artifacts.py:144](../../flare-fakenet-ng/fakenet/mcp/artifacts.py#L144)).
The fixed `.txt` names are stack diagnostics, not HTTP POST dumps
([artifacts.py:27](../../flare-fakenet-ng/fakenet/mcp/artifacts.py#L27)).
It therefore neither copied nor published raw HTTP POST `.txt` files. HTTP
observations embedded in published `.log`/HTML files were exportable, but that
does not establish export of the separately promised raw HTTP records.
An absolute configured POST prefix can also place output outside the isolated
run source, requiring explicit bounded handling rather than a registry-wide
scan. This last consequence is an inference from the prefix being passed
unchanged to `open` and the registrar being anchored to one run directory.

A portable reproduction imported the actual `artifacts.py` using `importlib`,
created isolated `http_20261008_000000.txt`, `fakenet.log` and
`report_20261008.html` files, then invoked `register_fakenet_outputs` and
`metadata`. Only the log/report copies were registered `complete=true`; the
HTTP source remained present and had no registered row. This used temporary
directories and no FakeNet capture or service.

Required closure for C1/F1/F2/J1:

1. The producer must register the actual completed HTTP dump members at its
   existing closed-run publication boundary, using run-owned/configured-prefix
   selection. Do not blanket-publish unrelated text files or rename unpublished
   bytes to imply completion.
2. Cover the actual registration path with HTTP member, unrelated/old output,
   staging, changed-byte and path-boundary cases; preserve the existing
   publication size/SHA-256 contract.
3. Save real producer overview, export receipt and Velo COMPLETE/destination/
   cleanup evidence for the registered HTTP record before marking that type
   accepted. Source tests alone cannot close the deployment gate.

The initial observation is historical if the root implementation subsequently
fixes this gap; bind the fix commit/tests/native results in the implementation
checklist rather than silently deleting this finding.

Closure evidence: `5a958fa` adds the closed/config-selected HTTP registrar and
producer exporter, with a red-to-green real registration regression; `6948bca`
fixes listener-only health and the empty diverter callback. The immutable
`b201e71` core candidate passed the required Windows/MinGit/HTTP/Linux gates.
Native run `a5246d17-d67c-4fab-8ac0-3744faf23a60` produced a real HTTP POST dump,
registered it complete after normal stop, exported it through the official
wrapper and completed a 20-file formal Velo pull. Every received size/SHA and
the HTTP body were independently checked, with both cleanups complete. A second
run after service restart also completed its 13-file pull. The historical HTTP
finding is closed for this handoff scope. Offline SYSTEM PCAP/report fixtures
and an owned-child controlled minidump cover format/permission boundaries;
they do not establish live interception or full native capture qualification.

## Existing source boundaries that must stay explicit

| Boundary | Source and consequence |
| --- | --- |
| Completion is a producer declaration plus byte verification | `write_publication` records finished size/SHA-256; `_completion_from_entry` returns a digest only if current bytes match. An ordinary filename alone supplies no completion proof. [artifacts.py:56](../../flare-fakenet-ng/fakenet/mcp/artifacts.py#L56), [artifacts.py:95](../../flare-fakenet-ng/fakenet/mcp/artifacts.py#L95). |
| A run overview is not an atomic transaction or lifecycle lock | `get_run_overview` reports versions before/after and current service status even for a historical selected run. The producer must remain quiescent after this query. [tools.py:374](../../flare-fakenet-ng/fakenet/mcp/tools.py#L374), [tools.py:461](../../flare-fakenet-ng/fakenet/mcp/tools.py#L461). |
| FakeNet wrapper never promotes an unpublished row | It checks stopped/consistent/nonpartial observations and selects only true complete rows below the selected registered run. [Export-VeloArtifacts.ps1:19](../../flare-fakenet-ng/tools/Export-VeloArtifacts.ps1#L19), [line 31](../../flare-fakenet-ng/tools/Export-VeloArtifacts.ps1#L31). |
| Windows-MCP wrapper uses `Files`, not `Sources` | Explicit files, completion/quiescence switches and references describe selected closed producer outputs. The switches assert completion; they do not close an application. [Export-VeloArtifacts.ps1:8](../../Windows-MCP/Export-VeloArtifacts.ps1#L8), [line 17](../../Windows-MCP/Export-VeloArtifacts.ps1#L17). |
| Shared export proves an independent copy and scoped ACL, not transfer COMPLETE | The exact policy read root is required; source reads deny writer/delete sharing; a receipt binds declared hashes before scoped configure/verify and publication. Actual service-token source reading, destination bytes, durable global result and owned cleanup still require the existing transfer coordinator. [export_transfer_artifacts.ps1:59](../export_transfer_artifacts.ps1#L59), [line 117](../export_transfer_artifacts.ps1#L117), [line 145](../export_transfer_artifacts.ps1#L145). |
| Private configuration has a different contract | An explicit authorized target and private input are required; replacement retains original owner/DACL, uses an unused sibling backup and verifies content/ACL. The helper performs no restart/loading check. [update_windows_service_file.ps1:52](../update_windows_service_file.ps1#L52), [line 60](../update_windows_service_file.ps1#L60), [line 81](../update_windows_service_file.ps1#L81). |
| Protected exit-evidence cannot receive a recursive third ACE | Its verifier requires exactly two protected, inheritable SYSTEM/Administrators FullControl ACEs. [exit_installation.py:94](../../flare-fakenet-ng/fakenet/mcp/exit_installation.py#L94). |
| Incident export consumes the controlled copy | `_copy_exit_dump` verifies source/run identity and expected size/SHA, copies via an exclusive partial file, verifies the dump and publishes it. Incident publication includes only successful members plus its manifest. [incident.py:323](../../flare-fakenet-ng/fakenet/mcp/incident.py#L323), [incident.py:193](../../flare-fakenet-ng/fakenet/mcp/incident.py#L193). |

## Documentation corrections made in this audit

Both Velo READMEs now link to shared export, private-file updates and the
implementation checklist. Windows-MCP and FakeNet READMEs link to their new
`docs/artifact-handoff.md` with variable-driven wrapper commands, caller
completion requirements, failure/retention boundaries and final transfer
verification. The shared Windows wrapper parameter typo was corrected from
`Sources` to `Files`. Private service-file docs now show exact verify, replace
and restore arguments without credentials or deployment paths.

Required R1/A1 verification remains: confirm documented commands against the
accepted/deployed wrapper versions, record explicit local commits, then compare
every checklist row to actual evidence. The audit changes do not claim that D1,
D2, W1/W2, F1–F3, S1/S2, T1–T5, J1/J2 or R2 have passed. Those gates require
their own runtime evidence and final service/task/process-state checks.

## Optional follow-up

After this scope passes, consider a dedicated structured producer manifest
command inside each producer instead of caller-maintained scripts, if routine
usage demonstrates a need. Automatic manifests, cleanup scheduling, additional
tool schemas and global ACL rewriting are not required to close the current
explicit handoff workflow.
