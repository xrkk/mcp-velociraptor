# Producer completion and cross-account export

The existing MCP tools retain their names, parameters and startup behavior.
The explicit post-production scripts below export finished outputs; ordinary
FileSystem writes do not imply that a larger producer has finished.

## Deployment contract

Configure a dedicated output directory as an exact policy `read_roots` entry.
Give the producing administrator/SYSTEM the required directory creation rights
and the pull service Read/traverse. Keep it separate from producer originals,
Velo private state and configuration. The new directory can have a protected
SYSTEM/admins DACL before source Read grants are configured. Existing broader
service grants are preserved by the handoff helper, not silently reduced.

| Input | Producer evidence | Consumer |
| --- | --- | --- |
| Text/report output | Windows-MCP writer closed; all selected producer jobs finished | Velo service reads export copy |
| PCAP/HTTP/report/log | FakeNet stopped, selected run, registered `complete=true`, size/SHA | Velo service reads export copy |
| incident/dump | FakeNet controlled incident publication; protected source exported by FakeNet | Velo reads registered copy, never protected exit-evidence |
| Config/environment/API credentials | Explicit authorized file, private replacement, preserved owner/DACL | Service reload/restart verifies actual loading |

## Source permission scope

`configure_transfer_source_access.ps1` retains whole-root configure/verify as
its default. `-ArtifactPath` selects one completed file or directory within the
exact read root. Only that subtree and its directory ancestors up to the root
are selected. Ancestors receive this-folder-only Read/traverse: no new inherited
ACE propagates to unrelated active batches. The completed subtree receives the
existing Read inheritance contract. Denies/reparse points are refused.

## Shared export

```powershell
& (Join-Path $VeloRepository 'export_transfer_artifacts.ps1') `
  -ManifestPath $ManifestPath -PolicyPath $PolicyPath -OutputRoot $OutputRoot
```

Manifest schema `velo.artifact-export.v1` requires producer (`Windows-MCP` or
`FakeNet-NG`), batch_id, absolute source_root, true producer_complete and
producer_quiescent, nonempty references, and files with absolute path, portable
relative_path, integer size, lowercase SHA-256 and `complete=true`. FakeNet also
requires producer_state=stopped and run_id; its source is registered artifacts.
Metadata files are limited to 1 MiB and content to policy file/byte/time budgets.

The exporter opens each source without writer/delete sharing, creates independent
copies in a new owned stage, checks size and SHA-256, retains a bound receipt,
configures/verifies the completed stage's service Read, then publishes a unique
batch directory and verifies its final ACL. Existing destinations are refused.
An export result is not transfer COMPLETE: submit the returned output directory
to the existing Velo host pull coordinator, then verify destination bytes,
SHA-256 and both owned cleanups. Keep the producer quiescent throughout handoff.

Failures retain operation, both paths, native class/HResult/OS message and a
native IO error code where available; UTF-8 error JSON is written to stderr and
an owned `.handoff-error-*.json`. Failed stage directories are retained for exact
manifest review; they are not published or blindly deleted. No source ACL or
original content is changed. The receipt binds the source manifest digest and
copied file hashes. EFS, sharing restrictions and other OS failures remain real
errors; ACL verification alone is not effective service-token read proof.

## Producer entry points

Windows-MCP `Export-VeloArtifacts.ps1`: explicit absolute Sources/SourceRoot,
producer references, completion/quiescence switches, deployment variables and
an evidence directory. Invoke through PowerShell after FileSystem/application
writers close. It retains an export manifest and calls the shared exporter.

FakeNet `tools/Export-VeloArtifacts.ps1`: save a fresh successful
`get_run_overview(run_id=...)` structured result after stop; provide OverviewPath,
ArtifactsRoot and deployment variables. The wrapper requires consistent,
nonpartial stopped status, matching selected query/run/version, and selects
only complete rows under that registered run. It never starts/stops FakeNet,
changes exit-evidence ACLs or promotes unpublished rows. The shared exporter
independently verifies the current bytes against FakeNet's declarations.
