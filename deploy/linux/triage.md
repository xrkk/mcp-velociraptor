# Production Linux basic triage

The optional Linux domain is an explicit separate registry on the same bridge
constructor. Set `VELOCIRAPTOR_LINUX_DOMAIN=1` and `VELOCIRAPTOR_LINUX_ROOT` to a
completed protected Linux installation. Default Windows construction, tools and
schemas are unchanged. The historical test runner is not a production entry.

The standard-library one-shot entry is:

```sh
sudo python3 -B velociraptor_linux_cli.py --deployment-root /opt/velociraptor < request.json
```

It invokes the same `register_linux_domain_tools` handlers as the MCP branch,
opens no listener and accepts one bounded JSON object with `tool` and `arguments`.
`linux_platform_route` takes `client_id`. The backend binds actual registered OS,
unique client ID, local private writeback ID and completed deployment VM/boot.
Unknown, ambiguous, non-Linux or unbound targets refuse before mutation.

`linux_triage_launch` and `linux_triage_collect` take `session_id` and `run_id`
(canonical UUIDs), explicit `client_id`, and `plan`. The plan has exactly
`parameters`, `timeout_seconds` (1..120) and `max_bytes` (1..33554432 per flow).
`parameters` maps all eight pinned artifacts to dictionaries of their real named
string parameters. Defaults stay in the pinned original; file acquisition and
journal date boundaries must be explicit. These resource values enter the real
`collect_client` request and returned request values are checked. Backend collection
quotas may overshoot by an in-flight block; independent result/export limits apply.

The eight full original definition SHA-256 values are pinned in
`velociraptor_linux_backend.py` for official v0.77.3. The complete live definitions,
platform preconditions, parameter schemas and raw original text are saved with
each run. This is not a name-only fingerprint or permission to replace artifacts.

| Basic evidence | Actual artifact / output |
|---|---|
| Process snapshot and parent facts | Linux.Sys.Pslist |
| File facts | Linux.Search.FileFinder rows |
| Network/process association | Linux.Network.Netstat TCP sources |
| Persistence inventory | Linux.Sys.Services, Linux.Sys.Crontab and explicitly selected system/user service/timer definitions via Linux.Search.FileFinder |
| System/security logs | Linux.Forensics.Journal with fixed dates, no raw journal upload |
| Metadata/hash | Linux.Search.FileFinder Calculate_Hash=Y |
| Targeted acquisition | Linux.Search.FileFinder Upload_File=Y, original upload inventory and API file bytes |

Generic.Client.Info and Linux.Sys.Users add host/account context. File metadata,
hashes and uploaded bytes are distinct outputs of one artifact, not duplicate
cron runs. Expected fixture identities and system/user/timer coverage still require
native verification. Snapshot facts do not prove realtime fork/exec, deletion,
rename or causal events. Do not close those separate requirements with triage.

`linux_triage_status/results/cancel` take `run_id`. `linux_triage_export` takes
`run_id` and optional `include_bytes` (default false); true returns a bounded
base64 bundle of retained originals for a protected consumer. `linux_triage_compare`
takes two distinct IDs `first` and `second` and reads both original results.

Every new run directory is exclusive under the private installation `triage` root.
An intent precedes each mutation. Only the returned exact flow ID is admitted;
there is no latest-flow selection. Unknown response/timeouts preserve originals
and block repeated launch under that run ID. Inspect/cancel known owned flows;
do not silently create another run to hide an unknown launch.

The collect method waits a finite deadline, retrieves real source pages (100 rows,
5000 per source), records optional empty sources, reconciles retrieved rows with each flow total, lists uploads and reads uploaded
bytes through the authenticated server filestore API. Regular uploads are limited
to 4 MiB each and compared with their source row hash and original size. Sparse or
ambiguous entries refuse. Results have an independent 32 MiB bound; bundle export
has a 64 MiB original-byte bound. Collection errors preserve raw requests/responses,
logs and any known flow references. Cancel reports actual API response and terminal
status; a missing creation response remains unknown even after known flows end.

The comparator rereads plans, complete definitions, flow bindings, source pages and
file refs, checks bytes/hashes and recomputes seven category facts. Both runs must
finish successfully with the same VM/boot/client/session/definitions/parameters;
ERROR, empty required evidence, missing classes and fabricated products refuse.
Changing timestamps/rows do not require byte-identical results between runs.

The old linux_scope_* API only changes memory records. It does not apply, extend,
withdraw, expire or stop real high-granularity collection. Its results explicitly
report `backend_applied=false`. These effects and native Windows qualification
remain separate acceptance work. Local tests use API doubles; they are not VM proof.

The pinned plan uses FileFinder for explicit system/user service and timer files. Native v0.77.3 Generic.Collectors.File sent three metadata rows that were not available through either source API form or its expected result-set path; its upload rows remained readable. That artifact is excluded from this plan, with no reduction in the seven evidence classes. Any reported-versus-retrieved row discrepancy now refuses result publication and repeatability. Historical nine-artifact runs remain preserved and do not meet this stronger completeness check.
