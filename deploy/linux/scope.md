# Bounded Linux kernel scopes

`MalTrace.ScopedKernel.v1` is a custom professional helper, not an upstream
Velociraptor artifact or monitoring flow. The existing VR deployment binds the
client, VM and boot. Its services/configuration/basic triage remain independent.
This backend requires root, the pinned installed bpftrace 0.20.2 full hash in
`velociraptor_linux_probe.py`, BTF with the declared sched/VFS/TCP hooks, and
100-Hz process birth ticks. Unsupported environments fail; no fallback collector
or package installation occurs. No additional listening socket is used.

The registered `linux_scope_apply/update/query/extend/withdraw/stop/export`
tools take `request`, with canonical UUID `session_id`, `owner_id`, `operation_id`,
`vm_uuid`, `boot_id`, and explicit `client_id`. `get` aliases query and
`bind_targets` aliases update. All mutation intents are durable before effects.
Each request uses a new operation ID. Unknown outcomes are not replayable: query
then stop the same owner/session. A session directory is exclusive and retained.

Apply needs `targets` (1..16 objects containing integer `pid`, decimal-string
`birth` from /proc/PID/stat field 22, nonzero integer `uid`) and
`lifetime_seconds` (30..900). Unknown/reused/root subjects refuse before launch.
Update replaces the latest default targets; an extension remains independent.
Extend needs explicit targets, nonblank `reason` and `termination`, and
`expires_in_seconds` (5..300). Its deadline starts at the durable request, capped
by the original session deadline. Termination text documents the caller's
condition; the caller invokes withdraw when that condition is met. Time expiry
is enforced by kernel predicates without queries, and by the worker's autonomous
transition. Withdrawal returns to the latest default targets. Only descendants
observed through actual kernel fork events inherit a root's scope and deadline.

The kernel filters PID plus group-leader birth before emission. Fork is the
actual process-start event, exec is an independent event, and leader exit carries
its exit status. Successful VFS create/write/unlink/rename and IPv4 TCP connect
carry process/root identities. File names are combined with actual parent inode
and kernel device number (major = value >> 20, minor = value & 0xfffff); callers
must verify a directory mapping before asserting a full path. Rename captures
both original names and parents at entry. Network destination port is raw
network byte order; this source is not packet capture. It does not cover mmap,
direct-I/O modifications, IPv6, all transport protocols, or threads as separate
processes. Strings have 32-byte storage; values reaching 31 bytes are explicitly
marked potentially truncated, never treated as complete paths.

Configuration switches detach the old probes before attaching the new ones.
The immutable transitions expose that bounded observation gap; only windows
following the APPLIED acknowledgment qualify for comparison. Kernel predicates
use monotonic nanoseconds (active runtime excludes system suspend), while PID
birth uses kernel start_boottime. The worker persists source hashes, generated
programs, effective configurations, raw NDJSON, normalized event records and
probe PID/birth. Unexpected diagnostics/loss, forced kill, resource overflow or
premature exit fail the session. Bounds are 128 seeded descendants, 1024 kernel
map entries, 50000 events, and 16 MiB raw bytes per generation.

Stop waits for the owned probe and worker to exit. A missing worker is UNKNOWN,
not APPLIED. SIGTERM interruption becomes FAILED after cleanup; SIGKILL uses
parent-death signaling plus the probe's independent session deadline. Recovery
stop only signals a PID whose original birth and exact argv still match. It
records FAILED/collection_stopped, never retroactively reports a normal stop.
Export requires confirmed termination and fingerprints the closed originals.
It never qualifies complete causality or a full sample round.

Open lookup may call the filesystem create operation directly. Successful
`do_filp_open` returns with kernel `FMODE_CREATED` supplement the vfs_create
hook; O_CREAT opening an existing file does not qualify as a new create event.
This is supported by the fixed kernel BTF/header and the upstream
[Linux 6.8 open lookup](https://github.com/torvalds/linux/blob/v6.8/fs/namei.c).
