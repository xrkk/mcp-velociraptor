# Bounded ordinary user timer evidence

`velociraptor_linux_scheduler.Collector` is an internal professional source used
by the pinned P04 management observer. It is not a new MCP tool and does not
change the bridge or shared environment startup. A host-selected profile fixes
an empty flat directory, three short artifact names, an existing qualified
ordinary user manager/private socket and a finite post-root observation window.
The host owns temporary manager setup/restoration. The collector never starts a
payload or grants sample privileges.

`PrivateManager` uses libsystemd peer mode and verifies SO_PEERCRED against the
pinned PID/birth, executable hash and credentials. The fresh service and timer
must be absent. Fanotify close-write events capture an actual live writer and
closed content on an open descriptor. Read leases reject concurrent writers and
subsequent mutation; a break invalidates the source and releases the lease.
Manager open and exec permission events expose the actual used inode. Replacement
and changed content cannot qualify by re-reading a current pathname. Permission
events are allowed, not used to grant execution authority. A bounded thread
services permission events while the caller reads manager properties, avoiding
a synchronous manager/query deadlock. Group and lease close also release pending
accesses on cancellation or process death.

`normalize` replays closed raw originals and kernel membership. It requires a
successful content write by a live chain instance, three unique versions, actual
manager-opened definition content, no drop-ins, native timer ActivationDetails,
a first InvocationID/MainPID and a matching live full credential/image inode
observation. The supported definitions are narrow: RefuseManualStart=yes,
Type=exec, one ELF command without arguments, Restart=no, RuntimeMaxSec=4-30s,
journal output, and one OnActiveSec timer (1-9 seconds). Unsupported forms are
unavailable. This source does not claim general systemd or arbitrary schedulers.

Native ActivationDetails belongs to the scheduler job, but older details win in
unit_start. Thus existing-unit or repeated-invocation facts cannot replace fresh
unit proof. Source references:
[systemd v255 timer.c](https://raw.githubusercontent.com/systemd/systemd/v255/src/core/timer.c),
[unit.c](https://raw.githubusercontent.com/systemd/systemd/v255/src/core/unit.c),
[dbus-unit.c](https://raw.githubusercontent.com/systemd/systemd/v255/src/core/dbus-unit.c).
The exact sd_bus_get_property signature is mandatory; see
[bus-convenience.c](https://raw.githubusercontent.com/systemd/systemd/v255/src/libsystemd/sd-bus/bus-convenience.c).

The host recovers raw records (including descriptor snapshots), stop results and
scoped journal output before derivation/cleanup. Complete chains produce three
semantic records with raw row mappings. A missing writer, hash, loaded version,
real trigger, UID, boot or process birth fails. A manual same-image process does
not become a timer candidate. The production FollowingCollector uses shared `qualify` while the fired process
is alive, then calls the existing `linux_scope_extend` exactly once. It records
the complete proof, original kernel prefix hash, full live credentials, target
PID/birth, bounded expiry and actual generation readiness. The next kernel
generation follows the fired process and its kernel-observed descendants. Its
origin is the fired instance, never a fabricated fork from the initial root.

Online admission and final `normalize` share the same complete-chain checks;
final replay additionally requires actual source closure without errors or lease
breaks. Missing facts, old/manual same-image invocation, wrong boot, reused or
dead PID, expiry, source failure and unknown extension outcomes never report
continuous coverage. Unknown requests are not retried. P04 finally still owns
formal scope stop/export, including cancellation. The kernel scope deadline is
autonomous; extension expiry is the remaining observation window plus a bounded
five-second cleanup allowance (rounded up), capped by the original scope.

There is an explicit fire-to-readiness blind interval. The independently observed
exec inode/credentials covers identity, not missing kernel actions or zero-loss
telemetry. Short-lived or unready payloads may be missed. The supported finite
subset does not guarantee arbitrary scheduler coverage. Every generation and
action retains its raw reference; the consumer verifies membership and expiry
before emitting causal edges or investigation candidates.

Run explicit local source tests with `python -m unittest discover -s tests -p
 test_linux_scheduler.py -v`. They are synthetic inputs to the production
normalizer, not native evidence. P04 integration tests use a caller-selected
VR_LINUX_SOURCE_ROOT test checkout; production never reads that environment
variable as authority.
