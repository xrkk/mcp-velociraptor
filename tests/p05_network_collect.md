# P05 network evidence collector

`tests.p05_network_collect` is the callable producer for the already-frozen
PC006 and dual-adapter schema originals consumed by `tests.p06_evidence`.  It
records facts; it does not restore a VM, decide the PC006 restore-time window,
reconstruct missing history, or activate Snapshot 188.

## Call order

1. On the approved host, call `collect_pc006(...)` with the HTTP phase's
   `run_id`, its `restore_attempt_id`, the phase ready JSON, the fixed VMX
   identity, non-allowed source, and comparison port.  The function executes
   both exact argv values returned by `p06_evidence.pc006_collector_argv`,
   retains their real UTC bounds, exit codes, stdout and stderr, reuses the
   same-round ready firewall Ref, and publishes `pc006.json` only if both
   executions and the firewall original pass the existing parsers.
2. In the approved Windows guest, call async `collect_stdio(...)`.  Supply the
   selected repository root, its `.venv\Scripts\python.exe`, its direct
   `mcp_velociraptor_bridge.py`, the formal HTTP tools-list original, the HTTP
   run ID, a separately reserved stdio diagnostic run ID, and the same restore
   attempt ID.  The function owns and reaps the child process, uses the official
   SDK `ClientSession`, captures initialize/initialized/tools-list through
   `SDKCapture`, and records the child's actual exit status and complete
   stdout/stderr bytes.
3. After carrying the host and guest originals into one self-contained bundle,
   call `assemble_network_evidence(...)` with the HTTP report's own
   `tools-list.json` and `http-headers.json`, service observation, ready file,
   PC006 boundary, stdio launch, and stdio capture.  It writes the
   `p06-schema-identity-v1` and `network-evidence.json` Ref graph and calls the
   existing `_verify_network_evidence` gate before returning.

All touched paths must be ordinary files or directories inside
`approved_root`; every output root is created exclusively and is never reused.
`bundle_root` independently bounds evidence inputs, outputs, and emitted POSIX
Refs.  It may equal the approved root, contain a narrower approved phase, or be
a child of a larger approved workspace.  In that last layout the repository
and `.venv` may be a sibling of the bundle: they remain approved execution
inputs but are not evidence-package members.  The HTTP and stdio run IDs must
differ, while their restore attempt IDs must be equal.

Before creating an output directory or launching an executor/subprocess, each
public entry preflights the approved root, bundle root, every input, the output
parent, and the absent output target.  Evidence inputs and outputs must be in
both their approved scope and the bundle; repository/interpreter/bridge inputs
need only be in the approved workspace.  This applies to indirect evidence too:
the ready firewall Ref and the PC006 boundary's bound-source, dual-port, and
firewall Refs are path-checked against both roots before their target bytes or
hashes are read.  Dotdot components are rejected rather than normalized, and
absolute escapes, links, Windows reparse points, special files, and missing
parents are also rejected.  Thus an invalid path cannot first read an
unapproved original, create raw originals, or fail only later while calculating
a Ref.

```python
pc006 = collect_pc006(
    approved_root=phase_root,
    bundle_root=bundle_root,
    output_root=phase_root / "collected-pc006",
    ready_path=phase_root / "ready" / "ready.json",
    run_id=http_run_id,
    restore_attempt_id=attempt_id,
    probe_source_address="192.168.204.231",
    comparison_port=28787,
    vmx="/approved/path/Win10MalBox-Velo.vmx",
)

stdio = await collect_stdio(
    approved_root=approved_root,
    bundle_root=bundle_root,
    output_root=phase_root / "collected-stdio",
    repository_root=repository_root,
    python_executable=repository_root / ".venv" / "Scripts" / "python.exe",
    bridge_script=repository_root / "mcp_velociraptor_bridge.py",
    host_name="DESKTOP-3FI41GR",
    http_run_id=http_run_id,
    stdio_run_id=reserved_stdio_run_id,
    restore_attempt_id=attempt_id,
    expected_http_tools=http_run_dir / "tools-list.json",
    environment=approved_stdio_environment,
)
```

## Failure and cleanup

- A timeout, spawn/protocol/model error, nonzero or unavailable process exit,
  malformed collector output, schema mismatch, cross-run/cross-attempt input,
  bad Ref, or invalid firewall original raises `CollectionError`.
- Failed attempts retain `collection-failure.json` and any already obtained raw
  command/capture/launch files, but never publish `pc006.json` or a final
  `network-evidence.json` that could be mistaken for success.
- The assembler first sends pending, non-final schema/network names through the
  existing gate.  It creates the final names only after that succeeds, verifies
  the final Ref graph again, and removes only files owned by that new attempt
  on any validation, unexpected-type, or write exception.  The exclusive
  output root prevents cleanup from touching an earlier attempt.
- stdio timeout and cancellation close the SDK streams and invoke the SDK's
  platform process-tree shutdown before control returns.  The launch exit code
  comes from that owned child; leaving an SDK context is not treated as exit 0.
- Environment values are consumed only by the child.  They are not written to
  argv, launch JSON, failure JSON, or logs.  Only the fixed allowlist of
  non-secret runtime variable names is accepted.

The Windows tests use an isolated, file-backed synthetic MCP server to verify
the pipe and owned-process seam.  It is explicitly not a formal bridge or real
PC006 observation.  The PC006 executor seam likewise exercises the frozen
collector with controlled curl results and does not claim a network probe.
One full synthetic activation test replaces a cycle's fixture network graph
with artifacts produced by all three public functions, rebuilds its Ref and
manifest chain, and invokes the public `verify_activation_bundle` entry.  A
hash-recomputed semantic mutation of that produced PC006 graph is rejected.

## Preconditions still outside this module

- The main session must decide the formal PC006 restore-round lower/upper time
  contract.  This producer records actual times and does not substitute service
  process start for restore completion or invent a tolerance.
- PLAN-CHANGE-016 remains subject to the main session's normative decision.
- Real restore/ready/PC006/stdio reacquisition and activation are separate,
  explicitly authorized stages.  Passing these seams does not make the current
  historical activity package valid.
- Before any formal P05 execution, the main session must register
  `tests/p05_network_collect.py` in the P05 §0.7 frozen
  `implementation_sources` set.  This iteration does not edit PLAN or the
  validator allowlist.
