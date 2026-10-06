# Windows daily service verification — 2026-10-06

Scope: the existing `mcp-velociraptor` service on the Windows guest with IPv4
suffix `.149`, using its existing virtual account and deployment configuration.
Only the formal SCM launcher and daily service-management script were deployed.
The established adapter and bridge implementation were retained.

## Configuration readback

- Launch file: repository-relative `velociraptor_windows_service.py`.
- Account: `NT SERVICE\mcp-velociraptor`; startup: Auto.
- SCM recovery: three restart actions, each delayed 10000 ms; the last action
  repeats for subsequent failures; reset period 86400 seconds.
- Noncrash failure flag: enabled. Windows documents that this flag takes effect
  on the next system start; no immediate-effect claim is made here. The periodic
  task also covers stopped services in the current boot.
- Keepalive task: `mcp-velociraptor-keepalive`, SYSTEM, enabled, startup trigger
  and indefinitely repeating one-minute time trigger; last execution result 0.
- Configuration script's `verify` mode passed on Windows.

## Actual lifecycle checks

The original PID was 3080. After switching the launch file, PID 3352 ran the
formal launcher and owned the listener on the measured guest IP, port 28790.

With the keepalive task disabled, the verified bridge process was terminated.
SCM alone restarted it as PID 6120 and restored the listener in 13.58 seconds
(configured delay plus startup and measurement overhead). The task was then
re-enabled.

A normal stop was separately observed with service exit code 0. With keepalive
disabled it remained Stopped for more than 12 seconds, establishing that SCM
failure recovery did not restart that clean stop. After re-enabling keepalive,
the existing periodic trigger started PID 6988; task result was 0 and the
listener belonged to that PID. No direct Start-Service was issued for this
controlled periodic-recovery check.

An authenticated official SDK session then completed initialize and tools/list,
returning 137 tools, including `run_vql`. No collection or other business tool
was invoked. Python compilation and native PowerShell parsing passed.

Original guest records are retained under
`Logs/service-management-c9f50f212e5d4beeb4a050d96b8dc234/`, including previous
SCM configuration and the independent crash/normal-stop checks. These are
operational checks, not a five-scenario or full product acceptance claim.
The VM was not rebooted; automatic startup and boot task were read back only.

## Local checks and remaining issue

The formal launcher's subprocess regression checks deployment-relative adapter
selection from an unrelated working directory, retained exit code and empty
stdout/stderr. The existing installer, bridge diagnostics and four SCM status/
stop callbacks also pass (23 tests total). The scoped syntax check covers the
new launcher plus the five files listed in AGENTS.md; `git diff --check` passes.

The broader existing `test_p05_service_stop_order` module has one stale test:
`test_actual_bridge_startup_rejection_survives_scm_mapping_without_exception_text`
supplies a mocked HTTP config without the current `observation_enabled` field
and patches the former precheck path. It consequently selects daily mode and
fails its old unconditional-archive-rejection expectation. That test and product
code were not changed in this service-management iteration; it is excluded
from the passing scoped command below.

```text
.venv/bin/python -m unittest tests.test_windows_service_entry tests.test_p05_service_script tests.test_bridge_service_diagnostics tests.test_p05_service_stop_order.ServiceStopOrderTests.test_pending_is_reported_before_bridge_observes_stop tests.test_p05_service_stop_order.ServiceStopOrderTests.test_stop_signal_survives_failed_pending_report tests.test_p05_service_stop_order.ServiceStopOrderTests.test_status_report_checks_native_failure tests.test_p05_service_stop_order.ServiceStopOrderTests.test_stopped_status_is_reported_only_once_if_native_call_fails
```

The native stop command returned SCM error 1061 even though the callback
completed a clean stop. Observed STOPPED/zero exit and subsequent recovery are
the lifecycle evidence; the command's return is not represented as success.
The bounded next improvement is to correct SCM stop acknowledgement, then
update the stale strict-mode test separately. For current planned maintenance,
disable keepalive first and inspect actual service status after requesting stop.
