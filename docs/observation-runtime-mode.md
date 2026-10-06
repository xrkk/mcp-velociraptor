# Observation archive runtime mode

Daily HTTP operation defaults to `VELOCIRAPTOR_MCP_OBSERVATION=off` (also the
default when absent). It uses the stateful official SDK server, the same 137
tools, bearer authentication, exact Host/Origin checks, session ownership and
binary transfer gates. It does not construct an archive controller, load PC026
approval inputs, enforce the archival interpreter/source pin, or publish
observation cuts and archival completion receipts. Ordinary DELETE success
means SDK session closure, without an archival audit claim.

For strict auditing, explicitly set `VELOCIRAPTOR_MCP_OBSERVATION=approved` in
the service's protected environment file and restart the service. This selects
the existing approved native archive path before backend initialization or
listening. The switch does not grant approval: the complete current fixed
governance inputs, approved source/SDK pin, private Windows storage identity,
permissions and resource budgets must already pass the original checks.
Missing or stale approval rejects startup as `OBSERVATION_STARTUP_REJECTED`.

Only `off` and `approved` are accepted (case insensitive). Invalid or empty
values reject configuration; `approved` with stdio is rejected because that
transport provides no archival integration. Mode changes require a new process;
they do not turn a daily session into an audited session or qualify old results.
