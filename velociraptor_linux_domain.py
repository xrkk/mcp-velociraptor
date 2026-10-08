# Copyright 2026 Google LLC
"""Linux professional registry and historical in-memory scope records.

Production scope tools use the persistent custom kernel backend.
Production basic triage uses the injected LinuxTriageBackend and full original
artifact fingerprints. ScopeState and its hints are bookkeeping only: they do
not implement realtime collection, scope activation, expiry, withdrawal or stop.
The historical name-only plan is not native collection evidence.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable

LINUX_OS_VALUES = frozenset({'linux', 'Linux'})

# Artifact fingerprint for the default Linux triage (exact built-in names).
DEFAULT_TRIAGE_ARTIFACTS: tuple[tuple[str, str], ...] = (
    ('Generic.Client.Info', 'host/process context'),
    ('Linux.Sys.Users', 'local accounts'),
    ('Linux.Network.Netstat', 'connections with process mapping'),
    ('Linux.Sys.Crontab', 'cron persistence'),
    ('Linux.Sys.Services', 'systemd service inventory'),
    ('Linux.Sys.Pslist', 'process list with ppid lineage (fork/exec fact '
                         'clues; realtime event streams belong to client '
                         'monitoring sessions, not base triage)'),
    ('Linux.Search.FileFinder', 'bounded file metadata/hash/acquisition and system/user/timer definitions'),
    ('Linux.Forensics.Journal', 'bounded system/security logs'),
)

SCOPE_KINDS = frozenset({'default', 'temporary_extension'})


class LinuxDomainError(Exception):
    def __init__(self, code: str, message: str, details: dict | None = None):
        super().__init__(f'{code}: {message}')
        self.code = code
        self.message = message
        self.details = details or {}


def fingerprint_artifacts(artifacts: Iterable[str]) -> str:
    joined = '\n'.join(sorted(artifacts))
    return hashlib.sha256(joined.encode('utf-8')).hexdigest()


def default_artifact_names() -> list[str]:
    return [name for name, _ in DEFAULT_TRIAGE_ARTIFACTS]


@dataclass
class ScopeState:
    """Reviewable high-granularity scope for one session."""

    session_id: str
    allowed_artifacts: set[str] = field(
        default_factory=lambda: set(default_artifact_names()))
    targets: frozenset[str] = frozenset()
    mode: str = 'default'  # default | temporary_extension
    extensions: list[dict] = field(default_factory=list)
    transitions: list[dict] = field(default_factory=list)
    stopped: bool = False

    def _record(self, action: str, **payload) -> None:
        self.transitions.append({
            'action': action,
            'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            **payload,
        })

    def effective_scope(self) -> dict:
        return {
            'session_id': self.session_id,
            'mode': self.mode,
            'allowed_artifacts': sorted(self.allowed_artifacts),
            'targets': sorted(self.targets),
            'target_semantics': (
                'high-granularity default scope covers ONLY the bound '
                'related targets; unrelated subjects are out of scope'),
            'fingerprint': fingerprint_artifacts(self.allowed_artifacts),
            'active_extensions': [e for e in self.extensions
                                  if e.get('active')],
            'stopped': self.stopped,
            'backend_applied': False,
            'limitation': 'in-memory bookkeeping only; no actual collection scope effects',
        }

    def bind_targets(self, targets: Iterable[str]) -> dict:
        """Anchor the default scope to the session's related target set.

        The high-granularity default covers only related targets
        (pids/paths/users of the current causal chain, supplied by P04);
        base triage artifacts are NOT narrowed by this binding.
        """
        if self.stopped:
            raise LinuxDomainError('SCOPE_STOPPED',
                                   'session scope already stopped')
        cleaned = sorted({str(t).strip() for t in targets if str(t).strip()})
        if not cleaned:
            raise LinuxDomainError('INVALID_ARGUMENT',
                                   'at least one non-empty target required')
        self.targets = frozenset(cleaned)
        self._record('bind_targets', targets=cleaned)
        return self.effective_scope()

    @staticmethod
    def target_vql_hints(targets: Iterable[str]) -> dict:
        """Reviewable mapping of targets to collector parameters, proving
        the actually-effective collection range (I-006 observable proof)."""
        paths = sorted({t for t in targets if t.startswith('/')})
        others = sorted(set(targets) - set(paths))
        return {
            'path_globs': paths,
            'subject_filters': others,
            'collector_bindings': {
                # targeted acquisition binds globs through the on-demand
                # file finder (hashing optional), not a base-triage artifact
                'Linux.Search.FileFinder': ({'Globs': paths}
                                            if paths else None),
            },
            'unrelated_exclusion': 'globs/filters outside the bound target '
                                   'set are not collected in high-granularity '
                                   'scope',
        }

    def extend_temporarily(self, artifacts: Iterable[str], reason: str,
                           expires_in_seconds: int) -> dict:
        if self.stopped:
            raise LinuxDomainError('SCOPE_STOPPED',
                                   'session scope already stopped')
        reason = (reason or '').strip()
        if not reason:
            raise LinuxDomainError('INVALID_ARGUMENT',
                                   'temporary extension requires a reason')
        if expires_in_seconds <= 0 or expires_in_seconds > 3600:
            raise LinuxDomainError('INVALID_ARGUMENT',
                                   'expiry must be 1..3600 seconds')
        if not isinstance(self.allowed_artifacts, set):
            self.allowed_artifacts = set(self.allowed_artifacts)
        added = sorted({a for a in artifacts if a not in self.allowed_artifacts})
        if not added:
            raise LinuxDomainError('INVALID_ARGUMENT',
                                   'artifacts already in allowed set')
        extension = {
            'artifacts': added,
            'reason': reason,
            'expires_in_seconds': expires_in_seconds,
            'active': True,
        }
        # optional target-set widening rides the same extension record
        ext_targets = None
        self.extensions.append(extension)
        self.allowed_artifacts.update(added)
        self.mode = 'temporary_extension'
        self._record('extend', artifacts=added, reason=reason,
                     expires_in_seconds=expires_in_seconds,
                     targets=ext_targets)
        return self.effective_scope()

    def withdraw(self) -> dict:
        """Withdraw all temporary extensions back to the default set."""
        if self.stopped:
            raise LinuxDomainError('SCOPE_STOPPED',
                                   'session scope already stopped')
        current = set(self.allowed_artifacts)
        withdrawn = sorted(current - set(default_artifact_names()))
        self.allowed_artifacts = set(default_artifact_names())
        # withdrawn extensions never leave widened targets behind
        self.extensions = [dict(e, active=False) for e in self.extensions]
        self.mode = 'default'
        self._record('withdraw', artifacts=withdrawn)
        return self.effective_scope()

    def stop(self) -> dict:
        self.stopped = True
        self._record('stop')
        return self.effective_scope()


class LinuxPlatformRouter:
    """Route Linux-domain actions by registered client OS only."""

    def __init__(self, clients_provider):
        """clients_provider() -> list of {client_id, os, hostname} dicts."""
        self._clients_provider = clients_provider

    def list_linux_clients(self) -> list[dict]:
        return [c for c in self._clients_provider()
                if c.get('os') in LINUX_OS_VALUES]

    def resolve_linux_target(self, client_id: str | None = None) -> dict:
        clients = self._clients_provider()
        linux = [c for c in clients if c.get('os') in LINUX_OS_VALUES]
        if client_id is None:
            if len(linux) == 1:
                return linux[0]
            raise LinuxDomainError(
                'LINUX_CLIENT_NOT_UNIQUE',
                'pass an explicit client_id or register exactly one Linux client',
                {'linux_clients': [c['client_id'] for c in linux]})
        matching = [c for c in clients if c.get('client_id') == client_id]
        if len(matching) > 1:
            raise LinuxDomainError('LINUX_CLIENT_NOT_UNIQUE', 'ambiguous client identity',
                                   {'velociraptor_mutations_issued': 0})
        match = next((c for c in linux if c['client_id'] == client_id), None)
        if match is not None:
            return match
        other = next((c for c in clients if c['client_id'] == client_id), None)
        if other is not None:
            raise LinuxDomainError(
                'WRONG_PLATFORM',
                'target is registered as %s, Linux tools refuse' % other.get('os'),
                {'client_id': client_id, 'os': other.get('os'),
                 'velociraptor_mutations_issued': 0})
        raise LinuxDomainError('CLIENT_NOT_FOUND',
                               'client id not registered',
                               {'client_id': client_id, 'velociraptor_mutations_issued': 0})


@dataclass
class TriagePlan:
    session_id: str
    client_id: str
    artifacts: list[str]
    fingerprint: str
    resource_hints: dict
    parameters: dict = field(default_factory=dict)

    def as_launch_specs(self) -> list[dict]:
        return [{'artifact': name, 'client_id': self.client_id,
                 'parameters': dict(self.parameters.get(name, {})),
                 'timeout': self.resource_hints['timeout_seconds'],
                 'max_bytes': self.resource_hints['max_collection_mb'] * 1024 * 1024}
                for name in self.artifacts]


def build_triage_plan(session: ScopeState, client: dict,
                      *, max_timeout_seconds: int = 600,
                      max_collection_mb: int = 512, parameters: dict | None = None) -> TriagePlan:
    if session.stopped:
        raise LinuxDomainError('SCOPE_STOPPED', 'session scope already stopped')
    artifacts = sorted(session.allowed_artifacts)
    return TriagePlan(
        session_id=session.session_id,
        client_id=client['client_id'],
        artifacts=artifacts,
        fingerprint=fingerprint_artifacts(artifacts),
        resource_hints={'timeout_seconds': max_timeout_seconds,
                        'max_collection_mb': max_collection_mb},
        parameters=parameters or {},
    )


def compare_triage_runs(run_a: dict, run_b: dict) -> dict:
    """Verify actual closed originals; matching names or ERROR states never pass."""
    from velociraptor_linux_backend import compare_verified
    return compare_verified(run_a, run_b)


# ---- bridge registration (opt-in via VELOCIRAPTOR_LINUX_DOMAIN=1) ---------
# Registered only when the environment switch is set; the default (unset)
# bridge registration is byte-identical for Windows deployments, so the
# Windows regression denominator does not change unless the switch is on.

LINUX_DOMAIN_TOOL_NAMES = (
    'linux_platform_route',
    'linux_scope_apply', 'linux_scope_update', 'linux_scope_query', 'linux_scope_export',
    'linux_scope_get',
    'linux_scope_bind_targets',
    'linux_scope_extend',
    'linux_scope_withdraw',
    'linux_scope_stop',
    'linux_triage_launch', 'linux_triage_status', 'linux_triage_results',
    'linux_triage_export', 'linux_triage_cancel', 'linux_triage_collect',
    'linux_triage_compare',
)


def register_linux_domain_tools(server, *, clients_provider=None, backend=None) -> tuple[str, ...]:
    """Register the Linux professional-domain tools on one MCPServer.

    Opt-in only: the bridge calls this exclusively when
    VELOCIRAPTOR_LINUX_DOMAIN=1, keeping un-switched (Windows) registries
    unchanged.
    """
    def platform_route(client_id: str) -> dict:
        if backend is not None:
            return backend.route(client_id)
        if clients_provider is None:
            raise LinuxDomainError('NO_CLIENTS_PROVIDER', 'live clients provider is required')
        return LinuxPlatformRouter(clients_provider).resolve_linux_target(client_id)

    def professional():
        if backend is None:
            raise LinuxDomainError('NO_TRIAGE_BACKEND', 'real professional backend is required')
        return backend

    def triage_launch(session_id: str, run_id: str, client_id: str, plan: dict) -> dict:
        return professional().launch(session_id, run_id, client_id, plan)

    def triage_status(run_id: str) -> dict:
        return professional().status(run_id)

    def triage_results(run_id: str) -> dict:
        return professional().results(run_id)

    def triage_export(run_id: str, include_bytes: bool = False) -> dict:
        return professional().export(run_id, include_bytes=include_bytes)

    def triage_cancel(run_id: str) -> dict:
        return professional().cancel(run_id)

    def triage_collect(session_id: str, run_id: str, client_id: str, plan: dict) -> dict:
        return professional().collect(session_id, run_id, client_id, plan)

    def triage_compare(first: str, second: str) -> dict:
        return professional().compare(first, second)

    for handler, name in ((triage_launch, 'linux_triage_launch'),
                          (triage_status, 'linux_triage_status'),
                          (triage_results, 'linux_triage_results'),
                          (triage_export, 'linux_triage_export'),
                          (triage_cancel, 'linux_triage_cancel'),
                          (triage_collect, 'linux_triage_collect'),
                          (triage_compare, 'linux_triage_compare')):
        server.add_tool(handler, name=name, description='Bounded real Linux basic triage; no realtime scope qualification.')

    def scoped(action, request):
        from velociraptor_linux_scope import ScopeBackend
        return ScopeBackend(professional()).call(action, request)

    def scope_apply(request: dict) -> dict:
        return scoped('apply', request)

    def scope_update(request: dict) -> dict:
        return scoped('update', request)

    def scope_query(request: dict) -> dict:
        return scoped('query', request)

    def scope_export(request: dict) -> dict:
        return scoped('export', request)

    def scope_extend(request: dict) -> dict:
        return scoped('extend', request)

    def scope_withdraw(request: dict) -> dict:
        return scoped('withdraw', request)

    def scope_stop(request: dict) -> dict:
        return scoped('stop', request)

    server.add_tool(platform_route, name='linux_platform_route', description='Resolve the fixed Linux client.')
    for handler, names in (
            (scope_apply, ('linux_scope_apply',)),
            (scope_update, ('linux_scope_update', 'linux_scope_bind_targets')),
            (scope_query, ('linux_scope_query', 'linux_scope_get')),
            (scope_export, ('linux_scope_export',)),
            (scope_extend, ('linux_scope_extend',)),
            (scope_withdraw, ('linux_scope_withdraw',)),
            (scope_stop, ('linux_scope_stop',))):
        for name in names:
            server.add_tool(handler, name=name, description='Durable bounded professional kernel scope; explicit identity request required.')
    return LINUX_DOMAIN_TOOL_NAMES
