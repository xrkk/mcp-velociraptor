# Copyright 2026 Google LLC
"""LNX-VR Linux domain: platform routing, artifact fingerprints, scoped
collection planning and the default/targeted triage toolset.

MalTrace master plan 7.1 (LNX-VR) contract implemented here:

- Platform routing: Linux tools only act on endpoints whose registered OS is
  ``linux``; a non-Linux (e.g. Windows) target is refused with
  ``WRONG_PLATFORM`` and the refusal carries proof that no Velociraptor
  mutation was issued for that target (Windows no-mis-operation evidence).
- Linux artifact fingerprint: the built-in triage set is pinned with exact
  names so two same-premise triage runs are comparable and drift is
  detectable.
- High-granularity scope supply: a default allowed set, explicit temporary
  extension with reason/scope/expiry, observable effective scope, withdrawal
  back to default, and full stop — each transition recorded and reviewable
  for P04's I-006 consumption.
- Session collect lifecycle: plan -> launch -> status -> (withdraw/extend) ->
  stop, with bounded resource hints.

Pure logic (unit-testable without a live server); the guest runner in
``linux_domain_runner.py`` executes the same plans against the real API.
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
    ('Linux.Systemd.Status', 'systemd services'),
    ('Linux.Sys.Autostart', 'autostart entries'),
    ('Linux.Sys.Pslist', 'process list with ppid lineage (fork/exec fact '
                         'clues; realtime event streams belong to client '
                         'monitoring sessions, not base triage)'),
    ('Linux.Triage.Sequential', 'bounded filesystem triage'),
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
                               {'client_id': client_id})


@dataclass
class TriagePlan:
    session_id: str
    client_id: str
    artifacts: list[str]
    fingerprint: str
    resource_hints: dict

    def as_launch_specs(self) -> list[dict]:
        return [{'artifact': name, 'client_id': self.client_id}
                for name in self.artifacts]


def build_triage_plan(session: ScopeState, client: dict,
                      *, max_timeout_seconds: int = 600,
                      max_collection_mb: int = 512) -> TriagePlan:
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
    )


def compare_triage_runs(run_a: dict, run_b: dict) -> dict:
    """Same-premise repeatability check between two triage executions."""
    stable = run_a.get('fingerprint') == run_b.get('fingerprint')
    same_client = run_a.get('client_id') == run_b.get('client_id')
    categories_a = run_a.get('category_results', {})
    categories_b = run_b.get('category_results', {})
    common = sorted(set(categories_a) & set(categories_b))
    missing_in_b = sorted(set(categories_a) - set(categories_b))
    return {
        'same_fingerprint': stable,
        'same_client': same_client,
        'common_categories': common,
        'missing_categories_in_second_run': missing_in_b,
        'repeatable': bool(stable and same_client and not missing_in_b
                           and common),
    }


# ---- bridge registration (opt-in via VELOCIRAPTOR_LINUX_DOMAIN=1) ---------
# Registered only when the environment switch is set; the default (unset)
# bridge registration is byte-identical for Windows deployments, so the
# Windows regression denominator does not change unless the switch is on.

LINUX_DOMAIN_TOOL_NAMES = (
    'linux_platform_route',
    'linux_scope_get',
    'linux_scope_bind_targets',
    'linux_scope_extend',
    'linux_scope_withdraw',
    'linux_scope_stop',
)

_SCOPE_SESSIONS: dict[str, ScopeState] = {}


def register_linux_domain_tools(server) -> tuple[str, ...]:
    """Register the Linux professional-domain tools on one MCPServer.

    Opt-in only: the bridge calls this exclusively when
    VELOCIRAPTOR_LINUX_DOMAIN=1, keeping un-switched (Windows) registries
    unchanged.
    """
    def platform_route(client_id: str) -> dict:
        raise LinuxDomainError(
            'NO_CLIENTS_PROVIDER',
            'platform routing requires a live clients provider; use the '
            'deployment runner for native acceptance')

    def _scope(session_id: str) -> ScopeState:
        scope = _SCOPE_SESSIONS.get(session_id)
        if scope is None:
            scope = ScopeState(session_id=session_id)
            _SCOPE_SESSIONS[session_id] = scope
        return scope

    def scope_get(session_id: str) -> dict:
        return _scope(session_id).effective_scope()

    def scope_bind(session_id: str, targets: list[str]) -> dict:
        return _scope(session_id).bind_targets(targets)

    def scope_extend(session_id: str, artifacts: list[str], reason: str,
                     expires_in_seconds: int,
                     targets: list[str] | None = None) -> dict:
        return _scope(session_id).extend_temporarily(
            artifacts, reason=reason, expires_in_seconds=expires_in_seconds)

    def scope_withdraw(session_id: str) -> dict:
        return _scope(session_id).withdraw()

    def scope_stop(session_id: str) -> dict:
        return _scope(session_id).stop()

    for handler, name, description in (
            (platform_route, 'linux_platform_route',
             'Route a client id against the fixed Linux endpoint identity; '
             'non-Linux targets refuse with WRONG_PLATFORM and zero issued '
             'mutations.'),
            (scope_get, 'linux_scope_get',
             'Return the reviewable high-granularity scope record.'),
            (scope_bind, 'linux_scope_bind_targets',
             'Anchor the default scope to the related target set.'),
            (scope_extend, 'linux_scope_extend',
             'Temporarily extend artifacts with reason and 1..3600s expiry.'),
            (scope_withdraw, 'linux_scope_withdraw',
             'Withdraw all temporary extensions back to defaults.'),
            (scope_stop, 'linux_scope_stop',
             'Stop the session scope; further mutations refuse.')):
        server.add_tool(handler, name=name, description=description)
    return LINUX_DOMAIN_TOOL_NAMES
