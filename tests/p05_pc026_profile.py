"""Explicit evidence generations; historical predicates keep their defaults."""
from dataclasses import dataclass
from tests import p05_pc020_evidence as evidence


@dataclass(frozen=True)
class Generation:
    number: int
    snapshot: str
    retained: tuple[str, ...]
    retired_append: tuple[str, ...]


HISTORICAL = Generation(189, evidence.SNAPSHOT_189,
    (evidence.SNAPSHOT_187, evidence.SNAPSHOT_188), (evidence.SNAPSHOT_187,))
CURRENT = Generation(191, "Snapshot 191-Velociraptor-MCP可恢复验收基线",
    (evidence.SNAPSHOT_187, evidence.SNAPSHOT_188, evidence.SNAPSHOT_189,
     "Snapshot 190-velo-mcp-18fce616-新版保留-验收未全通过"),
    (evidence.SNAPSHOT_187, evidence.SNAPSHOT_189,
     "Snapshot 190-velo-mcp-18fce616-新版保留-验收未全通过"))


def reviewed(value):
    if value not in (HISTORICAL, CURRENT):
        raise evidence.Pc020EvidenceError("unreviewed evidence generation")
    return value
