"""Unified finding model. Every scanner collapses into this."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ProofStatus(str, Enum):
    PROVEN = "proven"      # PoC succeeded in the sandbox
    UNPROVEN = "unproven"  # flagged by a tool, not yet confirmed
    FIXED = "fixed"        # patch applied and re-verified closed


_SEV_RANK = {s: i for i, s in enumerate(
    [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])}
_PROOF_RANK = {ProofStatus.UNPROVEN: 0, ProofStatus.PROVEN: 1, ProofStatus.FIXED: 2}


@dataclass
class Finding:
    title: str
    severity: Severity
    source_tool: str          # "headers" | "nuclei" | "js_secrets" ...
    layer: str                # "secrets"|"authz"|"runtime"|"transport"|"exposure"...
    location: str             # file:line, route, or host
    description: str
    evidence: str = ""        # redacted match / response excerpt
    proof: ProofStatus = ProofStatus.UNPROVEN
    remediation: str = ""
    cwe: str | None = None
    cve: str | None = None
    references: list[str] = field(default_factory=list)
    id: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = hashlib.sha256(self.dedupe_key().encode()).hexdigest()[:12]

    def dedupe_key(self) -> str:
        # Trivy says CVE-2019-10744, OSV says GHSA-jf85-cpcp-j695 for the same hole.
        # When a CVE is known it is the identity; the title is just the tool's wording.
        ident = self.cve or self.title
        return f"{self.layer}:{self.location}:{ident}".lower()

    @property
    def rank(self) -> tuple[int, int]:
        return (_SEV_RANK[self.severity], _PROOF_RANK[self.proof])


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge same-key findings; strongest severity+proof wins. Sorted worst-first."""
    best: dict[str, Finding] = {}
    for f in findings:
        k = f.dedupe_key()
        cur = best.get(k)
        if cur is None:
            best[k] = f
            continue
        # keep the stronger one, but union the tools that reported it
        winner, loser = (f, cur) if f.rank > cur.rank else (cur, f)
        if loser.source_tool not in winner.source_tool:
            winner.source_tool = f"{winner.source_tool}+{loser.source_tool}"
        best[k] = winner
    return sorted(best.values(), key=lambda f: (-f.rank[0], -f.rank[1], f.title))
