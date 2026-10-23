"""IDOR / broken-object-level-authorization prober — the bug class a URL scan
cannot see and that AI writes most often: the app checks that you are logged in,
but not that the record is yours.

Confirmed exploitation only. A finding this returns is PROVEN: user A was logged
in and actually received user B's data. Nothing here is a guess.
"""
from __future__ import annotations

import hashlib

from core.findings import Finding, ProofStatus, Severity
from core.net import Client
from core.seed import Seed, SeedUser


def _id(path: str) -> str:
    return "idor-" + hashlib.sha256(path.encode()).hexdigest()[:8]


def probe_one(attacker: Client, attacker_user: SeedUser,
              victim: SeedUser, path: str) -> Finding | None:
    """Logged in as the attacker, request a path owned by the victim. If the
    victim's unique marker comes back with a 2xx, authorization is broken."""
    resp = attacker.get(path)
    leaked = resp.ok and 200 <= resp.status < 300 and victim.marker and victim.marker in resp.body
    if not leaked:
        return None
    excerpt = resp.body[:200].replace(victim.marker, f">>>{victim.marker}<<<")
    return Finding(
        id=_id(path),
        title="Broken object-level authorization (IDOR)",
        severity=Severity.CRITICAL,
        source_tool="idor_prober",
        layer="authz",
        location=path,
        description=(f"Logged in as {attacker_user.email}, we requested {path} — a record owned by "
                     f"{victim.email} — and the server returned it. Any logged-in user can read other "
                     "users' data by changing the id in the URL. This is confirmed, not suspected: the "
                     "response contained data that belongs only to the other account."),
        evidence=f"GET {path} as {attacker_user.email} -> {resp.status}; response carried the victim's marker:\n{excerpt}",
        proof=ProofStatus.PROVEN,
        remediation=("Scope every query to the caller — `where user_id = auth.uid()` — or enable row-level "
                     "security on the table so the database enforces ownership regardless of the query."),
        cwe="CWE-639",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
    )


def probe(seed: Seed, clients: dict[str, Client]) -> list[Finding]:
    """Every ordered pair of users: can one read the other's resources?

    `clients` maps user email -> an authenticated Client for that user.
    """
    out: list[Finding] = []
    seen: set[str] = set()
    for attacker in seed.users:
        ac = clients.get(attacker.email)
        if ac is None:
            continue
        for victim in seed.users:
            if victim is attacker:
                continue
            for path in victim.owns:
                f = probe_one(ac, attacker, victim, path)
                if f and f.id not in seen:
                    seen.add(f.id)
                    out.append(f)
    return out


if __name__ == "__main__":  # self-check — fake Clients, no network
    class _Fake(Client):
        def __init__(self, body, status=200):
            self._body, self._status = body, status

        def get(self, path, **kw):
            from core.net import Resp
            return Resp(url=path, status=self._status, body=self._body)

    a = SeedUser("a@x.test", "pw", owns=["/api/records/1"], marker="MARKER_A_7f3")
    b = SeedUser("b@x.test", "pw", owns=["/api/records/2"], marker="MARKER_B_9a1")
    seed = Seed([a, b])

    # vulnerable: A's client returns B's data for any path
    vuln = {"a@x.test": _Fake("secret of b: MARKER_B_9a1"), "b@x.test": _Fake("MARKER_A_7f3")}
    fs = probe(seed, vuln)
    assert any(f.proof is ProofStatus.PROVEN for f in fs), "must prove the leak"
    assert any(">>>MARKER_B_9a1<<<" in f.evidence for f in fs), "evidence must show the marker"

    # fixed: ownership enforced -> 403, no marker
    safe = {"a@x.test": _Fake("forbidden", status=403), "b@x.test": _Fake("forbidden", status=403)}
    assert probe(seed, safe) == [], "a 403 is not a finding"

    # subtle: 200 but no victim marker (returned the attacker's own record) -> no finding
    own = {"a@x.test": _Fake("MARKER_A_7f3"), "b@x.test": _Fake("MARKER_B_9a1")}
    assert probe(seed, own) == [], "seeing your own data is not IDOR"
    print("idor_prober self-check ok")
