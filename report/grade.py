"""Vaultrix Labs grade. Deterministic, so two runs on the same findings agree."""
from __future__ import annotations

from core.findings import Finding, Severity

PENALTY = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 7,
           Severity.LOW: 2, Severity.INFO: 0}
BANDS = [(90, "A"), (80, "B"), (65, "C"), (50, "D"), (0, "F")]
# A single serious finding caps the grade regardless of points: five mediums are
# not "as bad as" one leaked service_role key, and the letter has to say so.
CAP = {Severity.CRITICAL: "F", Severity.HIGH: "C", Severity.MEDIUM: "B"}
ORDER = "ABCDF"

HEADLINE = {
    "A": "No material issues found in what we can see from outside.",
    "B": "Mostly solid. A few hardening gaps worth closing.",
    "C": "Real gaps. Fixable in an afternoon, but do not leave them.",
    "D": "Serious problems. Treat this as urgent.",
    "F": "Critical exposure. Assume an attacker could already be inside.",
}


def worst_per_place(findings: list[Finding]) -> list[Finding]:
    """One finding per (layer, location). Forty-eight CVEs in one package are a
    single action — `upgrade lodash` — and must not outweigh everything else."""
    best: dict[tuple[str, str], Finding] = {}
    for f in findings:
        k = (f.layer, f.location)
        if k not in best or f.rank > best[k].rank:
            best[k] = f
    return list(best.values())


def score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(PENALTY[f.severity] for f in worst_per_place(findings)))


def grade(findings: list[Finding]) -> tuple[str, int, str]:
    s = score(findings)
    letter = next(l for lo, l in BANDS if s >= lo)
    for sev, cap in CAP.items():
        if any(f.severity is sev for f in findings):
            letter = max(letter, cap, key=ORDER.index)
            break
    return letter, s, HEADLINE[letter]


def counts(findings: list[Finding]) -> dict[Severity, int]:
    return {sev: sum(1 for f in findings if f.severity is sev) for sev in Severity}


if __name__ == "__main__":  # self-check
    mk = lambda sev: Finding("t", sev, "x", "l", "loc", "d")
    assert grade([])[0] == "A"
    assert grade([mk(Severity.CRITICAL)])[0] == "F"
    assert grade([mk(Severity.HIGH)])[0] == "C", "one high caps at C even on points"
    assert grade([mk(Severity.MEDIUM)])[0] == "B"
    assert grade([mk(Severity.LOW)] * 2)[0] == "A"
    assert grade([mk(Severity.HIGH)] * 3)[0] == "C", "three highs in one place are one action"
    spread = [Finding("t", Severity.HIGH, "x", "l", f"loc{i}", "d") for i in range(3)]
    assert grade(spread)[0] == "F", "points still push below the cap"
    assert score([mk(Severity.CRITICAL)] * 5) == 60, "same place counts once"
    many = [Finding("t", Severity.CRITICAL, "x", "l", f"loc{i}", "d") for i in range(5)]
    assert score(many) == 0, "score never goes negative"
    print("grade self-check ok")
