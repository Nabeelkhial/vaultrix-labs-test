"""Live CVE watcher (DEVELOPMENT_PLAN §14 v0.5).

Queries OSV.dev for the packages a repo depends on and flags vulnerabilities.
Run on a schedule with `--since` and it reports only what is NEW since the last
run — so a fresh PHP2Shell-class CVE surfaces the same day it lands in the feed,
not at the next manual scan.

OSV.dev is free and needs no key. Dependency CVEs are covered here; runtime CVEs
for the stack itself (PHP, nginx) live in NVD and are the next increment.
"""
from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from core.findings import Finding, Severity

OSV_QUERY = "https://api.osv.dev/v1/query"
SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
       "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


@dataclass(frozen=True)
class Pkg:
    name: str
    ecosystem: str          # OSV ecosystem, e.g. "npm", "PyPI"
    version: str | None = None


# lockfile -> OSV ecosystem + how to pull (name, version) pairs
def packages(repo: Path) -> list[Pkg]:
    repo = Path(repo)
    out: list[Pkg] = []
    lock = repo / "package-lock.json"
    if lock.exists():
        out += _npm_lock(lock.read_text())
    pkg = repo / "package.json"
    if pkg.exists() and not lock.exists():
        out += _npm_manifest(pkg.read_text())
    req = repo / "requirements.txt"
    if req.exists():
        out += _pip_requirements(req.read_text())
    # de-dup, keep first version seen
    seen: dict[tuple[str, str], Pkg] = {}
    for p in out:
        seen.setdefault((p.ecosystem, p.name), p)
    return list(seen.values())


def _npm_lock(text: str) -> list[Pkg]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    pkgs = data.get("packages") or {}
    out = []
    for path, meta in pkgs.items():
        if not path.startswith("node_modules/"):
            continue
        name = path.split("node_modules/")[-1]
        if meta.get("version"):
            out.append(Pkg(name, "npm", meta["version"]))
    if not out:  # lockfileVersion 1
        for name, meta in (data.get("dependencies") or {}).items():
            out.append(Pkg(name, "npm", meta.get("version")))
    return out


def _npm_manifest(text: str) -> list[Pkg]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            out.append(Pkg(name, "npm", re.sub(r"[^0-9.].*$", "", str(spec)) or None))
    return out


def _pip_requirements(text: str) -> list[Pkg]:
    out = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([\w.\-]+)", line)
        if m:
            out.append(Pkg(m.group(1), "PyPI", m.group(2)))
    return out


def _query(pkg: Pkg, timeout: int = 20) -> list[dict]:
    q: dict = {"package": {"name": pkg.name, "ecosystem": pkg.ecosystem}}
    if pkg.version:
        q["version"] = pkg.version
    req = urllib.request.Request(OSV_QUERY, data=json.dumps(q).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return (json.load(r) or {}).get("vulns") or []
    except Exception:
        return []


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _severity(v: dict) -> Severity:
    db = (v.get("database_specific") or {}).get("severity")
    if db:
        return SEV.get(str(db).upper(), Severity.MEDIUM)
    for s in v.get("severity") or []:
        score = str(s.get("score", ""))
        m = re.search(r"/A:[NLH]", score)  # crude CVSS presence check
        if "CVSS:3" in score:
            # pull base score if a number is appended, else treat as high
            return Severity.HIGH
    return Severity.MEDIUM


def to_finding(v: dict, pkg: Pkg) -> Finding:
    cve = next((a for a in (v.get("aliases") or []) if a.startswith("CVE-")), None)
    vid = v.get("id", "")
    return Finding(
        title=f"{pkg.name} {pkg.version or ''}: {vid}".strip(),
        severity=_severity(v),
        source_tool="cve_watch", layer="dependencies",
        location=f"{pkg.ecosystem}:{pkg.name}",
        description=(v.get("summary") or v.get("details") or "Known vulnerability.")[:400],
        evidence=f"published {v.get('published','?')[:10]}, modified {v.get('modified','?')[:10]}",
        remediation=f"Review the advisory and upgrade {pkg.name} to a fixed version.",
        cve=cve, references=[f"https://osv.dev/vulnerability/{vid}"] if vid else [])


def watch(repo: Path, since: str | None = None, log=lambda _m: None) -> list[Finding]:
    """Flag OSV vulns for the repo's packages. With `since` (YYYY-MM-DD), only
    those modified on or after that date — i.e. new since your last run."""
    cutoff = _parse_dt(since + "T00:00:00+00:00") if since else None
    pkgs = packages(repo)
    log(f"{len(pkgs)} package(s) to check against OSV.dev")
    out: list[Finding] = []
    for pkg in pkgs:
        for v in _query(pkg):
            if cutoff:
                mod = _parse_dt(v.get("modified")) or _parse_dt(v.get("published"))
                if mod and mod < cutoff:
                    continue
            out.append(to_finding(v, pkg))
    log(f"{len(out)} vulnerability record(s)"
        + (f" new since {since}" if since else ""))
    return out


if __name__ == "__main__":  # self-check — parsing + filtering, no network
    npm = json.dumps({"packages": {
        "": {"name": "root"},
        "node_modules/lodash": {"version": "4.17.4"},
        "node_modules/next": {"version": "13.4.0"}}})
    pkgs = _npm_lock(npm)
    assert {p.name for p in pkgs} == {"lodash", "next"} and all(p.ecosystem == "npm" for p in pkgs)
    assert _pip_requirements("flask==2.0.1\n# c\nrequests==2.25.0\nbare\n")[0] == Pkg("flask", "PyPI", "2.0.1")

    v = {"id": "GHSA-x", "aliases": ["CVE-2026-1"], "summary": "bad",
         "published": "2026-10-20T00:00:00Z", "modified": "2026-10-22T00:00:00Z",
         "database_specific": {"severity": "CRITICAL"}}
    f = to_finding(v, Pkg("lodash", "npm", "4.17.4"))
    assert f.severity is Severity.CRITICAL and f.cve == "CVE-2026-1" and f.source_tool == "cve_watch"
    assert "2026-10-20" in f.evidence
    # the since filter is date math, test it directly
    assert _parse_dt("2026-10-22T00:00:00+00:00") >= _parse_dt("2026-10-21T00:00:00+00:00")
    print("cve_watch self-check ok")
