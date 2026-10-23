"""OSV-Scanner (Apache-2.0) — second opinion on dependencies, via OSV.dev.

Deliberately overlaps Trivy: DEVELOPMENT_PLAN §1 — only ~22% of AI-code vulns
are caught by more than one tool, so one scanner is not enough. Dedupe merges
whatever both find.
"""
from __future__ import annotations

import json

from core.findings import Finding, Severity
from scanners._tool import MOUNT, Tool, run as run_tool

# Google publishes only a floating `:latest` here, so §5's "pull by digest" is not
# optional. This is the image's RepoDigest — the registry reference `docker pull`
# resolves. (Do not take it from `docker manifest inspect -v`: that reports a
# platform manifest digest, which is a different hash and will not pull.)
TOOL = Tool(name="osv-scanner", network=True,
            image="ghcr.io/google/osv-scanner@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0",
            install="brew install osv-scanner — or start Docker")

SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
       "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def run(repo) -> list[Finding]:
    proc = run_tool(TOOL, ["scan", "source", "--recursive", "--format", "json", MOUNT], repo)
    return parse(proc.stdout)


def _severity(vuln: dict) -> Severity:
    for s in vuln.get("severity") or []:                      # CVSS vector
        score = str(s.get("score", ""))
        if score.startswith("CVSS:"):
            continue
    db = (vuln.get("database_specific") or {}).get("severity")
    if db:
        return SEV.get(str(db).upper(), Severity.MEDIUM)
    # GHSA ids without an explicit grade still matter; medium is the honest default.
    return Severity.MEDIUM


def parse(stdout: str) -> list[Finding]:
    start = stdout.find("{")
    if start < 0:
        return []
    try:
        data = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return []
    out: list[Finding] = []
    for res in data.get("results") or []:
        source = ((res.get("source") or {}).get("path") or "").replace(MOUNT + "/", "")
        for pkg in res.get("packages") or []:
            info = pkg.get("package") or {}
            name, version = info.get("name", "?"), info.get("version", "?")
            for v in pkg.get("vulnerabilities") or []:
                vid = v.get("id", "")
                aliases = [a for a in (v.get("aliases") or []) if a.startswith("CVE-")]
                out.append(Finding(
                    title=f"{name} {version}: {vid}",
                    severity=_severity(v), source_tool="osv", layer="dependencies",
                    location=f"{source} ({name})",
                    description=(v.get("summary") or v.get("details") or "Known vulnerability.")[:400],
                    evidence=f"{name}@{version}",
                    remediation=f"Upgrade {name} to a version outside the affected range.",
                    cve=aliases[0] if aliases else None,
                    references=[f"https://osv.dev/vulnerability/{vid}"] if vid else []))
    return out


if __name__ == "__main__":
    doc = json.dumps({"results": [{"source": {"path": "/src/package-lock.json"}, "packages": [
        {"package": {"name": "lodash", "version": "4.17.4"},
         "vulnerabilities": [{"id": "GHSA-jf85", "aliases": ["CVE-2019-10744"],
                              "summary": "Prototype pollution",
                              "database_specific": {"severity": "CRITICAL"}}]}]}]})
    f = parse(doc)
    assert len(f) == 1 and f[0].severity is Severity.CRITICAL, f
    assert f[0].cve == "CVE-2019-10744" and f[0].location == "package-lock.json (lodash)"
    assert parse("") == []
    print("osv self-check ok")
