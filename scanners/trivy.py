"""Trivy (Apache-2.0) — dependency CVEs, IaC misconfig and committed secrets."""
from __future__ import annotations

import json

from core.findings import Finding, Severity
from scanners._tool import MOUNT, Tool, run as run_tool

TOOL = Tool(name="trivy", image="aquasec/trivy:0.71.0", network=True,
            install="brew install trivy — or start Docker")

SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
       "LOW": Severity.LOW, "UNKNOWN": Severity.INFO}


def run(repo) -> list[Finding]:
    proc = run_tool(TOOL, ["fs", "--format", "json", "--quiet", "--scanners",
                           "vuln,misconfig,secret", MOUNT], repo)
    return parse(proc.stdout)


def parse(stdout: str) -> list[Finding]:
    start = stdout.find("{")
    if start < 0:
        return []
    try:
        data = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return []
    out: list[Finding] = []
    for res in data.get("Results") or []:
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion")
            out.append(Finding(
                title=f'{v.get("PkgName")} {v.get("InstalledVersion")}: {v.get("VulnerabilityID")}',
                severity=SEV.get((v.get("Severity") or "UNKNOWN").upper(), Severity.INFO),
                source_tool="trivy", layer="dependencies", location=f'{target} ({v.get("PkgName")})',
                description=(v.get("Title") or v.get("Description") or "Known vulnerability in a dependency.")[:400],
                evidence=f'{v.get("PkgName")}@{v.get("InstalledVersion")}',
                remediation=(f'Upgrade {v.get("PkgName")} to {fixed}.' if fixed
                             else f'No fixed version yet — consider replacing {v.get("PkgName")}.'),
                cve=v.get("VulnerabilityID"), references=(v.get("References") or [])[:3]))
        for m in res.get("Misconfigurations") or []:
            out.append(Finding(
                title=f'{m.get("ID")}: {m.get("Title")}',
                severity=SEV.get((m.get("Severity") or "UNKNOWN").upper(), Severity.INFO),
                source_tool="trivy", layer="runtime", location=target,
                description=(m.get("Description") or "")[:400],
                evidence=(m.get("Message") or "")[:200],
                remediation=m.get("Resolution") or "", references=(m.get("References") or [])[:2]))
        for s in res.get("Secrets") or []:
            out.append(Finding(
                title=f'Exposed secret: {s.get("RuleID")}',
                severity=SEV.get((s.get("Severity") or "HIGH").upper(), Severity.HIGH),
                source_tool="trivy", layer="secrets",
                location=f'{target}:{s.get("StartLine")}',
                description=f'Trivy matched secret rule `{s.get("RuleID")}` ({s.get("Title")}).',
                evidence=(s.get("Match") or "")[:200],
                remediation="Rotate the key and move it to a secret manager.", cwe="CWE-798"))
    return out


if __name__ == "__main__":
    doc = json.dumps({"Results": [{"Target": "package-lock.json", "Vulnerabilities": [
        {"PkgName": "lodash", "InstalledVersion": "4.17.4", "VulnerabilityID": "CVE-2019-10744",
         "Severity": "CRITICAL", "Title": "Prototype pollution", "FixedVersion": "4.17.12"}]}]})
    f = parse(doc)
    assert len(f) == 1 and f[0].severity is Severity.CRITICAL and f[0].cve == "CVE-2019-10744"
    assert "4.17.12" in f[0].remediation and f[0].layer == "dependencies"
    assert parse("") == []
    print("trivy self-check ok")
