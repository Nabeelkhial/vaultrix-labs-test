"""Optional Nuclei enrichment. Subprocess only (DEVELOPMENT_PLAN §5 licensing rule).

Off by default: Nuclei templates send request payloads, which is more than
"read-only" — so it is gated behind `--deep`, for targets the user owns.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from core.findings import Finding, Severity

BIN = "nuclei"
# ponytail: tag allowlist instead of a curated template set; narrow it if noise shows up
TAGS = "exposure,misconfig,tech,ssl,cve,default-login"
EXCLUDE_TAGS = "fuzz,dos,intrusive,brute-force"
SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
       "low": Severity.LOW, "info": Severity.INFO, "unknown": Severity.INFO}


def available() -> bool:
    return shutil.which(BIN) is not None


def run(url: str, timeout: int = 600) -> list[Finding]:
    if not available():
        return []
    proc = subprocess.run(
        [BIN, "-target", url, "-jsonl", "-silent", "-no-interactsh",
         "-tags", TAGS, "-exclude-tags", EXCLUDE_TAGS,
         "-severity", "low,medium,high,critical", "-rate-limit", "20", "-timeout", "10"],
        capture_output=True, text=True, timeout=timeout,
    )
    out: list[Finding] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append(_to_finding(item))
    return out


def _to_finding(item: dict) -> Finding:
    info = item.get("info", {})
    cls = info.get("classification") or {}
    cve = (cls.get("cve-id") or [None])[0] if isinstance(cls.get("cve-id"), list) else cls.get("cve-id")
    cwe = (cls.get("cwe-id") or [None])[0] if isinstance(cls.get("cwe-id"), list) else cls.get("cwe-id")
    return Finding(
        title=info.get("name") or item.get("template-id", "nuclei finding"),
        severity=SEV.get((info.get("severity") or "unknown").lower(), Severity.INFO),
        source_tool="nuclei",
        layer="runtime" if cve else "exposure",
        location=item.get("matched-at") or item.get("host", ""),
        description=info.get("description") or f'Nuclei template {item.get("template-id")} matched.',
        evidence=", ".join(item.get("extracted-results", []))[:300],
        remediation=info.get("remediation", ""),
        cwe=cwe, cve=cve,
        references=info.get("reference") or [],
    )


if __name__ == "__main__":  # self-check — parsing only, no network
    f = _to_finding({"template-id": "t", "matched-at": "https://x.test/.env",
                     "info": {"name": "Env file", "severity": "high",
                              "classification": {"cve-id": ["CVE-2020-1"], "cwe-id": ["CWE-200"]}}})
    assert (f.severity, f.cve, f.cwe, f.layer) == (Severity.HIGH, "CVE-2020-1", "CWE-200", "runtime")
    assert run("https://x.test") == [] or available()
    print("nuclei self-check ok")
