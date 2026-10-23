"""SAST over the source: OpenGrep if installed, else Semgrep CE in Docker.

OpenGrep publishes no container image, so the Docker path runs Semgrep CE — the
fallback DEVELOPMENT_PLAN §5 already names. Same LGPL-2.1 terms, same subprocess
rule, same JSON shape (OpenGrep is a Semgrep fork), so one parser covers both.
"""
from __future__ import annotations

import json

from core.findings import Finding, Severity
from scanners._tool import MOUNT, Tool, run as run_tool

# Semgrep CE also ships only `:latest`; pinned to its RepoDigest (see osv.py).
TOOL = Tool(name="opengrep", network=True,
            image="semgrep/semgrep@sha256:3db5c7af55eb1f512eac0abf0ab69a97b52c74b5e9a27314c221aee1a78d7ab2",
            install="see https://github.com/opengrep/opengrep — or start Docker",
            note="Docker path runs Semgrep CE (OpenGrep ships no image)")

# p/owasp-top-ten matched nothing on a real command-injection sink; p/default
# carries the detect-child-process / taint rules we actually want.
RULES = "p/default"
SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


def run(repo) -> list[Finding]:
    from scanners._tool import how
    proc = run_tool(TOOL, ["scan", "--config", RULES, "--json", "--quiet", "--timeout", "300", MOUNT], repo)
    findings = parse(proc.stdout)
    if how(TOOL) == "docker":
        for f in findings:
            f.source_tool = "semgrep"   # be honest about which engine actually ran
    return findings


def parse(stdout: str) -> list[Finding]:
    start = stdout.find("{")
    if start < 0:
        return []
    try:
        data = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return []
    out = []
    for r in data.get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        path = (r.get("path") or "").replace(MOUNT + "/", "")
        cwe = meta.get("cwe")
        cwe = cwe[0] if isinstance(cwe, list) and cwe else cwe
        out.append(Finding(
            title=(meta.get("shortDescription") or extra.get("message") or r.get("check_id", "SAST finding"))[:120],
            severity=SEV.get((extra.get("severity") or "WARNING").upper(), Severity.MEDIUM),
            source_tool="opengrep", layer="injection",
            location=f'{path}:{(r.get("start") or {}).get("line", "?")}',
            description=(extra.get("message") or "")[:400],
            evidence=(extra.get("lines") or "")[:200],
            remediation=meta.get("fix") or meta.get("fix_regex", {}).get("replacement", "") or
                        "Validate or parameterise the untrusted value before it reaches this sink.",
            cwe=str(cwe) if cwe else None,
            references=(meta.get("references") or [])[:2]))
    return out


if __name__ == "__main__":
    doc = json.dumps({"results": [{"check_id": "js.sqli", "path": "/src/api/x.ts",
                                   "start": {"line": 12},
                                   "extra": {"severity": "ERROR", "message": "SQL injection",
                                             "lines": "db.query(`select ${id}`)",
                                             "metadata": {"cwe": ["CWE-89: SQL Injection"]}}}]})
    f = parse(doc)
    assert len(f) == 1 and f[0].severity is Severity.HIGH and f[0].location == "api/x.ts:12"
    assert f[0].cwe.startswith("CWE-89") and f[0].layer == "injection"
    assert parse("") == []
    print("opengrep self-check ok")
