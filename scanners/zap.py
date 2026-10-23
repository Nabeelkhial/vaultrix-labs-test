"""OWASP ZAP (Apache-2.0) active DAST against the sandbox — never production.

Runs the ZAP baseline scan (`zap-baseline.py`) in Docker against the sandbox
URL and parses its JSON. The baseline is the active-but-safe profile: it spiders
and runs passive + the non-destructive active rules. The caller guarantees the
target is a sandbox the tool built; this module refuses a non-local host as a
second line of defence.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from core.findings import Finding, Severity

IMAGE = "ghcr.io/zaproxy/zaproxy:2.17.0"   # §5 pin
# ZAP risk code -> our severity. 3=High, 2=Medium, 1=Low, 0=Info.
RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}
LOCAL = {"127.0.0.1", "localhost", "::1", "host.docker.internal"}


class RefusedTarget(Exception):
    pass


def available() -> bool:
    if shutil.which("zap-baseline.py"):
        return True
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", IMAGE],
                          capture_output=True).returncode == 0


def _assert_sandbox(url: str) -> None:
    host = urlparse(url).hostname or ""
    if host not in LOCAL:
        raise RefusedTarget(
            f"ZAP active scan refused: {host} is not a local sandbox. Active scanning only "
            "runs against the disposable environment the tool builds, never a remote host.")


def run(url: str, timeout: int = 600) -> list[Finding]:
    _assert_sandbox(url)
    if not available():
        return []
    # ZAP (in its own container) reaches a host sandbox via host.docker.internal.
    target = url.replace("127.0.0.1", "host.docker.internal").replace("localhost", "host.docker.internal")
    outdir = Path(tempfile.mkdtemp(prefix="vaultrix-zap-"))
    try:
        subprocess.run(
            ["docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway",
             "-v", f"{outdir}:/zap/wrk:rw", IMAGE,
             "zap-baseline.py", "-t", target, "-J", "report.json", "-I", "-m", "2"],
            capture_output=True, text=True, timeout=timeout)
        report = outdir / "report.json"
        return parse(report.read_text()) if report.exists() else []
    finally:
        shutil.rmtree(outdir, ignore_errors=True)


def parse(text: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[Finding] = []
    for site in data.get("site") or []:
        for alert in site.get("alerts") or []:
            inst = (alert.get("instances") or [{}])[0]
            out.append(Finding(
                title=alert.get("alert") or alert.get("name", "ZAP alert"),
                severity=RISK.get(str(alert.get("riskcode", "0")), Severity.INFO),
                source_tool="zap", layer="dynamic",
                location=inst.get("uri") or site.get("@name", ""),
                description=_clean(alert.get("desc", "")),
                evidence=(inst.get("evidence") or inst.get("param") or "")[:200],
                remediation=_clean(alert.get("solution", "")),
                cwe=f'CWE-{alert.get("cweid")}' if alert.get("cweid", "-1") not in ("-1", "", None) else None,
                references=[r for r in (_clean(alert.get("reference", "")).split("\n")) if r][:2]))
    return out


def _clean(html: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", html or "").strip()[:400]


if __name__ == "__main__":  # self-check — parse + the sandbox guard, no docker
    doc = json.dumps({"site": [{"@name": "http://host.docker.internal:8080", "alerts": [
        {"alert": "CSP header not set", "riskcode": "2", "cweid": "693",
         "desc": "<p>No CSP.</p>", "solution": "<p>Set it.</p>",
         "instances": [{"uri": "http://host.docker.internal:8080/", "evidence": "x"}]}]}]})
    f = parse(doc)
    assert len(f) == 1 and f[0].severity is Severity.MEDIUM and f[0].cwe == "CWE-693"
    assert f[0].description == "No CSP." and f[0].layer == "dynamic"
    assert parse("not json") == []
    for bad in ("https://example.com", "http://vaultrix.net/app"):
        try:
            run(bad)
        except RefusedTarget:
            pass
        else:
            raise AssertionError(f"must refuse non-local target {bad}")
    print("zap self-check ok")
