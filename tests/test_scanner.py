"""End-to-end checks against the deliberately vulnerable fixture.

    python3 -m tests.test_scanner

ponytail: stdlib http.server + assert, no pytest. The borrowed scanners are
asserted only when Docker is actually up, so the suite still passes offline.
"""
from __future__ import annotations

import functools
import json
import http.server
import threading
from pathlib import Path

from core.findings import Finding, Severity, dedupe
from core.orchestrator import scan_repo, scan_url
from report.cso_report import markdown
from report.grade import grade
from scanners._tool import how
from scanners.trivy import TOOL as TRIVY

FIXTURE = Path(__file__).resolve().parent.parent / "examples" / "vuln-supabase-next"


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def serve(directory: Path):
    handler = functools.partial(_Quiet, directory=str(directory))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _has(titles, sub):
    assert any(sub in t for t in titles), f"missing {sub!r} in {titles}"


def test_url() -> None:
    srv, base = serve(FIXTURE)
    try:
        scan = scan_url(base)
    finally:
        srv.shutdown()

    titles = [f.title for f in scan.findings]
    assert "next.js" in scan.stack.tech and "supabase" in scan.stack.tech, scan.stack.tech
    assert scan.stack.profile == "supabase-next", scan.stack.profile
    _has(titles, "Exposed Supabase service_role key in frontend code")
    _has(titles, "Stripe live secret")
    _has(titles, "Publicly readable: /.env")
    _has(titles, "plain HTTP")
    assert not any("anon" in t for t in titles), "the anon key is public by design"
    assert grade(scan.findings)[0] == "F"
    print(f"  url  ok — grade F, {len(scan.findings)} findings")


def test_repo() -> None:
    scan = scan_repo(str(FIXTURE))
    titles = [f.title for f in scan.findings]

    # the checks that are ours, not a borrowed tool's
    _has(titles, "Environment file committed to the repository")
    _has(titles, "Row-level security not enabled on 3 table(s)")
    _has(titles, "API route(s) query the database with no visible auth check")
    _has(titles, "Exposed Supabase service_role key in the repository")

    rls = next(f for f in scan.findings if "Row-level security" in f.title)
    assert "profiles" not in rls.evidence, "profiles HAS rls enabled — must not be flagged"
    assert {"orders", "support_tickets", "api_keys"} == set(rls.evidence.split(", ")), rls.evidence

    keys = [f.dedupe_key() for f in scan.findings]
    assert len(keys) == len(set(keys)), "dedupe left duplicates"
    assert grade(scan.findings)[0] == "F"

    if how(TRIVY):   # Docker or a native binary is present, so the borrowed layer ran
        deps = [f for f in scan.findings if f.layer == "dependencies"]
        assert deps, "trivy/osv are available but produced no dependency findings"
        merged = [f for f in deps if "+" in f.source_tool]
        assert merged, "trivy and osv report the same CVEs; dedupe should have merged some"
        assert any("CVE-2019-10744" == f.cve for f in deps), "known lodash CVE missing"
        print(f"  repo ok — grade F, {len(scan.findings)} findings, "
              f"{len(deps)} dependency ({len(merged)} merged across tools)")
    else:
        print(f"  repo ok — grade F, {len(scan.findings)} findings (built-in checks only)")

    body = markdown(scan)
    assert "Fix these first" in body and "Which scanners ran" in body
    assert body.count("#### ") < 40, "report must roll dependencies up, not list every CVE"


def test_dedupe_across_tools() -> None:
    """Trivy and OSV name the same hole differently; the CVE is the identity."""
    t = Finding("lodash 4.17.4: CVE-2019-10744", Severity.CRITICAL, "trivy", "dependencies",
                "package-lock.json (lodash)", "d", cve="CVE-2019-10744")
    o = Finding("lodash 4.17.4: GHSA-jf85-cpcp-j695", Severity.HIGH, "osv", "dependencies",
                "package-lock.json (lodash)", "d", cve="CVE-2019-10744")
    merged = dedupe([t, o])
    assert len(merged) == 1 and merged[0].severity is Severity.CRITICAL
    assert merged[0].source_tool == "trivy+osv", merged[0].source_tool




def test_idor_proof_http() -> None:
    """The proof layer end to end over real HTTP, no Docker: vulnerable app proves,
    fixed app does not."""
    import importlib.util
    import os
    from http.server import ThreadingHTTPServer

    from prove import poc_runner
    from sandbox.generator import _demo_seed

    demo = Path(__file__).resolve().parent.parent / "examples" / "sandbox-idor-demo" / "app.py"

    def serve_app(fixed: bool):
        os.environ["VAULTRIX_FIXED"] = "1" if fixed else "0"
        spec = importlib.util.spec_from_file_location(f"demo_{fixed}", demo)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_address[1]}"

    srv, base = serve_app(fixed=False)
    try:
        fs = poc_runner.run(base, _demo_seed())
    finally:
        srv.shutdown()
    assert len(fs) == 2 and all(f.proof.value == "proven" for f in fs), fs
    assert any("BOB_SECRET_9a1c" in f.evidence for f in fs)
    assert grade(fs)[0] == "F", "a proven IDOR must grade F"

    srv, base = serve_app(fixed=True)
    try:
        clean = poc_runner.run(base, _demo_seed())
    finally:
        srv.shutdown()
        os.environ.pop("VAULTRIX_FIXED", None)
    assert clean == [], f"the patched app must prove nothing, got {clean}"


def test_attack_sandbox_docker() -> None:
    """Full containerised path: generate -> compose build/up -> prove -> teardown.
    Skipped unless Docker and the base image are present, so the suite still runs
    offline."""
    import shutil as _sh
    import subprocess

    from core.orchestrator import attack_sandbox

    if not _sh.which("docker"):
        print("  attack(docker) skipped — no docker"); return
    if subprocess.run(["docker", "image", "inspect", "python:3.13-slim"],
                      capture_output=True).returncode != 0:
        print("  attack(docker) skipped — python:3.13-slim not pulled"); return

    scan = attack_sandbox("demo", stack="demo")
    proven = [f for f in scan.findings if f.proof.value == "proven"]
    assert len(proven) == 2, f"both IDOR directions should be proven in the container: {scan.findings}"
    assert scan.kind == "attack" and grade(scan.findings)[0] == "F"
    body = markdown(scan)
    assert "disposable copy" in body and "proven" in body
    assert subprocess.run(["docker", "ps", "-aq", "--filter", "name=vaultrix-sandbox"],
                          capture_output=True, text=True).stdout.strip() == "", "sandbox leaked"
    print(f"  attack(docker) ok — {len(proven)} proven IDOR, sandbox torn down")



def test_fix_reverify_docker() -> None:
    """Prove -> patch on a branch -> rebuild -> re-prove closed -> FIXED.
    The whole v0.4 loop, against a real git checkout of the demo. Docker-guarded."""
    import shutil as _sh
    import subprocess
    import tempfile

    from core.orchestrator import attack_sandbox, fix_findings
    from sandbox.generator import DEMO_DIR

    if not _sh.which("docker"):
        print("  fix(docker) skipped — no docker"); return
    if subprocess.run(["docker", "image", "inspect", "python:3.13-slim"],
                      capture_output=True).returncode != 0:
        print("  fix(docker) skipped — python:3.13-slim not pulled"); return

    repo = Path(tempfile.mkdtemp(prefix="vaultrix-fixtest-"))
    try:
        for f in ("app.py", "Dockerfile"):
            _sh.copy(DEMO_DIR / f, repo / f)
        for args in (["init", "-q"], ["add", "-A"],
                     ["-c", "user.email=t@t.test", "-c", "user.name=t", "commit", "-qm", "init"]):
            subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

        scan = attack_sandbox(str(repo), stack="demo")
        proven = [f for f in scan.findings if f.proof.value == "proven"]
        assert proven, "setup: the demo must prove an IDOR first"

        results = fix_findings(scan, str(repo), stack="demo")
        assert results and all(r.closed for r in results), [r.note for r in results]
        assert all(r.finding.proof.value == "fixed" for r in results)
        assert all(r.branch and r.branch.startswith("vaultrix-fix/") for r in results)
        assert all("+" in r.diff and "if owner" in r.diff for r in results), "diff must show the one-line fix"

        branches = subprocess.run(["git", "-C", str(repo), "branch", "--format=%(refname:short)"],
                                  capture_output=True, text=True).stdout.split()
        assert any(b.startswith("vaultrix-fix/") for b in branches), branches
        # the patched source really enforces ownership now
        head = subprocess.run(["git", "-C", str(repo), "show", f"{results[0].branch}:app.py"],
                             capture_output=True, text=True).stdout
        assert "if owner[\"token\"] != caller[\"token\"]:" in head and "if FIXED and owner" not in head
        print(f"  fix(docker) ok — {len(results)} IDOR patched, rebuilt, re-verified FIXED")
    finally:
        _sh.rmtree(repo, ignore_errors=True)



def test_mcp_protocol_and_dispatch() -> None:
    """MCP handshake, tool listing, and a real tools/call into the engine —
    over the local fixture server, no Docker."""
    from interfaces.mcp import server

    init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"]["serverInfo"]["name"] == "vaultrix-labs"
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    names = [t["name"] for t in server.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]]
    assert names == ["scan_url", "scan_repo", "attack_sandbox", "fix_finding"], names
    bad = server.handle({"jsonrpc": "2.0", "id": 3, "method": "no_such"})
    assert bad["error"]["code"] == -32601

    srv, base = serve(FIXTURE)
    try:
        resp = server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                              "params": {"name": "scan_url", "arguments": {"url": base}}})
    finally:
        srv.shutdown()
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["grade"] == "F" and payload["findings"], payload
    print(f"  mcp ok — handshake + scan_url via tools/call, grade {payload['grade']}")


def test_cve_watch_parsing_and_since() -> None:
    """Lockfile parsing, finding mapping, and the since-filter — no network."""
    import json as _json
    from watch.cve_watch import _npm_lock, _pip_requirements, to_finding, Pkg, _parse_dt

    lock = _json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.4"}}})
    assert _npm_lock(lock) == [Pkg("lodash", "npm", "4.17.4")]
    assert _pip_requirements("django==4.0\n")[0] == Pkg("django", "PyPI", "4.0")
    v = {"id": "GHSA-z", "aliases": ["CVE-2026-9"], "summary": "x",
         "modified": "2026-10-22T00:00:00Z", "database_specific": {"severity": "HIGH"}}
    f = to_finding(v, Pkg("lodash", "npm", "4.17.4"))
    assert f.cve == "CVE-2026-9" and f.severity.value == "high" and f.source_tool == "cve_watch"
    assert _parse_dt("2026-10-22T00:00:00Z") is not None
    print("  cve_watch ok — parsing + mapping")


if __name__ == "__main__":
    test_dedupe_across_tools()
    test_idor_proof_http()
    test_url()
    test_repo()
    test_attack_sandbox_docker()
    test_fix_reverify_docker()
    test_mcp_protocol_and_dispatch()
    test_cve_watch_parsing_and_since()
    print("e2e ok")
