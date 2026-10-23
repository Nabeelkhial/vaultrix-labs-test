"""MCP server — the engine as tools for Cursor / Codex / any agent (§13).

Speaks the Model Context Protocol over stdio JSON-RPC 2.0. Implemented on the
stdlib so it stays zero-install like the rest of the engine; if the official
`mcp` SDK is ever added, this module can be swapped without touching the engine.

No logic lives here — every tool calls core/orchestrator and returns the same
Finding data the CLI renders. Active tools (attack, fix) carry the same ownership
and sandbox-only guarantees as the CLI, because they call the same functions.
"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict

PROTOCOL = "2024-11-05"
SERVER = {"name": "vaultrix-labs", "version": "0.5.0"}

TOOLS = [
    {"name": "scan_url",
     "description": "Passive, read-only security scan of a public URL. Safe for any site.",
     "inputSchema": {"type": "object", "required": ["url"], "properties": {
         "url": {"type": "string"}, "deep": {"type": "boolean", "default": False}}}},
    {"name": "scan_repo",
     "description": "Scan a local checkout or owner/name on GitHub (write access required) for "
                    "secrets, dependency CVEs, missing RLS and unauthed routes.",
     "inputSchema": {"type": "object", "required": ["repo"], "properties": {
         "repo": {"type": "string"}}}},
    {"name": "attack_sandbox",
     "description": "Build a disposable sandbox from a repo (or 'demo') and attack IT — never "
                    "production — to PROVE findings like IDOR. Ownership-gated for real repos.",
     "inputSchema": {"type": "object", "properties": {
         "target": {"type": "string", "default": "demo"},
         "stack": {"type": "string"}}}},
    {"name": "fix_finding",
     "description": "Attack, then for each proven finding patch on a branch, rebuild the sandbox, "
                    "re-run the proof, and report what was fixed. Does not open a PR.",
     "inputSchema": {"type": "object", "properties": {
         "target": {"type": "string", "default": "demo"},
         "stack": {"type": "string"}}}},
]


def _scan_to_dict(scan) -> dict:
    from report.grade import grade
    letter, pts, head = grade(scan.findings)
    return {"target": scan.target, "grade": letter, "score": pts, "headline": head,
            "findings": [asdict(f) for f in scan.findings]}


def call_tool(name: str, args: dict) -> dict:
    """Dispatch to the engine. Returns a JSON-able dict; raises on bad input."""
    from core import orchestrator as orch

    if name == "scan_url":
        return _scan_to_dict(orch.scan_url(args["url"], deep=bool(args.get("deep"))))
    if name == "scan_repo":
        return _scan_to_dict(orch.scan_repo(args["repo"]))
    if name == "attack_sandbox":
        target = args.get("target", "demo")
        stack = args.get("stack") or ("demo" if target == "demo" else "supabase-next")
        return _scan_to_dict(orch.attack_sandbox(target, stack=stack))
    if name == "fix_finding":
        target = args.get("target", "demo")
        stack = args.get("stack") or ("demo" if target == "demo" else "supabase-next")
        scan = orch.attack_sandbox(target, stack=stack)
        results = orch.fix_findings(scan, scan._repo or target, stack=stack, open_pr=False)
        return {"target": scan.target,
                "fixed": [{"id": r.finding.id, "title": r.finding.title,
                           "closed": r.closed, "branch": r.branch, "note": r.note}
                          for r in results]}
    raise ValueError(f"unknown tool: {name}")


# --- JSON-RPC 2.0 over stdio -------------------------------------------------
def handle(msg: dict) -> dict | None:
    """Return a response dict, or None for a notification (no id)."""
    mid = msg.get("id")
    method = msg.get("method")

    if method == "initialize":
        return _ok(mid, {"protocolVersion": PROTOCOL,
                         "capabilities": {"tools": {}},
                         "serverInfo": SERVER})
    if method == "notifications/initialized" or mid is None:
        return None
    if method == "tools/list":
        return _ok(mid, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        try:
            result = call_tool(params.get("name"), params.get("arguments") or {})
            return _ok(mid, {"content": [{"type": "text", "text": json.dumps(result, default=str)}],
                             "isError": False})
        except Exception as e:
            return _ok(mid, {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}],
                             "isError": True})
    return _err(mid, -32601, f"method not found: {method}")


def _ok(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve(stdin=sys.stdin, stdout=sys.stdout) -> None:
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(msg)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()


if __name__ == "__main__":
    import sys as _sys
    if "--selfcheck" in _sys.argv:
        assert handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})["result"]["serverInfo"]["name"] == "vaultrix-labs"
        assert [t["name"] for t in handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]] == ["scan_url", "scan_repo", "attack_sandbox", "fix_finding"]
        assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
        print("mcp server self-check ok")
    else:
        serve()
