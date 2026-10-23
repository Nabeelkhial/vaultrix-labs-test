"""Gitleaks (MIT) — secrets across the whole git history, not just the worktree."""
from __future__ import annotations

import json

from core.findings import Finding, Severity
from scanners._tool import MOUNT, Tool, run as run_tool

TOOL = Tool(name="gitleaks", image="zricethezav/gitleaks:v8.30.1", network=False,
            install="brew install gitleaks — or start Docker")


def run(repo) -> list[Finding]:
    # `git` walks history (where a deleted .env still lives); `dir` only sees the worktree.
    sub = "git" if (repo / ".git").exists() else "dir"
    # "-" is the only report-path that reaches stdout; /dev/stdout silently writes nothing.
    proc = run_tool(TOOL, [sub, MOUNT, "--report-format", "json", "--report-path", "-",
                           "--redact", "--exit-code", "0"], repo)
    return parse(proc.stdout)


def parse(stdout: str) -> list[Finding]:
    start = stdout.find("[")
    if start < 0:
        return []
    try:
        items = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return []
    out = []
    for it in items:
        if it.get("RuleID") == "jwt":
            # --redact hides the payload, so this rule cannot tell a public Supabase
            # anon key from a service_role key. scanners/secrets.py decodes the role
            # and gets it right; a blind "jwt found" here would only cry wolf.
            continue
        loc = f'{it.get("File")}:{it.get("StartLine")}'
        commit = (it.get("Commit") or "")[:8]
        out.append(Finding(
            title=f'Exposed secret: {it.get("RuleID")}',
            severity=Severity.HIGH, source_tool="gitleaks", layer="secrets", location=loc,
            description=(f'A secret matching rule `{it.get("RuleID")}` is in the repository'
                         + (f' (commit {commit}, "{(it.get("Message") or "").strip()[:60]}")' if commit else "")
                         + ". Anything ever committed stays in history until it is purged."),
            evidence=(it.get("Secret") or it.get("Match") or "[redacted]")[:200],
            remediation=("Rotate the key now, then purge it from history "
                         "(`git filter-repo --invert-paths --path <file>`) and force-push."),
            cwe="CWE-798"))
    return out


if __name__ == "__main__":
    f = parse('garbage\n[{"RuleID":"aws-access-key","File":"a.ts","StartLine":3,"Secret":"REDACTED","Commit":"abcdef1234"}]')
    assert len(f) == 1 and f[0].location == "a.ts:3" and f[0].severity is Severity.HIGH
    assert parse("not json at all") == []
    print("gitleaks self-check ok")
