"""Secrets in the frontend bundle — the #1 vibe-coding leak (3 of 5 audited apps).

Regex over same-origin JS. Not a repo scan; Gitleaks covers that at v0.2.
"""
from __future__ import annotations

import base64
import json
import re

from core.findings import Finding, Severity
from core.net import Resp

# (rule, severity, pattern). Ordered: the specific ones must win over generic JWT.
RULES: list[tuple[str, Severity, str]] = [
    ("AWS access key",        Severity.CRITICAL, r"\bAKIA[0-9A-Z]{16}\b"),
    ("Stripe live secret",    Severity.CRITICAL, r"\b[sr]k_live_[0-9a-zA-Z]{20,}"),
    ("Private key block",     Severity.CRITICAL, r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("OpenAI API key",        Severity.CRITICAL, r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
    ("Anthropic API key",     Severity.CRITICAL, r"\bsk-ant-[A-Za-z0-9_-]{32,}"),
    ("GitHub token",          Severity.CRITICAL, r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}"),
    ("Slack token",           Severity.HIGH,     r"\bxox[baprs]-[0-9A-Za-z-]{10,}"),
    ("SendGrid API key",      Severity.HIGH,     r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    ("Twilio account SID",    Severity.HIGH,     r"\bAC[0-9a-f]{32}\b"),
    ("Google API key",        Severity.MEDIUM,   r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("Stripe test secret",    Severity.LOW,      r"\b[sr]k_test_[0-9a-zA-Z]{20,}"),
]

_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


def redact(s: str) -> str:
    s = s.strip()
    return s if len(s) <= 12 else f"{s[:6]}…{s[-4:]} ({len(s)} chars)"


def _jwt_claims(tok: str) -> dict:
    payload = tok.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def scan_text(text: str, location: str) -> list[Finding]:
    out: list[Finding] = []
    for rule, sev, pat in RULES:
        m = re.search(pat, text)
        if not m:
            continue
        out.append(Finding(
            title=f"Exposed secret in frontend code: {rule}",
            severity=sev,
            source_tool="js_secrets",
            layer="secrets",
            location=location,
            description=(f"A {rule} is shipped in JavaScript the browser downloads. "
                         "Anything in the bundle is public — treat this key as compromised."),
            evidence=redact(m.group(0)),
            remediation=("Rotate the key now, then move it server-side (API route / edge function) "
                         "and never expose it to the client."),
            cwe="CWE-798",
        ))

    # Supabase/Postgres JWTs: the anon key is meant to be public, service_role is a full DB bypass.
    for tok in set(_JWT.findall(text)):
        role = _jwt_claims(tok).get("role")
        if role and role != "anon":
            out.append(Finding(
                title=f"Exposed Supabase {role} key in frontend code",
                severity=Severity.CRITICAL,
                source_tool="js_secrets",
                layer="secrets",
                location=location,
                description=(f'A JWT with role "{role}" is in the browser bundle. The service_role key '
                             "bypasses row-level security — anyone can read or delete your whole database."),
                evidence=f"{redact(tok)} role={role}",
                remediation=("Rotate the service_role key in Supabase now. Use the anon key in the browser "
                             "and keep service_role on the server only. Then turn RLS on for every table."),
                cwe="CWE-798",
                references=["https://supabase.com/docs/guides/database/postgres/row-level-security"],
            ))
    return out


def run(root: Resp, bundles: list[Resp]) -> list[Finding]:
    findings = scan_text(root.body, root.url)
    for r in bundles:
        findings += scan_text(r.body, r.url)
    return findings


if __name__ == "__main__":  # self-check
    anon = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.Ab_cdefghijklmnop"
    svc = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.Ab_cdefghijklmnop"
    assert scan_text(anon, "x") == [], "anon key must not be flagged"
    assert any("service_role" in f.title for f in scan_text(svc, "x"))
    assert scan_text("const k='AKIA" + "A" * 16 + "'", "x")[0].severity is Severity.CRITICAL
    # Stripe live key, built at runtime so no full-format literal is committed to the repo.
    stripe = scan_text("const s='" + "sk_live_" + "z" * 24 + "'", "x")
    assert stripe and stripe[0].title.endswith("Stripe live secret") and stripe[0].severity is Severity.CRITICAL
    assert "AKIAAA…AAAA" in scan_text("AKIA" + "A" * 16, "x")[0].evidence
    assert scan_text("const ok = 'not a secret at all'", "x") == []
    print("secrets self-check ok")
