"""Passive checks: read-only GETs against any URL. No payloads, no auth, no writes.

Legal note (DEVELOPMENT_PLAN §16): this layer is the only one allowed to touch a
host the user has not proven they own.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from core.findings import Finding, Severity
from core.net import Resp, fetch, fetch_many, peer_cert

PROBE_ORIGIN = "https://vaultrix-cors-probe.invalid"

# path, severity, layer, must-match body pattern, one-line why
EXPOSED: list[tuple[str, Severity, str, str]] = [
    ("/.env",                 Severity.CRITICAL, r"(?m)^\s*[A-Z_][A-Z0-9_]*\s*=", "Environment file with live credentials"),
    ("/.env.local",           Severity.CRITICAL, r"(?m)^\s*[A-Z_][A-Z0-9_]*\s*=", "Environment file with live credentials"),
    ("/.env.production",      Severity.CRITICAL, r"(?m)^\s*[A-Z_][A-Z0-9_]*\s*=", "Environment file with live credentials"),
    ("/.git/config",          Severity.CRITICAL, r"\[core\]",                     "Git metadata — your full source history is downloadable"),
    ("/.git/HEAD",            Severity.CRITICAL, r"(?m)^ref: refs/",              "Git metadata — your full source history is downloadable"),
    ("/.aws/credentials",     Severity.CRITICAL, r"aws_access_key_id",            "AWS credentials file"),
    ("/wp-config.php.bak",    Severity.CRITICAL, r"DB_PASSWORD",                  "WordPress config backup with the database password"),
    ("/backup.sql",           Severity.CRITICAL, r"(?i)(CREATE TABLE|INSERT INTO)", "Database dump"),
    ("/dump.sql",             Severity.CRITICAL, r"(?i)(CREATE TABLE|INSERT INTO)", "Database dump"),
    ("/docker-compose.yml",   Severity.HIGH,     r"(?m)^(services|version):",      "Deployment config, often with passwords"),
    ("/phpinfo.php",          Severity.HIGH,     r"(?i)php version",               "phpinfo() leaks paths, modules and the exact PHP build"),
    ("/actuator/env",         Severity.HIGH,     r'"propertySources"',             "Spring Actuator env endpoint leaks configuration"),
    ("/Dockerfile",           Severity.MEDIUM,   r"(?mi)^FROM ",                   "Build recipe reveals internal structure"),
    ("/server-status",        Severity.MEDIUM,   r"Apache Server Status",          "Apache status page leaks live request URLs"),
    ("/config.json",          Severity.MEDIUM,   r"^\s*\{",                        "Application config served to anyone"),
    ("/.DS_Store",            Severity.LOW,      r"Bud1",                          "macOS index file leaks your directory listing"),
    ("/openapi.json",         Severity.LOW,      r'"(openapi|swagger)"',           "API schema maps every endpoint for an attacker"),
]

SEC_HEADERS: list[tuple[str, Severity, str, str]] = [
    ("content-security-policy", Severity.MEDIUM, "No Content-Security-Policy",
     "Nothing restricts which scripts the page may run, so an injected script runs freely."),
    ("x-content-type-options",  Severity.LOW,    "No X-Content-Type-Options",
     "Browsers may guess a file's type and execute an upload as script."),
    ("referrer-policy",         Severity.LOW,    "No Referrer-Policy",
     "Full URLs — including tokens in query strings — leak to third-party sites."),
]

# Oldest PHP branch still receiving security fixes as of Oct 2026. See PHP2Shell, §1.
PHP_SUPPORTED = (8, 2)


def _baseline(base: str) -> tuple[int, int]:
    """Signature of a definitely-missing path, so SPA catch-all 200s don't become findings."""
    r = fetch(f"{base}/vaultrix-404-probe-9f3a2c")
    return r.status, len(r.body)


def exposure(base: str) -> list[Finding]:
    bstatus, blen = _baseline(base)
    paths = [p for p, *_ in EXPOSED]
    out: list[Finding] = []
    for (path, sev, pat, why), r in zip(EXPOSED, fetch_many([base + p for p in paths])):
        if not r.ok or r.status != 200:
            continue
        if r.status == bstatus and abs(len(r.body) - blen) < max(32, blen * 0.05):
            continue  # same page the 404 probe got — soft 404
        if not re.search(pat, r.body[:8000]):
            continue  # served something, but not the file we were looking for
        out.append(Finding(
            title=f"Publicly readable: {path}",
            severity=sev,
            source_tool="exposure",
            layer="exposure",
            location=r.url,
            description=f"{why}. Anyone on the internet can download it by typing the URL.",
            evidence=r.body[:200].strip(),
            remediation=f"Stop serving {path} — delete it from the deploy, or block the path at your host/CDN.",
            cwe="CWE-200",
        ))
    return out


def headers(root: Resp) -> list[Finding]:
    out: list[Finding] = []
    https = root.url.startswith("https://")
    csp = root.headers.get("content-security-policy", "")

    for name, sev, title, why in SEC_HEADERS:
        if name not in root.headers:
            out.append(Finding(
                title=title, severity=sev, source_tool="headers", layer="hardening",
                location=root.url, description=why,
                remediation=f"Send the {name} response header. Most hosts (Vercel, Netlify, Cloudflare) set it in one config line.",
                cwe="CWE-693"))

    if https and "strict-transport-security" not in root.headers:
        out.append(Finding(
            title="No HSTS", severity=Severity.MEDIUM, source_tool="headers", layer="transport",
            location=root.url,
            description="Without HSTS a visitor's first request can be downgraded to plain HTTP and intercepted.",
            remediation="Send Strict-Transport-Security: max-age=31536000; includeSubDomains",
            cwe="CWE-319"))

    if "x-frame-options" not in root.headers and "frame-ancestors" not in csp:
        out.append(Finding(
            title="Page can be framed (clickjacking)", severity=Severity.MEDIUM,
            source_tool="headers", layer="hardening", location=root.url,
            description="Another site can load your app in an invisible iframe and trick users into clicking inside it.",
            remediation="Add frame-ancestors 'none' to your CSP, or send X-Frame-Options: DENY.",
            cwe="CWE-1021"))

    for raw in root.cookies:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        if https and "secure" not in low:
            out.append(Finding(
                title=f"Cookie without Secure: {name}", severity=Severity.MEDIUM,
                source_tool="headers", layer="transport", location=root.url,
                description="This cookie is also sent over plain HTTP, where anyone on the network can read it.",
                evidence=raw[:120], remediation="Add the Secure attribute.", cwe="CWE-614"))
        if "httponly" not in low:
            out.append(Finding(
                title=f"Cookie readable by JavaScript: {name}", severity=Severity.LOW,
                source_tool="headers", layer="hardening", location=root.url,
                description="Any injected script can read this cookie. If it is a session cookie, that is account takeover.",
                evidence=raw[:120], remediation="Add the HttpOnly attribute.", cwe="CWE-1004"))

    for h, v in root.headers.items():
        versioned = re.search(r"\d+\.\d+", v)
        # x-powered-by is worth flagging even without a version: naming the framework
        # is already a shortlist of exploits to try.
        if h in ("server", "x-powered-by", "x-aspnet-version") and (versioned or h == "x-powered-by"):
            out.append(Finding(
                title=(f"Version disclosed in {h} header" if versioned
                       else f"Technology disclosed in {h} header"),
                severity=Severity.LOW,
                source_tool="headers", layer="exposure", location=root.url,
                description=(f"The {h} header announces the exact version you run, which tells an "
                             "attacker which CVEs to try." if versioned else
                             f"The {h} header names your framework ({v}), narrowing an attacker's "
                             "search to exploits that target it."),
                evidence=f"{h}: {v}", remediation=f"Suppress the {h} header at your server or CDN.",
                cwe="CWE-200"))
        out.extend(_php_eol(h, v, root.url))
    return out


def _php_eol(header: str, value: str, url: str) -> list[Finding]:
    m = re.search(r"PHP/(\d+)\.(\d+)", value, re.I)
    if not m or (int(m.group(1)), int(m.group(2))) >= PHP_SUPPORTED:
        return []
    ver = f"{m.group(1)}.{m.group(2)}"
    return [Finding(
        title=f"End-of-life PHP {ver} in production",
        severity=Severity.CRITICAL, source_tool="headers", layer="runtime", location=url,
        description=(f"PHP {ver} no longer gets security fixes. This is exactly the population hit by the "
                     "October 2026 PHP2Shell outbreak (CVE-2026-109618/109619, unauthenticated remote code "
                     "execution, ~884k hosts) — your server may already be exploitable."),
        evidence=f"{header}: {value}",
        remediation=f"Upgrade to PHP {PHP_SUPPORTED[0]}.{PHP_SUPPORTED[1]} or newer, today.",
        cve="CVE-2026-109618",
        references=["https://www.kaspersky.com/blog/cve-2026-109618-109619-php-vulnerabilities/56583/"])]


def cors(base: str) -> list[Finding]:
    r = fetch(base, origin=PROBE_ORIGIN)
    acao = r.headers.get("access-control-allow-origin", "")
    creds = r.headers.get("access-control-allow-credentials", "").lower() == "true"
    if not acao:
        return []
    reflected = acao == PROBE_ORIGIN
    if creds and (reflected or acao == "*"):
        return [Finding(
            title="CORS lets any website read authenticated responses",
            severity=Severity.HIGH, source_tool="cors", layer="authz", location=r.url,
            description=("The server reflects any origin and allows credentials, so a malicious page a logged-in "
                         "user visits can read their data straight out of your API."),
            evidence=f"Origin: {PROBE_ORIGIN} -> Access-Control-Allow-Origin: {acao}, Allow-Credentials: true",
            remediation="Allow only an explicit list of your own origins. Never reflect the request Origin when credentials are allowed.",
            cwe="CWE-942")]
    if reflected or acao == "*":
        return [Finding(
            title="Permissive CORS policy", severity=Severity.LOW, source_tool="cors",
            layer="hardening", location=r.url,
            description="Any site can read unauthenticated responses from this origin.",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            remediation="Restrict Access-Control-Allow-Origin to origins you own.", cwe="CWE-942")]
    return []


def tls(base: str) -> list[Finding]:
    p = urlparse(base)
    if p.scheme != "https":
        plain = Finding(
            title="Site served over plain HTTP", severity=Severity.HIGH, source_tool="tls",
            layer="transport", location=base,
            description="Traffic is unencrypted: passwords and session cookies travel in the clear.",
            remediation="Enable HTTPS (free via Let's Encrypt or your host) and redirect all HTTP to it.",
            cwe="CWE-319")
        return [plain]

    host = p.hostname or ""
    cert, version, err = peer_cert(host)
    if err:
        return [Finding(
            title="TLS certificate is not valid", severity=Severity.HIGH, source_tool="tls",
            layer="transport", location=host,
            description="A browser cannot verify this certificate, so visitors get a security warning and traffic may be interceptable.",
            evidence=err, remediation="Install a valid, in-date certificate for this hostname.", cwe="CWE-295")]

    out: list[Finding] = []
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(Finding(
            title=f"Obsolete TLS version negotiated ({version})", severity=Severity.HIGH,
            source_tool="tls", layer="transport", location=host,
            description=f"{version} is broken and disabled in modern browsers.",
            remediation="Require TLS 1.2 or higher.", cwe="CWE-327"))

    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    left = expires - datetime.now(timezone.utc)
    if left < timedelta(days=21):
        out.append(Finding(
            title=f"TLS certificate expires in {max(left.days, 0)} days", severity=Severity.MEDIUM,
            source_tool="tls", layer="transport", location=host,
            description="When it expires every visitor sees a full-page browser warning and the site is effectively down.",
            evidence=f"notAfter: {cert['notAfter']}",
            remediation="Renew it, and turn on auto-renewal so this cannot recur."))
    return out


if __name__ == "__main__":  # self-check — pure logic, no network
    from core.net import Resp
    bare = Resp(url="https://x.test", status=200, headers={}, cookies=["sid=1"])
    titles = {f.title for f in headers(bare)}
    assert "No HSTS" in titles and "No Content-Security-Policy" in titles
    assert "Cookie without Secure: sid" in titles
    hard = Resp(url="https://x.test", status=200, cookies=["sid=1; Secure; HttpOnly"], headers={
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff", "referrer-policy": "no-referrer"})
    assert headers(hard) == [], [f.title for f in headers(hard)]
    assert _php_eol("server", "Apache/2.4 PHP/8.0.30", "u")[0].severity is Severity.CRITICAL
    assert _php_eol("server", "Apache/2.4 PHP/8.4.1", "u") == []
    print("passive self-check ok")
