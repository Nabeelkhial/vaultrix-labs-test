"""Plain-English report. Written for the person who built the app, not an auditor."""
from __future__ import annotations

import json
from dataclasses import asdict

from core.findings import Finding, Severity
from report.grade import counts, grade

ICON = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵", Severity.INFO: "⚪"}

LAYER_NAME = {
    "secrets": "Leaked keys", "authz": "Who can see what", "dependencies": "Out-of-date packages",
    "injection": "Unsafe handling of input", "exposure": "Things the public can read",
    "transport": "Encryption in transit", "hardening": "Browser protections", "runtime": "Server and runtime",
    "dynamic": "Found by attacking a sandbox", "authz": "Who can see what",
}


def markdown(scan) -> str:
    letter, pts, headline = grade(scan.findings)
    c = counts(scan.findings)
    L = [
        f"# Vaultrix Labs security report — {scan.target}",
        "",
        f"## Grade: {letter}  ({pts}/100)",
        f"*{headline}*",
        "",
    ]
    if scan.ownership:
        L += [f"**Ownership:** ✅ {scan.ownership.detail}", ""]
    if scan.stack:
        L += [f"**Stack detected:** {', '.join(scan.stack.tech) or 'could not tell'}"
              f"{f' (profile: {scan.stack.profile})' if scan.stack.tech else ''}"]
    L += [
        f"**Findings:** {c[Severity.CRITICAL]} critical · {c[Severity.HIGH]} high · "
        f"{c[Severity.MEDIUM]} medium · {c[Severity.LOW]} low",
        "",
    ]

    top = [f for f in scan.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)][:3]
    if top:
        L += ["## Fix these first", ""]
        L += [f"{i}. **{f.title}** — {f.remediation or 'see below'}" for i, f in enumerate(top, 1)]
        L += [""]

    if not scan.findings:
        L += ["No issues found by the checks that ran.", ""]
    else:
        L += ["## Everything we found", ""]
        for layer in dict.fromkeys(f.layer for f in scan.findings):
            L += [f"### {LAYER_NAME.get(layer, layer.title())}", ""]
            for f, siblings in _rollup(x for x in scan.findings if x.layer == layer):
                L += [
                    f"#### {ICON[f.severity]} {f.title}",
                    f"`{f.severity.value}` · found by `{f.source_tool}` · proof: `{f.proof.value}`",
                    "",
                    f"**Where:** {f.location}",
                    "",
                    f.description,
                    "",
                ]
                if f.evidence:
                    L += ["**Evidence:**", "```", f.evidence[:500], "```", ""]
                if f.remediation:
                    L += [f"**Fix:** {f.remediation}", ""]
                if siblings:
                    ids = [x.cve or x.title.split(": ")[-1] for x in siblings]
                    L += [f"**Also in this package:** {len(siblings)} more known "
                          f"{'vulnerability' if len(siblings) == 1 else 'vulnerabilities'} — "
                          f"{', '.join(ids[:8])}"
                          f"{' …' if len(ids) > 8 else ''}. The same upgrade closes them all.", ""]
                meta = [x for x in (f.cwe, f.cve) if x] + f.references
                if meta:
                    L += [f"*{' · '.join(meta)}*", ""]

    L += ["---", ""]
    if scan.tools:
        L += ["## Which scanners ran", "",
              *[f"- `{n}` — {s}" for n, s in sorted(scan.tools.items())], ""]
    L += _limits(scan)
    L += ["*Every finding above is `unproven` — flagged, not exploited. "
          "Only the sandbox attack stage marks a finding `proven`.*", ""]
    return "\n".join(L)


def _rollup(findings):
    """Yield (finding, siblings). Many CVEs in one package are one upgrade, so the
    report leads with the worst and counts the rest instead of printing 48 entries.
    Only dependencies collapse; everything else is listed in full."""
    groups: dict[tuple[str, str], list] = {}
    loose: list = []
    for f in findings:
        if f.layer == "dependencies":
            groups.setdefault((f.layer, f.location), []).append(f)
        else:
            loose.append(f)          # two leaked keys in one file are two jobs
    for f in loose:
        yield f, []
    for group in groups.values():
        group.sort(key=lambda f: f.rank, reverse=True)
        yield group[0], group[1:]


def _limits(scan) -> list[str]:
    if scan.kind == "url":
        out = [
            "## What this scan did NOT check", "",
            "This was a **passive, read-only** scan of a public URL: response headers, exposed files, "
            "TLS, and secrets in the JavaScript your site ships to browsers. It did not log in, send "
            "attack payloads, or touch your database.", "",
            "It therefore cannot see your most likely serious bug: **broken authorization** — one "
            "logged-in user being able to read another user's data. Connect your repo with "
            "`scan --repo` to add the code, dependency and row-level-security layers.", "",
        ]
        if not scan.deep:
            out += ["Run with `--deep` on a site you own to add Nuclei's known-CVE templates.", ""]
        return out
    if scan.kind == "watch":
        return [
            "## About this report", "",
            "This is a **dependency CVE watch** against OSV.dev — the known vulnerabilities in the "
            "packages your project depends on. Run it on a schedule with `--since` to catch new "
            "advisories the day they publish.", "",
            "It does not read your own code or run your app; pair it with `scan --repo` and `attack`.", "",
        ]
    if scan.kind == "attack":
        proven = sum(1 for f in scan.findings if f.proof.value == "proven")
        return [
            "## About this report", "",
            f"We built a **disposable copy** of your app from the code — a throwaway database "
            "seeded with two fake users — attacked that, and destroyed it. Your real app and real "
            "data were never touched.", "",
            (f"**{proven} finding(s) are proven.** A proven finding is not a warning: we logged in "
             "as one user and actually received another user's private data. If you see a proven "
             "IDOR below, any of your users can do the same to each other right now." if proven else
             "No authorization bypass was proven in the sandbox — good. That covers the data we "
             "seeded; test with your own data shapes too."), "",
            "The sandbox catches code and logic bugs. Some bugs only appear with production's real "
            "configuration and data volume — pair this with `scan <url>` for the live surface.", "",
        ]
    return [
        "## What this scan did NOT check", "",
        "This read your **code and dependencies**. It did not run your app, so nothing here is proven "
        "by exploitation — a missing authorization check is reported because it is absent from the "
        "source, not because we called the route and got someone else's data.", "",
        "Row-level-security findings are read from your migration files. If you enabled RLS by hand in "
        "the Supabase dashboard, we cannot see that — check those tables before acting.", "",
        "Pair this with `scan <url>` for the live surface (headers, TLS, exposed files, runtime version).", "",
    ]


def as_json(scan) -> str:
    letter, pts, headline = grade(scan.findings)
    return json.dumps({
        "kind": scan.kind,
        "target": scan.target,
        "grade": letter,
        "score": pts,
        "headline": headline,
        "ownership": asdict(scan.ownership) if scan.ownership else None,
        "stack": ({"tech": scan.stack.tech, "profile": scan.stack.profile,
                   "banners": scan.stack.banners} if scan.stack else None),
        "tools": scan.tools,
        "counts": {s.value: n for s, n in counts(scan.findings).items()},
        "findings": [asdict(f) for f in scan.findings],
    }, indent=2, default=str)
