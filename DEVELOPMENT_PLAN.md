# Vaultrix Labs Test — Development Plan

> Open-source "AI Chief Security Officer" for AI-built SaaS apps.
> Paste a URL for a free security grade. Connect a repo to unlock the full
> report and a one-click fix. Run the aggressive "attack" scan only against a
> sandbox the tool builds from your own code.

**Status:** Planning / pre-development
**License (our code):** MIT
**Owner:** Nabeel (Vaultrix Labs)
**Last updated:** 2026-10-23

---

## 1. Problem

Most new SaaS apps are now built largely by AI, often by people who are not
security engineers. The result is a predictable set of holes that AI models
reproduce across thousands of codebases. Independent numbers back this up:

- AI-generated code carries roughly **2.74x more vulnerabilities** than
  human-written code (AppSec Santa, 2025).
- One audit of 5 real vibe-coded apps found **5/5 had a critical bug**, 3 had
  API keys exposed in frontend JavaScript, and 4 had row-level security off.
- Only **~22% of confirmed AI-code vulnerabilities were caught by more than one
  SAST tool** — so any single scanner misses most issues.

The October 2026 **PHP2Shell** outbreak (CVE-2026-109618 / CVE-2026-109619, both
CVSS 9.2, unauthenticated RCE, ~884k hosts on end-of-life PHP) proved a second
point: the dangerous flaws are not only in app code. They are in the runtime,
the dependencies, and the deployment. A source-only tool would have missed
PHP2Shell entirely. **We have to cover code, dependencies, runtime, and the live
surface.**

### Who we serve

Non-technical and semi-technical founders who shipped with Lovable, Bolt,
Cursor, v0, Replit, or Claude Code and have no idea whether their app is safe.

---

## 2. What exists today, and the gap

| Tool | Strength | Gap |
|---|---|---|
| Anthropic `/security-review` | Ships in Claude Code, semantic diff scan | Diffs only. No runtime, infra, or live checks. No proof. |
| Trail of Bits skills | Expert-grade static analysis | For professional auditors; CC BY-SA ShareAlike limits commercial reuse. |
| Strix / Shannon | Autonomous pentest with real PoCs | For security pros; needs Docker + judgment; not tuned to vibe stacks. |
| vibecheck / VibeScan / Heimdall | Know the vibe-coding threat model | Closed, paid, shallow checks, hand back a prompt but don't fix + verify. |
| Semgrep / Gitleaks / Trivy / ZAP | Deterministic, free, trusted | Noisy, need expertise, each misses most AI-code bugs alone. |

**The gap:** nobody combines verified exploitation, fix-and-reverify in your own
repo, and fully open + agent-native packaging, aimed at the person who built the app.

### Our wedge (the three things no competitor combines)

1. **Verified, not guessed** — prove each high finding with a safe PoC.
2. **Fix and re-verify** — patch on a branch, rebuild the sandbox, re-run the
   proof, confirm the hole is closed.
3. **Open and agent-native** — one engine shipped as a Claude Code skill, an MCP
   server, and a CLI.

---

## 3. Product model: three tiers, two gates

The core safety and legal rule: **passive is open to any URL; anything active
requires proof of ownership and runs only against a sandbox, never production.**
Active testing of a site you don't own is unauthorized access and a crime in
most jurisdictions (CFAA in the US, CMA in the UK, PECA 2016 in Pakistan). The
ownership gate is a feature, not a limitation.

```
Paste URL          → Passive scan (safe, any site, read-only)   → Teaser grade
Connect GitHub     → Code + deps scan (also proves ownership)   → Full CSO report
[Attack] button    → Build sandbox from repo (seeded fake data) → "What a hacker
                     → ZAP + custom probes attack the sandbox      could do" report
                     → Fix on branch → rebuild → re-run → confirm closed
```

### Ownership verification

- **Primary: GitHub connect.** Proves ownership *and* unlocks the code layer in
  one step.
- **Secondary: DNS TXT record** (e.g. `vaultrix-verify=<token>`). The web server
  never touches it, so there is zero risk to the app. This is how Google and SSL
  providers verify.
- We do **not** rely on dropping a file on the server as the main method.

### Why the sandbox

A non-technical founder has no staging environment, and firing an active scan at
production can corrupt real data or take the site down. So the tool **builds a
disposable environment from the repo** (Docker + seeded fake DB, fully isolated),
attacks that as aggressively as it wants, then tears it down. Production gets
**passive checks only** (headers, exposed files, version banners — where
PHP2Shell shows up). Aggressive in the sandbox, passive on production.

---

## 4. The engine: find → prove → fix → reverify

```
  URL ─▶ Fingerprint ─▶ Passive scan ─────────────────────▶ Teaser grade
                           │
        (repo connected)   ▼
                        Code + deps scan ──────────────────▶ Full CSO report
                           │
        ([Attack])         ▼
                        Build sandbox ─▶ Active scan ─▶ Prove ─▶ "Hacker" report
                                            │
                                            ▼
                        Generate fix ─▶ Rebuild sandbox ─▶ Re-run proof ─▶ Confirm
```

The AI orchestrator is the product. The scanners are commodities it drives. The
orchestrator fingerprints the stack, chooses which checks apply, normalizes every
tool's output into one finding model, dedupes and ranks, proves the high ones,
writes the plain-English report, generates the fix, and re-verifies it.

---

## 5. Open-source toolkit (verified, Oct 2026)

**Licensing rule for the whole project: invoke every scanner as a subprocess
(CLI or Docker), never import it as a library.** This keeps copyleft tools
(GPL/LGPL) at arm's length and lets us swap any one out. Our own code stays MIT.

| Layer | Tool | Repo | License | Verified version | How we use it |
|---|---|---|---|---|---|
| Fingerprint / probe | httpx | github.com/projectdiscovery/httpx | MIT | current | Detect stack, headers, tech |
| Passive / live CVE | Nuclei | github.com/projectdiscovery/nuclei | MIT | v3.x | Exposed files, misconfig, known CVEs, banners |
| TLS | testssl.sh | github.com/testssl/testssl.sh | GPLv2 (subprocess) | 3.x | TLS/cert checks |
| Secrets | Gitleaks | github.com/gitleaks/gitleaks | MIT | v8.30.x (CLI) | Repo + JS bundle secret scan |
| Deps / containers / runtime | Trivy | github.com/aquasecurity/trivy | Apache-2.0 | v0.71.0 (Jun 2026) | Dependency CVEs, images, misconfig |
| Deps (second opinion) | OSV-Scanner | github.com/google/osv-scanner | Apache-2.0 | v2.3.x | Package vulns via OSV.dev |
| Code (SAST) | OpenGrep | github.com/opengrep/opengrep | LGPL-2.1 (subprocess) | v1.25.0 (Jul 2026) | Taint analysis, OWASP + custom rules |
| Code (alt) | Semgrep CE | github.com/semgrep/semgrep | LGPL-2.1 (subprocess) | current | Fallback / rule compatibility |
| Active (DAST) | OWASP ZAP | github.com/zaproxy/zaproxy | Apache-2.0 | v2.17.0 (Dec 2025) | Dynamic probes via Automation Framework |
| Sandbox orchestration | Testcontainers | github.com/testcontainers | MIT | current | Throwaway seeded DBs, isolated run |
| Sandbox (Supabase stack) | Supabase CLI | github.com/supabase/cli | Apache-2.0 | current | Local Supabase for the first target stack |
| Model layer | Claude Agent SDK | github.com/anthropics/claude-agent-sdk-python | MIT | 0.2.x | Orchestration reasoning |
| Model routing (optional) | LiteLLM | github.com/BerriAI/litellm | MIT | current | Model-agnostic provider routing |

**Dropped on purpose:** TruffleHog (AGPL-3.0 — its network-copyleft would force
us to open-source any hosted service built on it). Gitleaks (MIT) replaces it.

**Supply-chain note:** pin every tool to an exact version + verify checksums.
Trivy's own release channel was briefly poisoned in March 2026 (the "TeamPCP"
incident); pulling `:latest` unverified is exactly how that spreads. Pin, verify,
pull from GHCR by digest.

---

## 6. What we build vs borrow

| Borrow (≈90% of detection) | Build (100% of the value) |
|---|---|
| Nuclei, Gitleaks, Trivy, OSV, OpenGrep, ZAP, testssl.sh | Orchestrator: normalize all outputs → one finding model |
| Docker, Testcontainers, Supabase CLI | **Auto-sandbox generator** (read repo → runnable isolated app + seed data) |
| Claude Agent SDK / LiteLLM | **Proof layer** (confirm a finding is real) |
| | **Fix-and-reverify loop** |
| | **IDOR / auth-logic prober** (the bug class URLs can't see) |
| | CSO report + Vaultrix Labs grade |
| | Skill / MCP / CLI packaging |

The auto-sandbox generator and the proof/reverify loop are the hard, novel
parts. Everything else is a wrapper.

---

## 7. Repository structure

```
vaultrix-labs-test/
├── core/
│   ├── orchestrator.py      # the CSO loop: fingerprint→scan→prove→fix→reverify
│   ├── findings.py          # unified Finding model, dedup, severity ranking
│   └── stack_profiles/      # per-stack rules: which checks apply
├── fingerprint/
│   └── detect.py            # httpx + bundle/header heuristics
├── scanners/                # thin subprocess wrappers, one per tool
│   ├── nuclei.py
│   ├── gitleaks.py
│   ├── trivy.py
│   ├── osv.py
│   ├── opengrep.py
│   ├── zap.py
│   └── testssl.py
├── sandbox/
│   ├── generator.py         # repo → docker-compose + seed data
│   ├── seed/                # deterministic fake-data fixtures
│   └── teardown.py
├── prove/
│   ├── idor_prober.py       # custom auth/IDOR PoC runner
│   └── poc_runner.py
├── fix/
│   ├── patch.py             # generate patch on a branch
│   └── reverify.py          # rebuild sandbox, re-run the proof
├── report/
│   ├── cso_report.py        # plain-English report
│   └── grade.py             # Vaultrix Labs grade (A–F)
├── interfaces/
│   ├── skill/SKILL.md       # Claude Code skill
│   ├── mcp/server.py        # MCP server (Cursor/Codex/any agent)
│   └── cli/main.py          # headless CLI for CI
├── examples/                # deliberately vulnerable demo apps = trophy case
│   ├── vuln-supabase-next/
│   └── vuln-laravel/
├── tests/
├── .github/workflows/       # CI: run tool on examples, publish findings
├── LICENSE                  # MIT
└── README.md
```

The `examples/` folder is strategic. Ship 3–4 deliberately vulnerable demo apps,
run the tool on them in CI, and publish the findings + fixes. A reproducible
trophy case is what earns GitHub stars and credibility — the same move Trail of
Bits and Strix use.

---

## 8. The unified Finding model

Everything the scanners emit collapses into one object so the report and the
grade have a single source of truth.

```python
# core/findings.py
from dataclasses import dataclass, field
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ProofStatus(str, Enum):
    PROVEN = "proven"        # PoC succeeded in the sandbox
    UNPROVEN = "unproven"    # flagged by a tool, not yet confirmed
    FIXED = "fixed"          # patch applied and re-verified closed

@dataclass
class Finding:
    id: str                       # stable hash of (rule, location)
    title: str
    severity: Severity
    source_tool: str              # "nuclei" | "gitleaks" | "idor_prober" ...
    layer: str                    # "secrets"|"authz"|"runtime"|"injection"...
    location: str                 # file:line, route, or host
    description: str              # plain English, written by the orchestrator
    evidence: str                 # redacted PoC output or match
    proof: ProofStatus = ProofStatus.UNPROVEN
    remediation: str = ""         # the fix we propose
    cwe: str | None = None
    cve: str | None = None
    references: list[str] = field(default_factory=list)

    def dedupe_key(self) -> str:
        return f"{self.layer}:{self.location}:{self.title}".lower()
```

Dedup rule: two findings with the same `dedupe_key` are merged; the one with a
higher `proof` status and more severe `severity` wins. This is how we collapse
the overlap between Trivy, OSV, Nuclei, and OpenGrep into a clean list.

---

## 9. Scanner wrapper pattern

Every scanner wrapper follows the same shape: run as a subprocess, pin the
version, parse structured output (SARIF/JSON), map to `Finding`. Example for
Gitleaks:

```python
# scanners/gitleaks.py
import json, subprocess, tempfile, hashlib
from pathlib import Path
from core.findings import Finding, Severity, ProofStatus

GITLEAKS_VERSION = "8.30.1"   # pinned; verify checksum on install

def run(repo_path: str) -> list[Finding]:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out:
        report_path = out.name
    # --redact keeps secrets out of our logs and the report
    proc = subprocess.run(
        ["gitleaks", "detect", "--source", repo_path,
         "--report-format", "json", "--report-path", report_path,
         "--redact", "--exit-code", "0"],
        capture_output=True, text=True, timeout=600,
    )
    findings: list[Finding] = []
    data = json.loads(Path(report_path).read_text() or "[]")
    for item in data:
        loc = f'{item.get("File")}:{item.get("StartLine")}'
        fid = hashlib.sha256(f'gitleaks:{loc}:{item.get("RuleID")}'.encode()).hexdigest()[:12]
        findings.append(Finding(
            id=fid,
            title=f'Exposed secret: {item.get("RuleID")}',
            severity=Severity.HIGH,
            source_tool="gitleaks",
            layer="secrets",
            location=loc,
            description=f'A secret matching rule {item.get("RuleID")} is committed in the repo.',
            evidence=item.get("Match", "[redacted]"),
            proof=ProofStatus.UNPROVEN,
            remediation="Rotate the key immediately and move it to an environment variable or secret manager.",
        ))
    return findings
```

Same pattern for `trivy.py` (`trivy fs --format json`), `osv.py`
(`osv-scanner --format json`), `nuclei.py` (`nuclei -jsonl`), `opengrep.py`
(`opengrep --sarif`), and `zap.py` (Automation Framework YAML → JSON report).

---

## 10. The sandbox generator (the hard part)

Flow:

1. Read the connected repo; `fingerprint/detect.py` returns the stack.
2. `sandbox/generator.py` writes a `docker-compose.yml` that runs the app with
   a throwaway DB and loads deterministic seed data (two fake users A and B,
   fake records owned by each — this is what the IDOR prober needs).
3. Bring it up on an isolated Docker network with no outbound access to real
   services (real API keys are stubbed).
4. Hand the live sandbox URL to the active scanners.
5. `sandbox/teardown.py` destroys everything, including volumes.

```python
# sandbox/generator.py (shape, not full)
def generate(stack: str, repo_path: str, workdir: str) -> SandboxHandle:
    if stack == "supabase-next":
        return _supabase_next(repo_path, workdir)
    raise UnsupportedStack(stack)   # v1 supports one stack, fails loudly otherwise
```

Honest limitation to document in the README: some bugs only exist with
production's real config and data volume. The sandbox catches the large majority
of code and logic bugs; the passive production layer covers the config/exposure
rest without ever touching real data.

---

## 11. The proof layer — IDOR prober example

This is the bug class a URL scan can't see and that AI writes most often: the app
checks that you're logged in but not that the record is yours.

```python
# prove/idor_prober.py (shape)
def probe_idor(base_url, session_a, session_b, owned_by_b):
    """
    Logged in as user A, try to read a record seeded as owned by user B.
    If A can read B's record, authorization is broken — a PROVEN finding.
    """
    resp = session_a.get(f"{base_url}/api/records/{owned_by_b.id}")
    if resp.status_code == 200 and owned_by_b.secret_marker in resp.text:
        return Finding(
            id=idor_id(owned_by_b.id),
            title="Broken object-level authorization (IDOR)",
            severity=Severity.CRITICAL,
            source_tool="idor_prober",
            layer="authz",
            location=f"/api/records/{owned_by_b.id}",
            description="User A can read a record owned by user B. Any logged-in "
                        "user can read other users' data by changing the ID.",
            evidence=f"GET returned 200 with B's marker while authenticated as A.",
            proof=ProofStatus.PROVEN,
            remediation="Enforce an ownership check (e.g. WHERE user_id = current_user) "
                        "or enable row-level security on this table.",
        )
    return None
```

Only findings confirmed this way get `PROVEN`. Everything else stays `UNPROVEN`
in the report. That honesty is the product.

---

## 12. Fix-and-reverify loop

```python
# fix/reverify.py (shape)
def fix_and_verify(finding, repo, sandbox_gen, prover):
    branch = f"vaultrix-fix/{finding.id}"
    repo.create_branch(branch)
    patch = generate_patch(finding)          # model proposes a minimal patch
    repo.apply(patch, branch)
    sb = sandbox_gen.build(repo, ref=branch)  # rebuild from the patched branch
    try:
        still_open = prover.replay(finding, sb)
        finding.proof = ProofStatus.FIXED if not still_open else finding.proof
    finally:
        sb.teardown()
    return finding, patch, branch             # open a PR, don't auto-merge
```

For non-technical users: **open a PR with a plain-English explanation; never
auto-merge.** The user clicks merge.

---

## 13. Packaging — one engine, three interfaces

- **Claude Code skill** (`interfaces/skill/SKILL.md`): the headline artifact for
  the repo. `name` + `description` so Claude Code auto-routes to it.
- **MCP server** (`interfaces/mcp/server.py`): exposes `scan_url`, `scan_repo`,
  `attack_sandbox`, `fix_finding` as tools so Cursor / Codex / any agent can call
  the engine.
- **CLI** (`interfaces/cli/main.py`): `vaultrix scan <url>`,
  `vaultrix scan --repo <path>`, `vaultrix attack --repo <path>` for CI.

All three call `core/orchestrator.py`. No logic lives in the interfaces.

---

## 14. Roadmap

### v0.1 — Passive MVP (target: 2 weeks)
- Fingerprint + passive scan (Nuclei, testssl, headers, exposed files, JS-bundle
  secrets via Gitleaks).
- Unified Finding model + dedup + CSO report + grade.
- CLI only.
- **Deliverable:** paste a URL, get a graded teaser report.

### v0.2 — Code + deps (target: +2 weeks)
- GitHub connect (ownership proof).
- Gitleaks (full repo), Trivy, OSV, OpenGrep.
- Full CSO report.
- Ship as a Claude Code skill.

### v0.3 — Sandbox + attack (target: +4 weeks, the hard milestone)
- Sandbox generator for **Supabase + Next.js only**.
- ZAP active scan + IDOR/auth prober in the sandbox.
- `PROVEN` findings and the "what a hacker could do" report.

### v0.4 — Fix loop
- Patch-on-branch + rebuild + re-verify + PR.
- `FIXED` status.

### v0.5 — Credibility + reach
- `examples/` trophy case running in CI.
- MCP server.
- Live CVE watcher (OSV/NVD feed) so new PHP2Shell-class CVEs flag same-day.
- Second stack (PHP/Laravel) — PHP2Shell audience.

---

## 15. Open decisions (confirm before coding)

1. **First stack = Supabase + Next.js?** (Recommended. Sandbox generation is
   per-stack and the hard 60% of the work, so v1 nails one stack.)
2. **Model layer:** hard-wire Claude Agent SDK (cleaner, faster to build) or
   model-agnostic via LiteLLM from day one (broader adoption, more work)?
   Recommendation: Agent SDK for v0.1–v0.3, add LiteLLM routing at v0.5.
3. **Fix autonomy:** PR-only (recommended) vs auto-commit to branch.
4. **Hosting:** local-Docker sandbox for the OSS repo (zero infra cost);
   hosted ephemeral sandbox as a later paid tier.

---

## 16. Legal and safety guardrails (non-negotiable)

- Active scanning only against an ownership-verified target, and only against the
  sandbox — never the user's production.
- Passive scanning of a third-party URL stays read-only (no payloads, no auth
  attempts).
- Terms of use must state the tool is for assets the user owns or is authorized
  to test.
- Redact secrets in all logs and reports (`--redact`).
- Pin and checksum every third-party tool; pull images by digest.
- No data retention of scanned source beyond the run.

---

## 17. Verified sources

- PHP2Shell: Kaspersky — https://www.kaspersky.com/blog/cve-2026-109618-109619-php-vulnerabilities/56583/
- Vibe-coding vuln rates: AppSec Santa — https://appsecsanta.com/api-ai-security/vibe-coding-security
- Georgia Tech Vibe Security Radar — https://www.cc.gatech.edu/news/bad-vibes-ai-generated-code-vulnerable-researchers-warn
- Nuclei (MIT) — https://github.com/projectdiscovery/nuclei
- Gitleaks (MIT) — https://github.com/gitleaks/gitleaks
- Trivy (Apache-2.0, v0.71.0) — https://github.com/aquasecurity/trivy
- OSV-Scanner (Apache-2.0, v2.3.x) — https://github.com/google/osv-scanner
- OpenGrep (LGPL-2.1, v1.25.0) — https://github.com/opengrep/opengrep
- Semgrep licensing — https://semgrep.dev/docs/faq/comparisons/opengrep
- TruffleHog AGPL-3.0 (why we dropped it) — https://dev.co/security/open-source/trufflehog
- OWASP ZAP (Apache-2.0, v2.17.0) — https://www.zaproxy.org
- Claude Agent SDK (Python) — https://github.com/anthropics/claude-agent-sdk-python
- LiteLLM — https://github.com/BerriAI/litellm
- Trail of Bits skills — https://github.com/trailofbits/skills
- Strix — https://github.com/usestrix/strix
