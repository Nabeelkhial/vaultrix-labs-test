# Vaultrix Labs Test

Open-source AI Chief Security Officer for AI-built SaaS apps.
Paste a URL for a grade. Connect a repo for the full report.

**v0.5 — the full engine behind three interfaces (CLI, MCP, Claude Code skill),
plus a live CVE watcher.** Passive scan, repo scan, a sandbox attack that
*proves* findings, and a fix loop that patches, rebuilds, re-proves and opens a
PR. The built-in checks are Python 3.11+ stdlib; the borrowed scanners and the
sandbox run from pinned Docker images when their binaries are absent.

```bash
python3 -m interfaces.cli.main scan https://yourapp.com     # passive, any site
python3 -m interfaces.cli.main scan --repo .                # local checkout
python3 -m interfaces.cli.main scan --repo owner/name       # verifies you own it, clones, scans
python3 -m interfaces.cli.main attack demo                  # build the demo sandbox, prove the IDOR
python3 -m interfaces.cli.main attack --repo owner/name     # build a sandbox from your repo, attack it
python3 -m interfaces.cli.main doctor                       # what's available and how
```

## The two gates

Passive URL checks are **read-only** — `GET`/`HEAD` only, no payloads, no login
attempts, no writes — which is why they are allowed against any URL.

Everything else needs proof the target is yours. `--repo owner/name` asks the
GitHub CLI whether the logged-in account has **write** access; read-only access is
refused. That single step proves ownership *and* unlocks the code layer. The clone
is shallow, goes to a temp dir, and is deleted when the scan ends (§16: no
retention). A local path needs no gate — it is already on your disk.

The **attack** stage never touches your running app. It builds a *disposable copy*
from the code — a throwaway database seeded with two fake users who each own one
record — attacks that copy as hard as it likes, then destroys it (`docker compose
down -v`). The sandbox port binds `127.0.0.1` only. The ZAP wrapper refuses any
non-local host as a second line of defence, so an active scan cannot be pointed at
a remote site even by mistake.

Active testing of someone else's site is a crime in most jurisdictions (CFAA, CMA,
PECA 2016). The gate is a feature, not a limitation.

## What it checks

**Live URL** — secrets in the JS bundle (Supabase `service_role`, Stripe, AWS,
OpenAI, Anthropic, GitHub, private keys), 17 publicly readable paths (`.env`,
`.git/`, DB dumps, `phpinfo.php`), end-of-life PHP (the PHP2Shell population,
CVE-2026-109618/109619), TLS validity and expiry, CORS that reflects any origin
while allowing credentials, CSP/HSTS/clickjacking/cookie flags, tech banners.

**Sandbox attack** (`attack`) — the part no competitor combines (§6):

| | |
|---|---|
| IDOR / broken-object-level-authorization prober | Logs in as user A, requests a record seeded as owned by user B. If B's unique marker comes back, authorization is broken. Confirmed, so the finding is `PROVEN` — not flagged, *exploited*. |
| OWASP ZAP baseline | Active-but-safe DAST (spider + passive + non-destructive active rules) against the sandbox URL. |

A proven IDOR is the headline: "logged in as one of your users, we read another
user's private data." That is the bug class a URL scan structurally cannot see and
that AI writes most often.

**Repository** — our own checks first, then four borrowed scanners:

| Check | Why it is ours and not a tool's |
|---|---|
| Row-level security missing on a table | Read from your migrations. Four of five audited vibe-coded apps had RLS off; no SAST tool looks for it. |
| `.env` committed to git | Deleting the file does not help — the commit still has it. |
| Secret behind a `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` name | The bundler inlines it into the browser. Naming a secret this way publishes it. |
| API route that queries the DB with no auth call | The IDOR precursor. Heuristic, so it stays MEDIUM/HIGH and `unproven`. |

| Borrowed | License | How it runs |
|---|---|---|
| Gitleaks | MIT | `zricethezav/gitleaks:v8.30.1` |
| Trivy | Apache-2.0 | `aquasec/trivy:0.71.0` |
| OSV-Scanner | Apache-2.0 | `ghcr.io/google/osv-scanner`, digest-pinned |
| OpenGrep / Semgrep CE | LGPL-2.1 | native `opengrep`, else `semgrep/semgrep`, digest-pinned |
| OWASP ZAP | Apache-2.0 | `ghcr.io/zaproxy/zaproxy:2.17.0` (sandbox only) |

Every one is a **subprocess**, never an imported library (§5), so copyleft stays at
arm's length and any of them is swappable. Docker runs get a read-only mount, and
the two that need no vulnerability database run with `--network none`.

## Noise control

This is most of the work. Raw, the fixture produces 99 findings; the report shows 10.

- **Soft-404 baseline.** A known-missing URL is fetched first and fingerprinted, so
  an SPA catch-all route does not turn into seventeen "exposed file" findings.
- **Supabase `anon` keys are never flagged** — they are public by design. The JWT
  payload is decoded and the `role` claim read. Gitleaks' blind `jwt` rule is
  dropped for the same reason: `--redact` hides the payload, so it cannot tell the
  two apart and would cry wolf.
- **Cross-tool dedupe on the CVE.** Trivy says `CVE-2019-10744`, OSV says
  `GHSA-jf85-cpcp-j695`. When a CVE is known it is the identity, not the title, so
  the two merge into one finding credited `trivy+osv`.
- **One place, one penalty.** Forty-eight CVEs in one package are a single action —
  *upgrade lodash* — so only the worst in each (layer, location) counts toward the
  grade, and the report prints the worst plus "also 47 more; the same upgrade
  closes them all".

## Grading

Points start at 100 and drop 40/20/7/2 per critical/high/medium/low, counting one
finding per place. A single critical caps the grade at F and a single high at C
whatever the points say — five hardening nits are not one leaked database key.

## Honest limits

Passive and repo findings are `unproven` — flagged, not exploited. Only the
**attack** stage produces `proven` findings, and only when a PoC actually
succeeded in the sandbox. A proven finding is the honest core of the product: it
is not a warning, it is a demonstration.

The supabase-next sandbox needs the Supabase CLI to run the real GoTrue/PostgREST
stack locally; absent it, `attack --repo` fails with an install hint. The bundled
`attack demo` target needs only Docker and proves the engine end to end.

RLS findings are read from migration files. If you enabled RLS by hand in the
Supabase dashboard we cannot see that, so check before acting.

The repo's unauthed-route check is keyword-and-path matching, not dataflow — it
points at where to look. The IDOR prober is what actually calls the route as user
A and reads user B's row; when a sandbox can be built, prefer `attack` over trusting
that heuristic.

Some bugs only exist with production's real config and data volume. The sandbox
catches the large majority of code and logic bugs; the passive production layer
covers the config/exposure rest without ever touching real data.

## Layout

```
core/         findings.py (model, CVE-aware dedupe) · net.py (HTTP/TLS + authed Client) · seed.py · orchestrator.py
ownership/    github.py — the write-access gate, shallow clone, cleanup
fingerprint/  detect.py — stack from root HTML + JS bundles
scanners/     passive.py · secrets.py · repo.py (ours) · _tool.py (native-or-Docker runner)
              gitleaks.py · trivy.py · osv.py · opengrep.py · nuclei.py · zap.py (borrowed, subprocess)
sandbox/      generator.py (repo -> compose + seed) · sandbox.py (up / wait-healthy / teardown -v)
prove/        idor_prober.py (the proof) · poc_runner.py (login -> probe)
fix/          patch.py (fixer registry + diff) · reverify.py (branch -> rebuild -> re-prove -> PR)
watch/        cve_watch.py — OSV.dev dependency CVE watch with a since-filter
report/       grade.py (A–F) · cso_report.py (markdown + JSON)
interfaces/   cli/main.py · mcp/server.py (stdio JSON-RPC) · skill/SKILL.md
examples/     vuln-supabase-next (repo fixture) · sandbox-idor-demo (runnable attack target)
tests/        test_scanner.py — end-to-end: URL, repo, in-process IDOR proof, containerised attack
```

## Tests

```bash
./check.sh
```

Serves the fixture on localhost and scans it both ways; proves the IDOR prober
over real HTTP against the vulnerable demo (two directions) and confirms the
*patched* demo proves nothing; and, when Docker is up, stands the demo sandbox up
in a real container, proves the IDOR through the full `attack` pipeline, and checks
the sandbox was torn down. Asserts the leaked `service_role` key, live Stripe key,
readable `.env`/`.git/`, RLS missing on exactly the three unprotected tables, and
the unauthed route — grade `F` throughout, `anon` key never flagged. Everything
Docker-dependent is skipped offline, and the suite still passes.

## One engine, three interfaces (§13)

No logic lives in an interface — each calls `core/orchestrator.py`.

- **CLI** (`interfaces/cli/main.py`) — `scan`, `attack`, `fix`, `watch`, `doctor`.
- **MCP server** (`interfaces/mcp/server.py`) — exposes `scan_url`, `scan_repo`,
  `attack_sandbox`, `fix_finding` to Cursor / Codex / any agent, over stdio
  JSON-RPC. Stdlib only, so it needs no extra install:
  ```json
  { "mcpServers": { "vaultrix": {
      "command": "python3",
      "args": ["-m", "interfaces.mcp.server"],
      "cwd": "/path/to/vaultrix-labs-test" } } }
  ```
- **Claude Code skill** (`interfaces/skill/SKILL.md`) — `name` + `description`
  frontmatter so Claude Code auto-routes "is my app secure?" to the engine.
- **Web front door** (`interfaces/web/`) — a Flask app: Login with GitHub, connect
  a repo you own, run the inspection, read the graded report. Passive scans run
  inline; repo scans and sandbox attacks run as background jobs. See
  `interfaces/web/README.md` for OAuth setup and deploy.

## Live CVE watcher (`watch`)

Queries OSV.dev for the CVEs in your dependencies. Run it on a schedule with
`--since` and it reports only advisories published since your last run, so a new
PHP2Shell-class CVE surfaces the day it lands — not at the next manual scan:

```bash
python3 -m interfaces.cli.main watch --repo . --since "$(date -v-1d +%F)"
```

OSV.dev is free and needs no key. Dependency CVEs are covered now; runtime CVEs
for the stack itself (PHP, nginx) live in NVD and are the next increment.

## The fix loop (`fix`)

For every **proven** finding, Vaultrix:

1. creates a branch `vaultrix-fix/<id>`,
2. applies a minimal patch (a deterministic fixer for known classes; a model seam
   for the rest — we never apply a patch we cannot re-verify),
3. rebuilds the sandbox from the patched branch,
4. **replays the exact proof** that confirmed the bug,
5. marks the finding `FIXED` only if the proof no longer succeeds.

Opening a PR writes to your GitHub repo, so `fix` only prepares the branch and
shows the diff by default. `--open-pr` pushes and opens it via `gh` — and never
auto-merges; you click merge. `fix demo` runs the whole loop on the bundled target
with nothing but Docker, and closes both seeded IDORs.

## Not built yet

A second stack (Laravel/PHP) for the sandbox; the NVD runtime-CVE feed in the
watcher; and the Agent-SDK patch generator behind the `fix/patch.py` seam, for
fixing bug classes beyond the ones with a deterministic fixer today. Roadmap in
DEVELOPMENT_PLAN.md.

MIT.
