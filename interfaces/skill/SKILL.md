---
name: vaultrix-security-scan
description: >-
  Security scan for AI-built SaaS apps (the AI Chief Security Officer). Use when
  the user wants to check whether their app or website is safe, asks for a
  security grade or report, pastes a URL or repo to audit, mentions leaked API
  keys / secrets in their frontend, exposed .env or .git, missing Supabase
  row-level security, an IDOR or "users can see each other's data" bug,
  dependency CVEs, or wants a found vulnerability proven and fixed. Triggers:
  "is my app secure", "scan my site", "security grade", "check my repo for
  vulnerabilities", "did I leak a key", "prove the IDOR", "fix and open a PR".
---

# Vaultrix Labs security scan

One engine, driven from `core/orchestrator.py`. Prefer the CLI; it prints a
plain-English report and a letter grade (A–F). Run from the repo root.

## Decide which command fits

- **Just a URL, any site** → passive, read-only, always safe:
  `python3 -m interfaces.cli.main scan <url>`
- **Their code** (local path, or `owner/name` they own on GitHub — write access
  is checked and is the ownership proof):
  `python3 -m interfaces.cli.main scan --repo <path-or-owner/name>`
- **Prove what a hacker could do** (builds a disposable sandbox from the code,
  attacks it, never touches production):
  `python3 -m interfaces.cli.main attack --repo <path-or-owner/name>`
  (`attack demo` runs the whole thing on a bundled target with just Docker.)
- **Fix a proven finding** (patch on a branch, rebuild, re-verify, prepare a PR):
  `python3 -m interfaces.cli.main fix --repo <owner/name>`
  Add `--open-pr` only when the user explicitly asks to open the PR — it writes
  to their GitHub repo and never auto-merges.
- **Watch for new CVEs** in their dependencies (schedulable):
  `python3 -m interfaces.cli.main watch --repo <path> --since <YYYY-MM-DD>`
- **What's installed** (Docker, gh, scanner images): `... doctor`

## Rules to respect (they are enforced in code, don't try to bypass them)

- Active scanning (`attack`, `--deep`) only runs against a sandbox or a target
  the user owns. Never point it at a third party's site.
- `fix --open-pr` is the only command that writes to a remote. Confirm with the
  user first; it never auto-merges.
- Every passive/repo finding is `unproven` (flagged); only `attack` produces
  `proven` findings. Say so — the honesty is the product.

## Reading the result

Lead with the grade and the "Fix these first" list. A `proven` IDOR means one
logged-in user really read another's data in the sandbox — that is the headline.
Add `--json` for machine-readable output to feed into other steps.
