"""The CSO loop.

    v0.1  URL  -> fingerprint -> passive scan ------------------> teaser grade
    v0.2  repo -> ownership   -> code + deps scan --------------> full CSO report

v0.3 (sandbox + attack) and v0.4 (fix + reverify) hang off the same seam: another
list of callables returning Findings.
"""
from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from core.findings import Finding, ProofStatus, dedupe
from core.net import fetch, fetch_many, normalize
from fingerprint.detect import Stack, detect, script_urls
from ownership.github import NotVerified, Ownership
from ownership import github
from scanners import gitleaks, nuclei, opengrep, osv, passive, repo as repo_checks, secrets, trivy
from scanners._tool import how, status

# Borrowed scanners, in the order DEVELOPMENT_PLAN §5 lists them.
BORROWED = {"gitleaks": gitleaks, "trivy": trivy, "osv": osv, "opengrep": opengrep}


class Unreachable(Exception):
    pass


@dataclass
class Scan:
    kind: str                                   # "url" | "repo"
    target: str
    findings: list[Finding]
    stack: Stack | None = None
    ownership: Ownership | None = None
    tools: dict[str, str] = field(default_factory=dict)   # tool -> how it ran, or why not
    deep: bool = False
    _seed: object = None       # the sandbox seed, kept so the fix loop can replay the proof
    _repo: str | None = None   # the checkout the sandbox was built from, for the fix loop


def _gather(jobs: dict, log) -> tuple[list[Finding], dict[str, str]]:
    """Run every job; one broken scanner must not sink the scan."""
    findings: list[Finding] = []
    ran: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max(1, len(jobs))) as pool:
        futures = {name: pool.submit(fn) for name, fn in jobs.items()}
        for name, fut in futures.items():
            try:
                got = fut.result()
            except Exception as e:
                log(f"{name} failed: {type(e).__name__}: {e}")
                ran[name] = f"failed: {type(e).__name__}"
                continue
            log(f"{name}: {len(got)} finding(s)")
            findings += got
            ran.setdefault(name, "ok")
    return findings, ran


def scan_url(url: str, deep: bool = False, log=lambda _m: None) -> Scan:
    base = normalize(url)
    log(f"fetching {base}")
    root = fetch(base)
    if not root.ok and base.startswith("https://"):
        log("https failed, retrying over http")
        base = "http://" + base.removeprefix("https://")
        root = fetch(base)
    if not root.ok:
        raise Unreachable(f"{base}: {root.error}")

    bundles = [r for r in fetch_many(script_urls(root)) if r.ok and r.status == 200]
    log(f"fetched {len(bundles)} script bundle(s)")
    stack = detect(root, bundles)
    log(f"stack: {', '.join(stack.tech) or 'unknown'}")

    jobs = {
        "headers":  lambda: passive.headers(root),
        "tls":      lambda: passive.tls(base),
        "cors":     lambda: passive.cors(base),
        "exposure": lambda: passive.exposure(base),
        "secrets":  lambda: secrets.run(root, bundles),
    }
    if deep and nuclei.available():
        jobs["nuclei"] = lambda: nuclei.run(base)
    elif deep:
        log("nuclei not installed, skipping (brew install nuclei)")

    findings, ran = _gather(jobs, log)
    return Scan("url", base, dedupe(findings), stack=stack, tools=ran, deep=deep)


def scan_repo(target: str, log=lambda _m: None, keep: bool = False) -> Scan:
    """`target` is a local path, or owner/repo — which is verified and cloned first."""
    cleanup: Path | None = None
    ownership: Ownership | None = None

    if github.is_slug(target):
        log(f"verifying ownership of {target}")
        ownership = github.verify(target)           # raises NotVerified; the gate is the point
        log(str(ownership))
        path = github.clone(target)
        cleanup = path.parent
        log(f"cloned to {path}")
    else:
        path = Path(target).expanduser().resolve()
        if not path.is_dir():
            raise NotVerified(f"{target} is neither a directory nor a GitHub repo")
        log(f"scanning local checkout {path} (ownership not required for a local path)")

    try:
        jobs = {"repo": lambda: repo_checks.run(path)}
        ran: dict[str, str] = {}
        for name, mod in BORROWED.items():
            if how(mod.TOOL):
                jobs[name] = (lambda m=mod: m.run(path))
            else:
                ran[name] = status(mod.TOOL)
                log(f"{name}: skipped — {ran[name]}")

        findings, got = _gather(jobs, log)
        for name in got:
            ran[name] = status(BORROWED[name].TOOL) if name in BORROWED else "built-in"
        return Scan("repo", str(path if ownership is None else ownership.subject),
                    dedupe(findings), ownership=ownership, tools=ran)
    finally:
        if cleanup and not keep:
            shutil.rmtree(cleanup, ignore_errors=True)   # §16: no retention of scanned source
            log("deleted the clone")


# --- v0.3: sandbox attack arm -----------------------------------------------
def attack_sandbox(target: str, stack: str = "demo", log=lambda _m: None,
                   keep: bool = False) -> Scan:
    """Build a disposable sandbox, attack IT (never production), prove findings.

    `target` is a local path or owner/repo for a real stack, or the literal
    "demo" for the bundled vulnerable app. A real repo is ownership-gated exactly
    like scan_repo — active testing only ever runs against something you own.
    """
    import tempfile
    from pathlib import Path

    from prove import poc_runner
    from sandbox.generator import generate
    from sandbox.sandbox import Sandbox
    from scanners import zap

    ownership: Ownership | None = None
    repo_path: str | None = None
    cleanup_clone: Path | None = None

    if stack == "demo":
        log("building the bundled demo sandbox")
    elif github.is_slug(target):
        log(f"verifying ownership of {target}")
        ownership = github.verify(target)          # the active-scan gate
        log(str(ownership))
        src = github.clone(target)
        cleanup_clone = src.parent
        repo_path = str(src)
    else:
        p = Path(target).expanduser().resolve()
        if not p.is_dir():
            raise NotVerified(f"{target} is neither a directory nor a GitHub repo")
        repo_path = str(p)
        log(f"using local checkout {p} (sandbox is built from a copy; production is never touched)")

    workdir = tempfile.mkdtemp(prefix="vaultrix-sandbox-")
    plan = generate(stack, repo_path, workdir)
    log(f"generated sandbox for stack {stack!r} ({len(plan.seed.users)} seeded users)")

    findings: list[Finding] = []
    try:
        with Sandbox(plan) as sb:
            log(f"sandbox up at {sb.url}")
            login = poc_runner.json_login
            findings += poc_runner.run(sb.url, plan.seed, login=login, log=log)
            if zap.available():
                log("running ZAP baseline against the sandbox")
                findings += zap.run(sb.url)
            else:
                log("ZAP image not available, skipping active DAST (docker pull "
                    "ghcr.io/zaproxy/zaproxy:2.17.0)")
        log("sandbox torn down")
    finally:
        if cleanup_clone and not keep:
            shutil.rmtree(cleanup_clone, ignore_errors=True)

    subject = ownership.subject if ownership else (target if stack != "demo" else "demo sandbox")
    return Scan("attack", subject, dedupe(findings), ownership=ownership,
                tools={"idor_prober": "built-in", "zap": status_or(zap)},
                _seed=plan.seed, _repo=repo_path)


def status_or(mod) -> str:
    try:
        return "available" if mod.available() else "image not pulled"
    except Exception:
        return "unavailable"


# --- v0.4: fix-and-reverify --------------------------------------------------
def fix_findings(scan: "Scan", repo: str, stack: str = "demo", open_pr: bool = False,
                 log=lambda _m: None):
    """For each proven finding in `scan`, patch on a branch, rebuild the sandbox,
    replay the proof, and mark it FIXED if closed. Returns a list of FixResult.

    Opening a PR writes to the user's repo, so it happens only when open_pr=True.
    """
    from pathlib import Path

    from fix import reverify

    repo_path = Path(repo).expanduser().resolve()
    proven = [f for f in scan.findings if f.proof is ProofStatus.PROVEN]
    if not proven:
        log("no proven findings to fix")
        return []

    results = []
    for f in proven:
        log(f"fixing {f.id}: {f.title}")
        res = reverify.fix_and_verify(f, repo_path, scan._seed, stack=stack, log=log)
        log(reverify.open_pr(repo_path, res, confirm=open_pr, log=log))
        results.append(res)
    return results
