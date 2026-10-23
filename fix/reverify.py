"""The fix-and-reverify loop (DEVELOPMENT_PLAN §12).

For a proven finding: branch, patch, rebuild the sandbox from the patched tree,
re-run the exact proof that confirmed the bug, and mark it FIXED only if the
proof no longer succeeds. We never claim a fix we did not re-verify.

A PR pushes to the user's real repository — an outward, side-effectful action —
so `fix_and_verify` only ever prepares the branch locally. Opening the PR is a
separate, explicit step (`open_pr`), never automatic, and never auto-merged.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from core.findings import Finding, ProofStatus
from core.seed import Seed
from fix.patch import Patch, apply_on_branch, propose_patch
from prove import poc_runner
from sandbox.generator import generate
from sandbox.sandbox import Sandbox


@dataclass
class FixResult:
    finding: Finding
    patch: Patch | None
    branch: str | None
    reverified: bool            # True only if the proof no longer fires after the patch
    note: str
    diff: str = ""              # the unified diff, captured before the branch dance

    @property
    def closed(self) -> bool:
        return self.reverified and self.finding.proof is ProofStatus.FIXED


def fix_and_verify(finding: Finding, repo: Path, seed: Seed, stack: str = "demo",
                   log=lambda _m: None) -> FixResult:
    if finding.proof is not ProofStatus.PROVEN:
        return FixResult(finding, None, None, False,
                         "only proven findings are auto-fixed; this one was not exploited")
    patch = propose_patch(finding, repo)
    if patch is None:
        return FixResult(finding, None, None, False,
                         "no automated fixer for this finding class yet — fix by hand")

    diff = patch.diff(repo)      # capture now, while the original is still on disk
    branch = f"vaultrix-fix/{finding.id}"
    base = _current_ref(repo)
    apply_on_branch(repo, patch, branch, base=base)
    log(f"patched on branch {branch}")

    try:
        workdir = tempfile.mkdtemp(prefix="vaultrix-reverify-")
        plan = generate(stack, str(repo), workdir)   # build from the patched checkout
        with Sandbox(plan) as sb:
            log(f"rebuilt sandbox at {sb.url}, replaying the proof")
            still = poc_runner.run(sb.url, seed, log=lambda _m: None)
        reverified = not any(f.id == finding.id for f in still)
    finally:
        _git(repo, "checkout", base)   # leave the repo back on its base branch

    if reverified:
        finding.proof = ProofStatus.FIXED
        note = "re-ran the proof against the patched sandbox: the hole is closed"
        log(note)
    else:
        note = "patch applied but the proof still fires — not marking fixed"
        log(note)
    return FixResult(finding, patch, branch, reverified, note, diff=diff)


def open_pr(repo: Path, result: FixResult, *, confirm: bool = False,
            log=lambda _m: None) -> str:
    """Push the branch and open a PR via gh. Refuses unless `confirm` is True,
    because this writes to the user's GitHub repo. Never auto-merges."""
    if not result.branch or not result.closed:
        return "no PR: nothing was fixed and re-verified"
    if not _has_github_remote(repo):
        return (f"branch {result.branch} is ready locally, but this checkout has no GitHub "
                "remote, so there is no PR to open. Push it to your repo yourself.")
    if not confirm:
        return (f"ready to open a PR from {result.branch} (not done — opening a PR writes to "
                "your GitHub repo). Re-run with --open-pr to push and open it.")

    import subprocess
    _git(repo, "push", "-u", "origin", result.branch)
    title = f"Fix: {result.finding.title}"
    body = (f"{result.patch.explanation}\n\n"
            f"**Vaultrix re-verified this fix**: after the patch, the sandbox proof for "
            f"`{result.finding.id}` no longer succeeds.\n\n"
            f"Finding: {result.finding.title} ({result.finding.cwe or 'authz'}) at "
            f"`{result.finding.location}`.\n\nReview and merge — this was not auto-merged.\n\n"
            "🤖 Generated with [Claude Code](https://claude.com/claude-code)")
    r = subprocess.run(["gh", "pr", "create", "--title", title, "--body", body,
                        "--head", result.branch],
                       cwd=str(repo), capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return f"push ok, but gh pr create failed: {r.stderr.strip()[:300]}"
    url = r.stdout.strip()
    log(f"opened PR: {url}")
    return url


def _git(repo: Path, *args: str) -> str:
    import subprocess
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()[:200]}")
    return r.stdout


def _current_ref(repo: Path) -> str:
    return _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()


def _has_github_remote(repo: Path) -> bool:
    try:
        return "github.com" in _git(repo, "remote", "-v")
    except RuntimeError:
        return False


if __name__ == "__main__":  # self-check — guards only; the real loop is in the e2e test
    from core.findings import Finding, Severity
    unproven = Finding("x", Severity.HIGH, "headers", "hardening", "l", "d")
    r = fix_and_verify(unproven, Path("/tmp"), Seed([]))
    assert not r.closed and "only proven" in r.note, r.note
    assert open_pr(Path("/tmp"), r) == "no PR: nothing was fixed and re-verified"
    print("reverify self-check ok")
