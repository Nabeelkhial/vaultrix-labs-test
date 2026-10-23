"""Propose a minimal source patch for a finding, and apply it on a branch.

DEVELOPMENT_PLAN §12. A real deployment hands the finding to the model (Agent SDK)
and gets back a diff. v0.4 ships a deterministic fixer for the one class we can
prove end to end — IDOR confirmed by the prober — and leaves a clear seam
(`register`) for model-generated patches. Anything without a registered fixer
returns None: we never apply a patch we cannot re-verify.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from core.findings import Finding


@dataclass
class Patch:
    finding_id: str
    files: dict[str, str]          # repo-relative path -> full new content
    explanation: str               # plain-English, for the PR body

    def diff(self, repo: Path) -> str:
        """Unified diff against what is on disk now, for display and the PR."""
        chunks = []
        for rel, new in self.files.items():
            old = (repo / rel).read_text() if (repo / rel).exists() else ""
            chunks.append(_unified(rel, old, new))
        return "\n".join(chunks)


# finding (layer, source_tool) -> fixer(finding, repo) -> Patch | None
FIXERS: dict[tuple[str, str], Callable[[Finding, Path], "Patch | None"]] = {}


def register(layer: str, tool: str):
    def deco(fn):
        FIXERS[(layer, tool)] = fn
        return fn
    return deco


def propose_patch(finding: Finding, repo: Path) -> Patch | None:
    fixer = FIXERS.get((finding.layer, finding.source_tool))
    return fixer(finding, repo) if fixer else None


@register("authz", "idor_prober")
def _fix_idor_demo(finding: Finding, repo: Path) -> Patch | None:
    """Make the ownership check unconditional.

    The demo gates the ownership comparison behind a feature flag (the vulnerable
    default skips it). The fix is to enforce it always — the same shape as the
    real fix: compare the record's owner to the caller before returning it.
    """
    app = repo / "app.py"
    if not app.exists():
        return None
    src = app.read_text()
    patched, n = re.subn(
        r'if FIXED and (owner\["token"\] != caller\["token"\]):',
        r'if \1:  # vaultrix-fix: enforce object ownership (was gated behind a flag)',
        src)
    if n == 0 or patched == src:
        return None
    return Patch(
        finding_id=finding.id,
        files={"app.py": patched},
        explanation=(
            "Enforce object-level authorization on the record endpoint. The handler "
            "verified the caller was logged in but did not check that the record "
            "belonged to them, so any authenticated user could read another user's "
            "record by changing the id. This patch compares the record's owner to "
            "the caller and returns 403 on a mismatch, for every request."),
    )


def apply_on_branch(repo: Path, patch: Patch, branch: str,
                    base: str | None = None) -> None:
    """Create `branch`, write the patched files, and commit. Leaves the repo on
    the new branch. Caller owns pushing / PR."""
    _git(repo, "checkout", "-b", branch, *( [base] if base else [] ))
    for rel, content in patch.files.items():
        (repo / rel).write_text(content)
    _git(repo, "add", *patch.files.keys())
    _git(repo, "-c", "user.email=fix@vaultrix.labs", "-c", "user.name=Vaultrix",
         "commit", "-m", f"vaultrix-fix: {patch.finding_id}\n\n{patch.explanation}")


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()[:300]}")
    return r.stdout


def _unified(path: str, old: str, new: str) -> str:
    import difflib
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=f"a/{path}", tofile=f"b/{path}"))


if __name__ == "__main__":  # self-check — patch synthesis + diff, no git/docker
    import tempfile
    from core.findings import Severity, ProofStatus
    repo = Path(tempfile.mkdtemp(prefix="vaultrix-fix-test-"))
    (repo / "app.py").write_text('x\nif FIXED and owner["token"] != caller["token"]:\n    deny()\n')
    f = Finding("Broken object-level authorization (IDOR)", Severity.CRITICAL,
                "idor_prober", "authz", "/api/records/2", "d", proof=ProofStatus.PROVEN)
    patch = propose_patch(f, repo)
    assert patch is not None and "app.py" in patch.files
    assert "if FIXED" not in patch.files["app.py"], "the flag gate must be gone"
    assert "vaultrix-fix" in patch.files["app.py"]
    d = patch.diff(repo)
    assert d.startswith("--- a/app.py") and "+" in d, d

    # a finding with no registered fixer must not fabricate a patch
    g = Finding("Something else", Severity.LOW, "headers", "hardening", "x", "d")
    assert propose_patch(g, repo) is None
    import shutil; shutil.rmtree(repo, ignore_errors=True)
    print("patch self-check ok")
