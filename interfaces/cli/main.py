"""vaultrix — security grade for an AI-built app.

    vaultrix scan <url>              passive, read-only, any site
    vaultrix scan --repo <path>      code + dependencies, local checkout
    vaultrix scan --repo owner/name  verifies you own it, then clones and scans
    vaultrix doctor                  which scanners are available and how
"""
from __future__ import annotations

import argparse
import sys

from core.orchestrator import BORROWED, Unreachable, attack_sandbox, fix_findings, scan_repo, scan_url
from ownership.github import NotVerified
from report.cso_report import as_json, markdown
from report.grade import grade
from scanners._tool import status

CONSENT = ("Scan only what you own or are authorized to test. Passive URL checks are read-only; "
           "--deep and repo scanning are for your own projects.")


def _doctor() -> int:
    import shutil
    from scanners import nuclei
    print("vaultrix doctor\n")
    print(f"  {'docker':<12} {shutil.which('docker') or 'MISSING — the no-install path needs it'}")
    print(f"  {'gh':<12} {shutil.which('gh') or 'MISSING — needed for owner/repo scanning'}")
    print(f"  {'git':<12} {shutil.which('git') or 'MISSING'}")
    print()
    for name, mod in BORROWED.items():
        line = status(mod.TOOL)
        print(f"  {name:<12} {line}" + (f"\n  {'':<12} ↳ {mod.TOOL.note}" if mod.TOOL.note else ""))
    print(f"  {'nuclei':<12} {'native' if nuclei.available() else 'not installed (optional, --deep only)'}")
    from scanners import zap
    print(f"  {'zap':<12} {'available (' + zap.IMAGE + ')' if zap.available() else 'image not pulled (active DAST, attack only)'}")
    import subprocess as _sp
    base_ok = _sp.run(["docker", "image", "inspect", "python:3.13-slim"], capture_output=True).returncode == 0
    print(f"  {'sandbox':<12} {'python:3.13-slim present' if base_ok else 'python:3.13-slim not pulled (demo sandbox needs it)'}")
    print("\n  Passive URL scanning and the built-in repo checks need none of the above.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vaultrix", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=CONSENT)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="show which scanners are available")

    s = sub.add_parser("scan", help="scan a URL or a repository")
    s.add_argument("target", nargs="?", help="URL to scan passively")
    s.add_argument("--repo", help="local path, or owner/name on GitHub")
    s.add_argument("--deep", action="store_true", help="URL scans: also run Nuclei (your own sites only)")
    s.add_argument("--keep-clone", action="store_true", help="do not delete a cloned repo afterwards")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.add_argument("-o", "--out", help="write the report to a file instead of stdout")
    s.add_argument("-q", "--quiet", action="store_true", help="no progress lines")
    s.add_argument("--fail-on", choices=list("ABCDF"), help="exit 1 if the grade is worse than this")

    at = sub.add_parser("attack", help="build a sandbox from a repo and attack it (your own code only)")
    at.add_argument("target", nargs="?", default="demo",
                    help="local path, owner/name, or 'demo' for the bundled vulnerable app")
    at.add_argument("--stack", default=None,
                    help="sandbox stack (default: supabase-next for a repo, demo for 'demo')")
    at.add_argument("--keep-clone", action="store_true")
    at.add_argument("--json", action="store_true")
    at.add_argument("-o", "--out")
    at.add_argument("-q", "--quiet", action="store_true")

    fx = sub.add_parser("fix", help="attack, then patch+rebuild+re-verify each proven finding (your own code only)")
    fx.add_argument("target", nargs="?", default="demo",
                    help="local git checkout, owner/name, or 'demo'")
    fx.add_argument("--stack", default=None)
    fx.add_argument("--open-pr", action="store_true",
                    help="push the fix branch and open a PR (writes to your GitHub repo; never auto-merges)")
    fx.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args(argv)

    if a.cmd == "doctor":
        return _doctor()

    quiet = a.quiet or getattr(a, "json", False)
    log = (lambda _m: None) if quiet else (lambda m: print(f"  · {m}", file=sys.stderr))

    if a.cmd == "fix":
        return _run_fix(a, log)

    if a.cmd == "attack":
        stack = a.stack or ("demo" if a.target == "demo" else "supabase-next")
        try:
            scan = attack_sandbox(a.target, stack=stack, log=log, keep=a.keep_clone)
        except NotVerified as e:
            print(f"vaultrix: ownership not verified — {e}", file=sys.stderr); return 3
        except Exception as e:
            print(f"vaultrix: sandbox attack failed: {type(e).__name__}: {e}", file=sys.stderr); return 2
        _emit(scan, a)
        return _grade_exit(scan, None)

    if bool(a.target) == bool(a.repo):
        ap.error("give either a URL or --repo, not both")
    try:
        scan = (scan_repo(a.repo, log=log, keep=a.keep_clone) if a.repo
                else scan_url(a.target, deep=a.deep, log=log))
    except NotVerified as e:
        print(f"vaultrix: ownership not verified — {e}", file=sys.stderr)
        return 3
    except (Unreachable, ValueError) as e:
        print(f"vaultrix: {e}", file=sys.stderr)
        return 2

    _emit(scan, a)
    return _grade_exit(scan, a.fail_on)


def _emit(scan, a) -> None:
    text = as_json(scan) if a.json else markdown(scan)
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(text)
        print(f"wrote {a.out}", file=sys.stderr)
    else:
        print(text)


def _grade_exit(scan, fail_on) -> int:
    letter, _, _ = grade(scan.findings)
    if fail_on and "ABCDF".index(letter) > "ABCDF".index(fail_on):
        print(f"vaultrix: grade {letter} is worse than --fail-on {fail_on}", file=sys.stderr)
        return 1
    return 0




def _run_fix(a, log) -> int:
    """attack -> fix_findings, with `demo` bootstrapped into a throwaway git repo."""
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    from core.orchestrator import attack_sandbox
    from fix.reverify import open_pr
    from report.grade import grade
    from sandbox.generator import DEMO_DIR

    temp_repo = None
    if a.target == "demo":
        temp_repo = Path(tempfile.mkdtemp(prefix="vaultrix-demo-repo-"))
        for f in ("app.py", "Dockerfile"):
            shutil.copy(DEMO_DIR / f, temp_repo / f)
        for args in (["init", "-q"], ["add", "-A"],
                     ["-c", "user.email=demo@vaultrix.labs", "-c", "user.name=demo",
                      "commit", "-qm", "demo target"]):
            subprocess.run(["git", "-C", str(temp_repo), *args], check=True, capture_output=True)
        repo, stack = str(temp_repo), "demo"
    else:
        repo, stack = a.target, (a.stack or "supabase-next")

    try:
        scan = attack_sandbox(repo if stack != "demo" else repo, stack=stack, log=log)
        results = fix_findings(scan, repo, stack=stack, open_pr=a.open_pr, log=log)
    except Exception as e:
        print(f"vaultrix: fix failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    finally:
        if temp_repo:
            shutil.rmtree(temp_repo, ignore_errors=True)

    fixed = [r for r in results if r.closed]
    print(f"\n=== Fix summary for {scan.target} ===")
    if not results:
        print("No proven findings to fix.")
        return 0
    for r in results:
        mark = "✅ FIXED & re-verified" if r.closed else "⚠️  not fixed"
        print(f"\n{mark}: {r.finding.title}  [{r.finding.id}]")
        print(f"  {r.note}")
        if r.branch:
            print(f"  branch: {r.branch}")
        if r.diff:
            print("  patch:")
            print("\n".join("    " + ln for ln in r.diff.splitlines()[:30]))
        if r.branch and not a.open_pr:
            print(f"  (PR not opened — re-run with --open-pr to push and open it)")
    print(f"\n{len(fixed)}/{len(results)} proven finding(s) fixed and re-verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
