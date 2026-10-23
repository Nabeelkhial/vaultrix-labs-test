"""One runner for every borrowed scanner.

DEVELOPMENT_PLAN §5: invoke every scanner as a subprocess, never import it as a
library, so GPL/LGPL tools stay at arm's length and any one is swappable.

Native binary if it is on PATH, otherwise the pinned Docker image — so the user
installs nothing. §5 supply-chain note: tags are pinned, never `:latest`.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

MOUNT = "/src"


@dataclass(frozen=True)
class Tool:
    name: str            # binary name on PATH
    image: str           # pinned image, used when the binary is absent
    network: bool = False  # does it need to reach a vulnerability database?
    install: str = ""    # hint shown by `doctor`
    note: str = ""       # shown by `doctor` when the image is not the tool's own


def how(tool: Tool) -> str:
    """'native' | 'docker' | '' — how this tool can run right now."""
    if shutil.which(tool.name):
        return "native"
    if shutil.which("docker") and _docker_up():
        return "docker"
    return ""


def _docker_up() -> bool:
    try:
        return subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                              capture_output=True, timeout=15).returncode == 0
    except Exception:
        return False


def have_image(tool: Tool) -> bool:
    p = subprocess.run(["docker", "image", "inspect", tool.image],
                       capture_output=True, timeout=30)
    return p.returncode == 0


def run(tool: Tool, args: list[str], repo: Path, timeout: int = 900) -> subprocess.CompletedProcess:
    """`args` use MOUNT ('/src') for the repo path; native runs get it rewritten."""
    mode = how(tool)
    if mode == "native":
        real = str(Path(repo).resolve())
        cmd = [tool.name] + [a.replace(MOUNT, real) for a in args]
        cwd = real
    elif mode == "docker":
        cmd = ["docker", "run", "--rm",
               # read-only mount: we never write to the user's checkout
               "-v", f"{Path(repo).resolve()}:{MOUNT}:ro", "-w", MOUNT]
        if not tool.network:
            cmd += ["--network", "none"]
        cmd += [tool.image] + args
        cwd = None
    else:
        raise RuntimeError(f"{tool.name} is unavailable: no binary on PATH and no usable Docker")

    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)


def status(tool: Tool) -> str:
    """One line for `vaultrix doctor`."""
    mode = how(tool)
    if mode == "native":
        return f"native ({shutil.which(tool.name)})"
    if mode == "docker":
        return f"docker {tool.image}" + ("" if have_image(tool) else "  [image not pulled yet]")
    return f"unavailable — {tool.install}"


if __name__ == "__main__":  # self-check — command construction, nothing executed
    t = Tool("nope-not-a-real-binary", "img:1.0", network=True)
    assert how(t) in ("docker", ""), how(t)
    if how(t) == "docker":
        import unittest.mock as m
        with m.patch("subprocess.run") as run_mock:
            run_mock.return_value.returncode = 0   # keep the docker-up probe happy
            run(t, ["scan", MOUNT], Path("."))
            cmd = run_mock.call_args[0][0]
        assert cmd[:3] == ["docker", "run", "--rm"] and "--network" not in cmd, cmd
        assert cmd[-2:] == ["scan", MOUNT] and ":ro" in cmd[4], cmd
        t2 = Tool("nope-not-a-real-binary", "img:1.0", network=False)
        with m.patch("subprocess.run") as run_mock:
            run_mock.return_value.returncode = 0
            run(t2, ["x"], Path("."))
        assert "--network" in run_mock.call_args[0][0], "offline tools must be network-isolated"
    print("_tool self-check ok")
