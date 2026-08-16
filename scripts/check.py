#!/usr/bin/env python3
"""Run the dependency-free source release gate from the repository root."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    environment = os.environ.copy()
    source = str(ROOT / "src")
    environment["PYTHONPATH"] = source + os.pathsep + environment.get("PYTHONPATH", "")
    commands = (
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        [sys.executable, "-m", "compileall", "-q", "src", "tests", "scripts"],
        ["git", "diff", "--check"],
    )
    for command in commands:
        print("+", " ".join(command), flush=True)
        completed = subprocess.run(command, cwd=ROOT, env=environment, check=False)
        if completed.returncode:
            return completed.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
