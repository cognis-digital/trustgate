#!/usr/bin/env python3
"""Demo 01 — runnable scenario for TrustGate.

Builds a throwaway copy of `sample-project/`, plants an out-of-repo symlink
(symlinks don't survive a git checkout reliably, so we create it at runtime),
then runs TrustGate against it and prints the report.

Usage:
    python demos/01-basic/run_demo.py            # table output
    python demos/01-basic/run_demo.py --format json
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Make the package importable when run from a checkout.
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))

from trustgate.cli import main as cli_main  # noqa: E402


def build_scenario(dest: Path) -> Path:
    src = HERE / "sample-project"
    proj = dest / "sample-project"
    shutil.copytree(src, proj)

    # Plant an out-of-repo symlink (the symlink-hijack primitive).
    # Target: a sensitive-looking host path well outside the project root.
    notes = proj / "notes"
    notes.mkdir(exist_ok=True)
    link = notes / "host-secrets"
    outside_target = (dest / "OUTSIDE_HOST_DIR")
    outside_target.mkdir(exist_ok=True)
    (outside_target / "id_rsa").write_text("FAKE PRIVATE KEY\n", encoding="utf-8")
    try:
        os.symlink(outside_target, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        print(f"[demo] WARNING: could not create symlink ({exc}); "
              f"symlink finding will be skipped on this platform.",
              file=sys.stderr)
    return proj


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the TrustGate demo scenario.")
    ap.add_argument("--format", choices=("table", "json", "sarif"),
                    default="table")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="trustgate-demo-"))
    try:
        proj = build_scenario(tmp)
        print(f"[demo] scanning {proj}\n", file=sys.stderr)
        rc = cli_main(["scan", str(proj), "--format", args.format,
                       "--fail-on", "high"])
        print(f"\n[demo] exit code = {rc} "
              f"(non-zero means risky settings were found)", file=sys.stderr)
        return rc
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
