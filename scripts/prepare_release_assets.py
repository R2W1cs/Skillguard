#!/usr/bin/env python3
"""Build package artifacts and write SHA-256 checksums for a release."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
RELEASE = ROOT / "release"
VERSION = "0.3.0"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    RELEASE.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, "-m", "build"], cwd=ROOT, check=True)
    artifacts = sorted(DIST.glob(f"skillguard-{VERSION}*"))
    if not artifacts:
        print(f"No artifacts matching skillguard-{VERSION}* in dist/", file=sys.stderr)
        return 1
    lines = []
    for path in artifacts:
        digest = sha256_file(path)
        lines.append(f"{digest}  {path.name}")
        print(f"{path.name}: {digest}")
    out = RELEASE / f"SHA256SUMS-{VERSION}.txt"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
