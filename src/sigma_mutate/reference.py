"""Thin wrapper around rsigma, used as a reference engine for differential tests."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile

PROCESSED = re.compile(r"Processed\s+(\d+)\s+events?,\s+(\d+)\s+match", re.IGNORECASE)


def rsigma_matches(rsigma: str, rule_path: str, event: dict) -> bool:
    """Run rsigma on a single event; True if the rule fired."""
    with tempfile.NamedTemporaryFile("w", suffix=".ndjson", delete=False, encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(event) + "\n")
        tmp = f.name
    try:
        proc = subprocess.run(
            [rsigma, "engine", "eval", "-r", rule_path, "-e", "@" + tmp],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    finally:
        os.unlink(tmp)
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = PROCESSED.search(out)
    if not m:
        raise RuntimeError(f"cannot read rsigma result (exit {proc.returncode}):\n{out}")
    return int(m.group(2)) > 0
