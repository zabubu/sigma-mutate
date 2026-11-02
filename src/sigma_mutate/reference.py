"""Thin wrapper around rsigma, used as a reference engine for differential tests."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time

PROCESSED = re.compile(r"Processed\s+(\d+)\s+events?,\s+(\d+)\s+match", re.IGNORECASE)


def rsigma_matches(rsigma: str, rule_path: str, event: dict, retries: int = 3) -> bool:
    """Run rsigma on a single event; True if the rule fired.

    On Windows an antivirus can briefly lock the temporary file: retry a few times.
    """
    last: Exception | None = None
    for attempt in range(retries):
        tmp = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".ndjson", delete=False, encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(event) + "\n")
                tmp = f.name
            proc = subprocess.run(
                [rsigma, "engine", "eval", "-r", rule_path, "-e", "@" + tmp],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            out = (proc.stdout or "") + "\n" + (proc.stderr or "")
            m = PROCESSED.search(out)
            if not m:
                raise RuntimeError(f"cannot read rsigma result (exit {proc.returncode}):\n{out}")
            return int(m.group(2)) > 0
        except PermissionError as e:
            last = e
            time.sleep(0.5 * (attempt + 1))
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    raise RuntimeError(f"file access denied after {retries} attempts (antivirus?): {last}")
