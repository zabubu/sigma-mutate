"""Run rsigma (https://github.com/timescale/rsigma) to cross-check our matcher."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time

PROCESSED = re.compile(r"Processed\s+(\d+)\s+events?,\s+(\d+)\s+match", re.IGNORECASE)


def _run_rsigma(rsigma: str, rule_path: str, events: list[dict], retries: int = 3) -> str:
    # Antivirus software sometimes locks the temp file for a moment on Windows, hence the retries.
    last: Exception | None = None
    for attempt in range(retries):
        tmp = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".ndjson", delete=False, encoding="utf-8", newline="\n") as f:
                for e in events:
                    f.write(json.dumps(e) + "\n")
                tmp = f.name
            proc = subprocess.run(
                [rsigma, "engine", "eval", "-r", rule_path, "-e", "@" + tmp],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            return (proc.stdout or "") + "\n" + (proc.stderr or "")
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


def _counts(out: str) -> tuple[int, int]:
    m = PROCESSED.search(out)
    if not m:
        raise RuntimeError(f"cannot read rsigma result:\n{out}")
    return int(m.group(1)), int(m.group(2))


def _json_objects(text: str) -> list:
    dec, objs = json.JSONDecoder(), []
    i = text.find("{")
    while i != -1:
        try:
            obj, end = dec.raw_decode(text, i)
            objs.append(obj)
            i = text.find("{", end)
        except json.JSONDecodeError:
            i = text.find("{", i + 1)
    return objs


def rsigma_matches(rsigma: str, rule_path: str, event: dict) -> bool:
    return _counts(_run_rsigma(rsigma, rule_path, [event]))[1] > 0


def rsigma_matches_many(rsigma: str, rule_path: str, events: list[dict], key_field: str = "CommandLine") -> list[bool]:
    """One boolean per event, using a single rsigma run when possible.

    rsigma reports matched field values rather than event indexes, so matches are mapped back
    through `key_field`. If that is ambiguous, fall back to one run per event.
    """
    if not events:
        return []
    keys = [str(e[key_field]) if key_field in e else None for e in events]
    if None in keys or len(set(keys)) != len(keys):
        return [rsigma_matches(rsigma, rule_path, e) for e in events]
    out = _run_rsigma(rsigma, rule_path, events)
    n_events, n_matches = _counts(out)
    if n_events != len(events):
        raise RuntimeError(f"rsigma processed {n_events} of {len(events)} events")
    if n_matches == 0:
        return [False] * len(events)
    matched = []
    for obj in _json_objects(out):
        if isinstance(obj, dict) and "matched_fields" in obj:
            vals = [str(f.get("value")) for f in obj["matched_fields"]
                    if isinstance(f, dict) and f.get("field") == key_field]
            matched.append(vals[0] if vals else None)
    if len(matched) == n_matches and None not in matched and len(set(matched)) == n_matches:
        found = set(matched)
        return [k in found for k in keys]
    return [rsigma_matches(rsigma, rule_path, e) for e in events]
