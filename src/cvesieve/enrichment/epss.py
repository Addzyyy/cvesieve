"""
EPSS score lookup via bulk CSV cache.

Downloads the full EPSS dataset once per day and caches it locally.
Lookup is a simple dict operation — no per-CVE API calls.

CSV format (after skipping the leading # comment line):
  cve,epss,percentile
  CVE-2024-1234,0.00123,0.45678
  ...
"""
import csv
import gzip
import io
import json
import sys
import time
from pathlib import Path

import requests

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
CACHE_FILENAME = "epss.json"
MAX_AGE_SECONDS = 86400  # 24 hours


def _cache_path(cache_dir: Path) -> Path:
    return cache_dir / CACHE_FILENAME


def _load_cache(cache_dir: Path) -> dict[str, dict] | None:
    path = _cache_path(cache_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        age = time.time() - data.get("timestamp", 0)
        if age > MAX_AGE_SECONDS:
            return None
        return data["scores"]
    except Exception:
        return None


def _save_cache(cache_dir: Path, scores: dict[str, dict]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    payload = {"timestamp": time.time(), "scores": scores}
    _cache_path(cache_dir).write_text(json.dumps(payload))


def _download_and_parse() -> dict[str, dict]:
    print("Downloading EPSS data...", file=sys.stderr)
    response = requests.get(EPSS_URL, timeout=30)
    response.raise_for_status()

    decompressed = gzip.decompress(response.content).decode("utf-8")
    scores: dict[str, dict] = {}

    reader = csv.reader(io.StringIO(decompressed))
    for row in reader:
        # Skip comment lines (start with #) and the header line
        if not row or row[0].startswith("#") or row[0] == "cve":
            continue
        if len(row) >= 3:
            cve_id = row[0].strip()
            try:
                scores[cve_id] = {
                    "epss": float(row[1]),
                    "percentile": float(row[2]),
                }
            except ValueError:
                continue

    return scores


def load_epss(cache_dir: Path, no_cache: bool = False) -> dict[str, dict]:
    if not no_cache:
        cached = _load_cache(cache_dir)
        if cached is not None:
            return cached

    try:
        scores = _download_and_parse()
        _save_cache(cache_dir, scores)
        return scores
    except Exception as e:
        print(f"Warning: failed to download EPSS data: {e}", file=sys.stderr)
        return {}


def lookup_epss(scores: dict[str, dict], cve_id: str) -> tuple[float | None, float | None]:
    entry = scores.get(cve_id)
    if entry is None:
        return None, None
    return entry["epss"], entry["percentile"]
