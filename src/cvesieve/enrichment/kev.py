"""
CISA KEV (Known Exploited Vulnerabilities) catalogue lookup.

Downloads the full catalogue once per day and caches it locally.
Lookup is a set membership check — O(1).
"""
import json
import sys
import time
from pathlib import Path

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_FILENAME = "kev.json"
MAX_AGE_SECONDS = 86400  # 24 hours


def _cache_path(cache_dir: Path) -> Path:
    return cache_dir / CACHE_FILENAME


def _load_cache(cache_dir: Path) -> set[str] | None:
    path = _cache_path(cache_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        age = time.time() - data.get("timestamp", 0)
        if age > MAX_AGE_SECONDS:
            return None
        return set(data["cve_ids"])
    except Exception:
        return None


def _save_cache(cache_dir: Path, cve_ids: set[str]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    payload = {"timestamp": time.time(), "cve_ids": list(cve_ids)}
    _cache_path(cache_dir).write_text(json.dumps(payload))


def _download_and_parse() -> set[str]:
    print("Downloading CISA KEV data...", file=sys.stderr)
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    data = response.json()
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def load_kev(cache_dir: Path, no_cache: bool = False) -> set[str]:
    if not no_cache:
        cached = _load_cache(cache_dir)
        if cached is not None:
            return cached

    try:
        cve_ids = _download_and_parse()
        _save_cache(cache_dir, cve_ids)
        return cve_ids
    except Exception as e:
        print(f"Warning: failed to download CISA KEV data: {e}", file=sys.stderr)
        return set()


def is_in_kev(kev_set: set[str], cve_id: str) -> bool:
    return cve_id in kev_set
