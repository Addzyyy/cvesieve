"""
NVD API lookup for CVSS vector strings and published dates.

Used when the scanner (e.g. Docker Scout) doesn't include the CVSS vector
or published date in its SARIF output. Fetches from the NVD CVE API and
caches indefinitely — CVSS vectors and published dates never change.

Rate limits:
  Without API key: 5 requests per 30 seconds → sleep 6s between requests
  With API key:   50 requests per 30 seconds → sleep 0.6s between requests

Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key

Cache format: {cve_id: {"vector": str|None, "published": str|None}}
"""
import json
import sys
import time
from pathlib import Path
from dataclasses import dataclass

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILENAME = "nvd_cvss.json"


@dataclass
class NvdData:
    vector: str | None
    published: str | None  # ISO date string e.g. "2024-01-15T10:15:00.000"


def _cache_path(cache_dir: Path) -> Path:
    return cache_dir / CACHE_FILENAME


def _load_cache(cache_dir: Path) -> dict[str, NvdData]:
    path = _cache_path(cache_dir)
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text())
        result = {}
        for cve_id, value in raw.items():
            # Handle old cache format (just a string vector)
            if isinstance(value, str) or value is None:
                result[cve_id] = NvdData(vector=value, published=None)
            else:
                result[cve_id] = NvdData(
                    vector=value.get("vector"),
                    published=value.get("published"),
                )
        return result
    except Exception:
        return {}


def _save_cache(cache_dir: Path, cache: dict[str, NvdData]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    serialisable = {
        cve_id: {"vector": d.vector, "published": d.published}
        for cve_id, d in cache.items()
    }
    _cache_path(cache_dir).write_text(json.dumps(serialisable))


def _fetch_nvd_data(cve_id: str, api_key: str | None) -> NvdData:
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Warning: NVD lookup failed for {cve_id}: {e}", file=sys.stderr)
        return NvdData(vector=None, published=None)

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return NvdData(vector=None, published=None)

    cve_data = vulns[0].get("cve", {})
    metrics = cve_data.get("metrics", {})
    published = cve_data.get("published")  # e.g. "2024-01-15T10:15:00.000"

    # Prefer v3.1, then v3.0, then v2
    vector = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            v = entries[0].get("cvssData", {}).get("vectorString")
            if v:
                vector = v
                break

    return NvdData(vector=vector, published=published)


def fetch_missing_data(
    cve_ids: list[str],
    cache_dir: Path,
    api_key: str | None = None,
) -> dict[str, NvdData]:
    """
    For each CVE ID, return NvdData (vector + published date).
    Fetches from NVD only for IDs not already cached.
    """
    cache = _load_cache(cache_dir)

    missing = [cve_id for cve_id in cve_ids if cve_id not in cache]

    if not missing:
        return {cve_id: cache.get(cve_id, NvdData(None, None)) for cve_id in cve_ids}

    delay = 0.6 if api_key else 6.0

    if not api_key and len(missing) > 5:
        print(
            f"Warning: looking up {len(missing)} CVEs from NVD without an API key "
            f"— this will take ~{len(missing) * delay:.0f}s. "
            f"Set --nvd-api-key or NVD_API_KEY env var to speed this up.",
            file=sys.stderr,
        )

    print(f"Fetching {len(missing)} CVE(s) from NVD (vector + published date)...", file=sys.stderr)

    for i, cve_id in enumerate(missing):
        if i > 0:
            time.sleep(delay)
        cache[cve_id] = _fetch_nvd_data(cve_id, api_key)

    _save_cache(cache_dir, cache)

    return {cve_id: cache.get(cve_id, NvdData(None, None)) for cve_id in cve_ids}
