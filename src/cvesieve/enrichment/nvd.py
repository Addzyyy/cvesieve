"""
NVD API lookup for CVSS vector strings.

Used when the scanner (e.g. Docker Scout) doesn't include the CVSS vector
in its SARIF output. Fetches from the NVD CVE API and caches indefinitely —
CVSS vectors almost never change once a CVE is published.

Rate limits:
  Without API key: 5 requests per 30 seconds → sleep 6s between requests
  With API key:   50 requests per 30 seconds → sleep 0.6s between requests

Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key
"""
import json
import sys
import time
from pathlib import Path

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILENAME = "nvd_cvss.json"


def _cache_path(cache_dir: Path) -> Path:
    return cache_dir / CACHE_FILENAME


def _load_cache(cache_dir: Path) -> dict[str, str | None]:
    path = _cache_path(cache_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _save_cache(cache_dir: Path, cache: dict[str, str | None]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    _cache_path(cache_dir).write_text(json.dumps(cache))


def _fetch_cvss_vector(cve_id: str, api_key: str | None) -> str | None:
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
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    metrics = vulns[0].get("cve", {}).get("metrics", {})

    # Prefer v3.1, then v3.0, then v2
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            vector = entries[0].get("cvssData", {}).get("vectorString")
            if vector:
                return vector

    return None


def fetch_missing_vectors(
    cve_ids: list[str],
    cache_dir: Path,
    api_key: str | None = None,
) -> dict[str, str | None]:
    """
    For each CVE ID, return its CVSS vector string.
    Fetches from NVD only for IDs not already cached.
    Returns a dict: {cve_id: vector_string_or_None}
    """
    cache = _load_cache(cache_dir)

    missing = [cve_id for cve_id in cve_ids if cve_id not in cache]

    if not missing:
        return {cve_id: cache.get(cve_id) for cve_id in cve_ids}

    delay = 0.6 if api_key else 6.0

    if not api_key and len(missing) > 5:
        print(
            f"Warning: looking up {len(missing)} CVE vectors from NVD without an API key "
            f"— this will take ~{len(missing) * delay:.0f}s. "
            f"Set --nvd-api-key or NVD_API_KEY env var to speed this up.",
            file=sys.stderr,
        )

    print(f"Fetching {len(missing)} CVSS vector(s) from NVD...", file=sys.stderr)

    for i, cve_id in enumerate(missing):
        if i > 0:
            time.sleep(delay)
        vector = _fetch_cvss_vector(cve_id, api_key)
        cache[cve_id] = vector  # cache None too — avoids re-fetching unknown CVEs

    _save_cache(cache_dir, cache)

    return {cve_id: cache.get(cve_id) for cve_id in cve_ids}
