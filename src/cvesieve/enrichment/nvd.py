"""
NVD API lookup for CVSS vector strings and published dates.

Used when the scanner (e.g. Docker Scout) doesn't include the CVSS vector
or published date in its SARIF output. Fetches from the NVD CVE API and
caches indefinitely — CVSS vectors and published dates never change.

Rate limits:
  Without API key: 5 requests per 30 seconds → sleep 6s between requests
  With API key:   50 requests per 30 seconds → parallel batches of 10

Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key

Cache format: {cve_id: {"vector": str|None, "published": str|None}}
"""
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def _fetch_nvd_data(cve_id: str, api_key: str | None) -> tuple[str, NvdData | None]:
    """
    Fetch NVD data for a single CVE.
    Returns (cve_id, NvdData) on success (fields may be None if NVD has no data).
    Returns (cve_id, None) on network/HTTP failure — caller should not cache this.
    """
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    last_exc = None
    for attempt in range(3):
        try:
            response = requests.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                headers=headers,
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
            break
        except Exception as e:
            last_exc = e
            if attempt < 2:
                time.sleep(2)
    else:
        print(f"Warning: NVD lookup failed for {cve_id}: {last_exc}", file=sys.stderr)
        return (cve_id, None)  # do not cache transient failures

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return (cve_id, NvdData(vector=None, published=None))

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

    return (cve_id, NvdData(vector=vector, published=published))


def _fetch_batch_sequential(
    missing: list[str],
    cache: dict[str, NvdData],
    cache_dir: Path,
    api_key: str | None,
    delay: float,
) -> None:
    """Fetch CVEs one at a time with delay between requests."""
    for i, cve_id in enumerate(missing):
        if i > 0:
            time.sleep(delay)
        print(f"  [{i+1}/{len(missing)}] {cve_id}", file=sys.stderr)
        _, result = _fetch_nvd_data(cve_id, api_key)
        if result is not None:
            cache[cve_id] = result

        if (i + 1) % 25 == 0:
            _save_cache(cache_dir, cache)


def _fetch_batch_parallel(
    missing: list[str],
    cache: dict[str, NvdData],
    cache_dir: Path,
    api_key: str | None,
) -> None:
    """Fetch CVEs in parallel batches of 10, with a pause between batches to respect rate limits."""
    batch_size = 10
    # 50 req/30s = need ~6s per batch of 10 to stay safe
    batch_delay = 6.0
    total = len(missing)
    fetched = 0

    for batch_start in range(0, total, batch_size):
        batch = missing[batch_start:batch_start + batch_size]

        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            futures = {
                executor.submit(_fetch_nvd_data, cve_id, api_key): cve_id
                for cve_id in batch
            }
            for future in as_completed(futures):
                cve_id, result = future.result()
                fetched += 1
                print(f"  [{fetched}/{total}] {cve_id}", file=sys.stderr)
                if result is not None:
                    cache[cve_id] = result

        # Save after each batch
        _save_cache(cache_dir, cache)

        # Rate limit pause between batches (skip after last batch)
        if batch_start + batch_size < total:
            time.sleep(batch_delay)


def fetch_missing_data(
    cve_ids: list[str],
    cache_dir: Path,
    api_key: str | None = None,
    no_cache: bool = False,
) -> dict[str, NvdData]:
    """
    For each CVE ID, return NvdData (vector + published date).
    Fetches from NVD only for IDs not already cached.
    If no_cache=True, also re-fetches entries with missing published dates
    (NVD may have processed them since last lookup).
    """
    cache = _load_cache(cache_dir)

    if no_cache:
        # Re-fetch anything with incomplete data (missing published date)
        missing = [
            cve_id for cve_id in cve_ids
            if cve_id not in cache or cache[cve_id].published is None
        ]
    else:
        missing = [cve_id for cve_id in cve_ids if cve_id not in cache]

    if not missing:
        return {cve_id: cache.get(cve_id, NvdData(None, None)) for cve_id in cve_ids}

    if api_key:
        # Parallel: 10 concurrent requests, ~6s between batches = ~50 req/30s
        batches = (len(missing) + 9) // 10
        eta = batches * 6
        print(f"Fetching {len(missing)} CVE(s) from NVD (parallel, 10 at a time, ETA ~{eta:.0f}s)...", file=sys.stderr)
        _fetch_batch_parallel(missing, cache, cache_dir, api_key)
    else:
        delay = 6.0
        if len(missing) > 5:
            print(
                f"Warning: looking up {len(missing)} CVEs from NVD without an API key "
                f"— this will take ~{len(missing) * delay:.0f}s. "
                f"Set --nvd-api-key or NVD_API_KEY env var to speed this up.",
                file=sys.stderr,
            )
        eta = len(missing) * delay
        print(f"Fetching {len(missing)} CVE(s) from NVD (sequential, 5 req/30s, ETA ~{eta:.0f}s)...", file=sys.stderr)
        _fetch_batch_sequential(missing, cache, cache_dir, api_key, delay)

    _save_cache(cache_dir, cache)

    return {cve_id: cache.get(cve_id, NvdData(None, None)) for cve_id in cve_ids}
