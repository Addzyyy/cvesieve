# cvesieve
**Problem Statement & Design Overview**
*Version 0.3 | February 2026*

---

## Problem

Container image scanners (Docker Scout, Trivy, Grype) flag every CVE matching a package version — regardless of whether it's exploitable in context. A local-privilege-escalation CVE is given the same weight as a remotely exploitable one, even when every container runs in Kubernetes where local access is near-impossible. Research shows only 2–7% of published CVEs are ever exploited in the wild, yet scanners provide no signal to distinguish those from the rest.

The result: alert fatigue, blocked pipelines, and engineers who stop trusting scanner output entirely — meaning genuinely critical vulnerabilities get the same shrug as the noise.

---

## Solution

**cvesieve** is a lightweight CLI that sits between the scanner and the CI pipeline. It takes standard SARIF output, enriches each CVE with exploitability signals, and classifies every finding into one of three tiers: **BLOCK**, **WARN**, or **SUPPRESS**.

Nothing is hidden. Nothing is deleted. The scanner still runs. cvesieve just makes the output usable.

```bash
docker scout cves --format sarif myimage:latest | cvesieve
```

---

## Signals

| Signal | Source | Purpose |
|--------|--------|---------|
| **EPSS Score** | FIRST (free public data, cached locally 24h) | Probability the CVE will be exploited in the next 30 days. Below 0.1% = extremely unlikely to ever be exploited. |
| **Attack Vector** | CVSS string from scan output or NVD API | Local = attacker needs existing access. Network = remotely exploitable. |
| **Published Date** | NVD API (cached indefinitely) | Used to enforce the 14-day stabilisation window on new CVEs. |
| **CISA KEV** | CISA catalogue (free, cached locally 24h) | CVEs with confirmed active exploitation in the wild. Hard override — always BLOCK. |

---

## Classification

| KEV? | Attack Vector | EPSS | Age > 14 days? | → Tier |
|------|--------------|------|----------------|--------|
| Yes | *any* | *any* | *any* | **BLOCK** |
| No | Network / Adjacent / Unknown | ≥ 0.1% | *any* | **BLOCK** |
| No | Network / Adjacent / Unknown | < 0.1% | No | **BLOCK** |
| No | Network / Adjacent / Unknown | < 0.1% | Yes | **WARN** |
| No | Network / Adjacent / Unknown | Unknown | *any* | **BLOCK** |
| No | Local / Physical | ≥ 0.1% | *any* | **WARN** |
| No | Local / Physical | < 0.1% | No | **WARN** |
| No | Local / Physical | < 0.1% | Yes | **SUPPRESS** |
| No | Local / Physical | Unknown | *any* | **WARN** |

**BLOCK** → pipeline fails, must fix.
**WARN** → pipeline passes, surfaces in report — fix when convenient.
**SUPPRESS** → visible in full report only — near-zero risk.

---

## Safety Guarantees

- **KEV hard override.** Any CVE with confirmed active exploitation is always BLOCK, regardless of all other signals.
- **Fail open.** Missing EPSS data, unparseable CVSS vector, or unknown age → the CVE is pushed toward the higher tier, never suppressed.
- **Fail-open is asymmetric.** Missing data on a network CVE → BLOCK. Missing data on a local CVE → WARN. The blast radius is different.
- **Full audit trail.** Every classification includes a plain-English reason. Every suppressed CVE is visible in the report.
- **14-day stabilisation.** CVEs younger than 14 days are never downgraded — EPSS needs time to calibrate.

---

## NVD Lookup

Docker Scout does not include CVSS vectors or published dates in its SARIF output. cvesieve fetches both from the NVD API and caches them locally.

- **CVSS vectors and published dates never change** — cached indefinitely.
- **Rate limits:** 5 req/30s without API key, 50 req/30s with key.
- **Retry logic:** up to 3 attempts with 2s delay on network failure.
- **Transient failures are not cached** — the CVE will be retried on next run.
- **Stale cache entries** (previously fetched with no published date) are refreshed when `--no-cache` is passed.

---

## Configuration

All thresholds are configurable via CLI flags. Defaults are chosen conservatively (fail open).

| Flag | Default | Description |
|------|---------|-------------|
| `--epss-threshold` | `0.001` (0.1%) | EPSS score below which a CVE is considered low-probability. Raise to reduce noise, lower to be more conservative. |
| `--age-threshold` | `14` (days) | Minimum age before a low-EPSS CVE can be downgraded. Younger CVEs are not trusted to have stable EPSS scores. |
| `--min-severity` | `low` | Ignore findings below this severity. **BLOCK findings are always shown regardless — KEV always wins.** |
| `--min-block-severity` | `low` | Cap findings below this severity at WARN. CVEs below the threshold can never be BLOCK unless in KEV. |
| `--min-nvd-severity` | `low` | Skip NVD lookups for CVEs below this severity. Reduces API requests on noisy images. Skipped CVEs are classified fail-open. |
| `--no-cache` | off | Force re-download of EPSS and KEV data. Also re-fetches NVD entries previously cached with no published date. |

### Recommended configurations

```bash
# Standard — good balance of signal and noise reduction
cvesieve --min-block-severity high scan.sarif.json

# Fast scan on a noisy image (skip NVD for LOW/MEDIUM)
cvesieve --min-nvd-severity high --min-block-severity high scan.sarif.json

# Strict — conservative thresholds for sensitive environments
cvesieve --epss-threshold 0.0001 --age-threshold 30 scan.sarif.json
```

---

## Example Output

```
cvesieve v0.1.0
Scanner: docker scout | Total CVEs: 47

══ BLOCK (8) — pipeline will fail ════════════════════════
  CVE-2024-1234   CRITICAL  openssl 1.1.1k  34.2%  Network  In CISA KEV
  CVE-2024-5678   HIGH      curl 7.88.1      5.1%  Network  EPSS above threshold

══ WARN (15) — fix when convenient ═══════════════════════
  CVE-2024-3456   HIGH      zlib 1.2.11     0.08%  Network  Low EPSS, 45d old
  CVE-2024-7777   MEDIUM    sudo 1.9.5       0.4%  Local    EPSS above threshold

══ SUPPRESS (24) — near-zero risk ════════════════════════
  CVE-2024-9999   HIGH      glibc 2.31-13   0.02%  Local    EPSS 0.02%, 67d old

Summary: 47 total → 8 block, 15 warn, 24 suppress (83% noise reduction)
```

---

## Scope

**This version does:**
- Accept SARIF from Docker Scout, Trivy, and Grype
- Enrich with EPSS, attack vector, published date, and CISA KEV
- Fetch missing CVSS vectors and published dates from NVD API (with caching and retry)
- Classify into BLOCK / WARN / SUPPRESS with plain-English reasons
- Filter by minimum severity (`--min-severity`) — BLOCK findings always shown
- Cap findings by severity (`--min-block-severity`) — KEV always overrides
- Skip NVD lookups for low-severity CVEs (`--min-nvd-severity`) to reduce API requests
- Output as table, JSON, or one-line summary
- Work as a CI pipeline gate (exit 1 on BLOCK findings)

**This version does not:**
- Perform code reachability or runtime analysis
- Replace security review for BLOCK-tier findings
- Require changes to existing scanners or CI infrastructure

**Future iterations may add:** weighted scoring across additional signals, AI-assisted reachability analysis, GitHub Action / PR comment integration.
