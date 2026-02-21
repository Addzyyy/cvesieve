# cvesieve

> Filter CVE scanner noise using real-world exploitability signals.

Container image scanners flag every CVE matching a package version — regardless of whether it's exploitable in context. Research shows only 2–7% of published CVEs are ever exploited in the wild, yet scanners give them all equal weight. The result is alert fatigue, blocked pipelines, and engineers who stop trusting scanner output entirely.

**cvesieve** sits between your scanner and your CI pipeline. It takes standard SARIF output, enriches each CVE with exploitability signals, and classifies every finding into one of three tiers: **BLOCK**, **WARN**, or **SUPPRESS** — so you only fail the pipeline on things that actually matter.

---

## How it works

cvesieve enriches each CVE with:

- **EPSS score** — probability the CVE will be exploited in the next 30 days (FIRST, free, cached locally)
- **Attack vector** — local vs. network-accessible, from CVSS string or NVD lookup
- **Published date** — used to enforce a 14-day stabilisation window on new CVEs
- **CISA KEV** — confirmed active exploitation in the wild (hard override: always BLOCK)

Then classifies using this decision table:

| KEV? | Attack Vector | EPSS | Age > 14 days? | Tier |
|------|--------------|------|----------------|------|
| Yes | any | any | any | **BLOCK** |
| No | Network / Adjacent / Unknown | ≥ 0.1% | any | **BLOCK** |
| No | Network / Adjacent / Unknown | < 0.1% | No | **BLOCK** |
| No | Network / Adjacent / Unknown | < 0.1% | Yes | **WARN** |
| No | Network / Adjacent / Unknown | Unknown | any | **BLOCK** |
| No | Local / Physical | ≥ 0.1% | any | **WARN** |
| No | Local / Physical | < 0.1% | No | **WARN** |
| No | Local / Physical | < 0.1% | Yes | **SUPPRESS** |
| No | Local / Physical | Unknown | any | **WARN** |

| Tier | CI behaviour | Action |
|------|-------------|--------|
| **BLOCK** | Exit 1 — pipeline fails | Must fix before deployment |
| **WARN** | Exit 0 — pipeline passes | Fix when convenient |
| **SUPPRESS** | Exit 0 — full report only | Near-zero risk, no action needed |

---

## Tuning for your risk profile

Every organisation has a different risk tolerance. cvesieve's defaults are conservative (fail open), but all key thresholds are configurable so you can dial the sensitivity to match your environment.

| What you want | Flag | Effect |
|---------------|------|--------|
| Only care about HIGH/CRITICAL | `--min-severity high` | LOW and MEDIUM findings removed from output entirely |
| Stop LOW/MEDIUM from blocking CI | `--min-block-severity high` | LOW/MEDIUM can never be BLOCK unless in KEV |
| Raise the EPSS bar | `--epss-threshold 0.01` | Only flag CVEs with >1% exploitation probability |
| Shorten the new-CVE window | `--age-threshold 7` | CVEs older than 7 days can be downgraded (vs 14) |
| Extend the new-CVE window | `--age-threshold 30` | Hold new CVEs at BLOCK for longer |
| Speed up large scans | `--min-nvd-severity high` | Skip NVD lookups for LOW/MEDIUM CVEs |

**Conservative (high-security environment):**
```bash
cvesieve --epss-threshold 0.0001 --age-threshold 30 scan.sarif.json
```

**Balanced (recommended starting point):**
```bash
cvesieve --min-block-severity high scan.sarif.json
```

**Aggressive noise reduction (large/legacy images):**
```bash
cvesieve --min-severity high --min-block-severity high --min-nvd-severity high scan.sarif.json
```

Regardless of thresholds, **KEV always wins** — any CVE with confirmed active exploitation is always BLOCK.

---

## Safety guarantees

- **KEV always wins.** Any CVE with confirmed active exploitation is BLOCK, no exceptions.
- **Fail open.** Missing EPSS, unparseable CVSS vector, or unknown age → pushed toward the higher tier, never suppressed.
- **Nothing is hidden.** SUPPRESS findings are visible in the full report.
- **14-day stabilisation.** CVEs younger than 14 days are never downgraded — EPSS needs time to calibrate.

---

## Installation

```bash
pip install .
```

Or in development mode:

```bash
pip install -e ".[dev]"
```

---

## Usage

```bash
# Docker Scout
docker scout cves --format sarif myimage:latest | cvesieve

# Trivy
trivy image --format sarif myimage:latest | cvesieve

# Grype
grype myimage:latest -o sarif | cvesieve

# From file
cvesieve scan.sarif.json

# JSON output (for CI integration)
cvesieve --format json scan.sarif.json

# One-line summary
cvesieve --format summary scan.sarif.json

# Only show what's blocking the pipeline
cvesieve --tier block scan.sarif.json

# Force cache refresh (EPSS, KEV, and stale NVD entries)
cvesieve --no-cache scan.sarif.json
```

### Example output

```
cvesieve v0.1.0
Scanner: docker scout | Total CVEs: 47

══ BLOCK (8) — pipeline will fail ════════════════════════════════════
  CVE ID               SEVERITY   PACKAGE              EPSS     VECTOR   REASON
  CVE-2024-1234        CRITICAL   openssl 1.1.1k       34.20%   Network  In CISA KEV — confirmed active exploitation in the wild
  CVE-2024-5678        HIGH       curl 7.88.1           5.10%   Network  Network-accessible, EPSS 5.10% (≥ threshold)

══ WARN (15) — fix when convenient ═══════════════════════════════════
  CVE-2024-3456        HIGH       zlib 1.2.11           0.08%   Network  Network-accessible, EPSS 0.08%, 45d old — low risk, fix when convenient

══ SUPPRESS (24) — near-zero risk ════════════════════════════════════
  CVE-2024-9999        HIGH       glibc 2.31            0.02%   Local    Local vector, EPSS 0.02%, not in KEV, 67d old — near-zero risk

Summary: 47 total → 8 block, 15 warn, 24 suppress (83.0% noise reduction)
```

---

## Options

```
Options:
  -f, --format [table|json|summary]              Output format (default: table)
  -o, --output FILE                              Write output to file
  --epss-threshold FLOAT                         EPSS score threshold 0.0-1.0 (default: 0.001)
                                                 Findings below this are considered low-probability.
                                                 Raise to reduce noise, lower to be more conservative.
  --age-threshold INT                            Minimum days since publication for downgrade (default: 14)
  --min-severity [low|medium|high|critical]      Ignore findings below this severity (default: low)
                                                 BLOCK findings are always shown — KEV always wins.
  --min-block-severity [low|medium|high|critical]
                                                 Cap findings below this severity at WARN (default: low)
                                                 CVEs below the threshold can never be BLOCK unless in KEV.
                                                 Useful for suppressing pipeline failures on low/medium CVEs
                                                 that are technically network-accessible but low real-world risk.
  --cache-dir PATH                               Cache directory (default: ~/.cvesieve/cache)
  --no-cache                                     Force re-download of EPSS, KEV, and stale NVD entries
  --tier [block|warn|suppress|all]               Filter output to specific tier (default: all)
  --nvd-api-key TEXT                             NVD API key for CVSS vector and published date lookup.
                                                 Also reads NVD_API_KEY env var.
                                                 Get one free at https://nvd.nist.gov/developers/request-an-api-key
                                                 Without a key: 5 req/30s (slow for large scans).
                                                 With a key: 50 req/30s.
  --min-nvd-severity [low|medium|high|critical]  Skip NVD lookups for CVEs below this severity (default: low)
                                                 Reduces API requests on noisy images. Skipped CVEs are
                                                 classified fail-open (unknown vector/age).
  --version                                      Show version
  --help                                         Show this message
```

---

## Docker Scout and NVD lookups

Docker Scout's SARIF output does not include CVSS vector strings or published dates, so cvesieve fetches both from the NVD API and caches them locally. CVSS vectors and published dates never change, so the cache persists indefinitely — subsequent runs on the same CVEs are instant.

Provide an API key for fast lookups (strongly recommended for large images):

```bash
# Set once, use everywhere
export NVD_API_KEY=your-key-here

# Or pass per run
cvesieve --nvd-api-key your-key-here scan.sarif.json
```

Get a free key at https://nvd.nist.gov/developers/request-an-api-key

**Rate limits:**
- Without API key: 5 requests / 30s → ~6s per CVE
- With API key: 50 requests / 30s → ~0.6s per CVE

For images with hundreds of CVEs, use `--min-nvd-severity high` to skip NVD lookups for LOW and MEDIUM findings:

```bash
cvesieve --min-nvd-severity high scan.sarif.json
```

---

## Common configurations

```bash
# Only care about HIGH and CRITICAL findings
cvesieve --min-severity high scan.sarif.json

# Prevent LOW/MEDIUM CVEs from blocking the pipeline (KEV still overrides)
cvesieve --min-block-severity high scan.sarif.json

# Both together — recommended for noisy base images
cvesieve --min-severity high --min-block-severity high scan.sarif.json

# Speed up NVD lookups on large scans — skip LOW/MEDIUM entirely
cvesieve --min-nvd-severity high --min-block-severity high scan.sarif.json

# More aggressive noise reduction — raise EPSS threshold to 1%
cvesieve --epss-threshold 0.01 scan.sarif.json

# Strict mode — lower EPSS threshold, flag newer CVEs for longer
cvesieve --epss-threshold 0.0001 --age-threshold 30 scan.sarif.json

# Refresh stale NVD cache entries (e.g. CVEs previously cached with no published date)
cvesieve --no-cache scan.sarif.json
```

---

## Running tests

```bash
pytest tests/ -v
```

---

## Licence

MIT
