# cvesieve

> Filter CVE scanner noise using real-world exploitability signals.

Container image scanners flag every CVE matching a package version — regardless of whether it's exploitable in context. Research shows only 2–7% of published CVEs are ever exploited in the wild, yet scanners give them all equal weight. The result is alert fatigue, blocked pipelines, and engineers who stop trusting scanner output entirely.

**cvesieve** sits between your scanner and your CI pipeline. It takes standard SARIF output, enriches each CVE with two exploitability signals, and classifies every finding into one of three tiers: **BLOCK**, **WARN**, or **SUPPRESS** — so you only fail the pipeline on things that actually matter.

---

## How it works

cvesieve enriches each CVE with:

- **EPSS score** — probability the CVE will be exploited in the next 30 days (FIRST, free, cached locally)
- **Attack vector** — local vs. network-accessible, extracted from the CVSS string already in your scan output
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

# Force cache refresh
cvesieve --no-cache scan.sarif.json
```

### Example output

```
cvesieve v0.1.0
Scanner: docker scout | Total CVEs: 47

══ BLOCK (8) — pipeline will fail ════════════════════════════════════
  CVE ID               SEVERITY   PACKAGE              EPSS     VECTOR   REASON
  CVE-2024-1234        CRITICAL   openssl 1.1.1k       34.20%   Network  In CISA KEV — confirmed active exploitation in the wild
  CVE-2024-5678        HIGH       curl 7.88.1          5.10%    Network  Network-accessible, EPSS 5.10% (≥ threshold)

══ WARN (15) — fix when convenient ═══════════════════════════════════
  CVE-2024-3456        HIGH       zlib 1.2.11          0.08%    Network  Network-accessible, EPSS 0.08%, 45d old — low risk, fix when convenient

══ SUPPRESS (24) — near-zero risk ════════════════════════════════════
  CVE-2024-9999        HIGH       glibc 2.31            0.02%   Local    Local vector, EPSS 0.02%, not in KEV, 67d old — near-zero risk

Summary: 47 total → 8 block, 15 warn, 24 suppress (83.0% noise reduction)
```

---

## Options

```
Options:
  -f, --format [table|json|summary]   Output format (default: table)
  -o, --output FILE                   Write output to file
  --epss-threshold FLOAT              EPSS threshold (default: 0.001)
  --age-threshold INT                 Minimum days since publication for downgrade (default: 14)
  --cache-dir PATH                    Cache directory (default: ~/.cvesieve/cache)
  --no-cache                          Force re-download of EPSS and KEV data
  --tier [block|warn|suppress|all]    Filter output to specific tier (default: all)
  --version                           Show version
  --help                              Show this message
```

---

## Running tests

```bash
pytest tests/ -v
```

---

## Licence

MIT
