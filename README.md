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
| No | Local / Physical | ≥ 5% | any | **WARN** |
| No | Local / Physical | < 5% | No | **WARN** |
| No | Local / Physical | < 5% | Yes | **SUPPRESS** |
| No | Local / Physical | Unknown | any | **WARN** |

> Network and local vectors use separate EPSS thresholds (0.1% and 5% by default). All thresholds are configurable — see [Tuning for your risk profile](#tuning-for-your-risk-profile).

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
| Raise the EPSS bar for everything | `--epss-threshold 0.01` | Sets a 1% base threshold for both network and local vectors |
| Raise the bar for network only | `--network-epss-threshold 0.01` | Only affects network/adjacent CVEs |
| Relax local CVE sensitivity | `--local-epss-threshold 0.10` | Local CVEs need >10% EPSS to WARN instead of suppressing |
| Skip age gate on very-low-EPSS CVEs | `--age-gate-floor 0.001` | CVEs below this EPSS bypass the 14-day window (see below) |
| Shorten the new-CVE window | `--age-threshold 7` | CVEs older than 7 days can be downgraded (vs 14) |
| Extend the new-CVE window | `--age-threshold 30` | Hold new CVEs at BLOCK for longer |
| Speed up large scans | `--min-nvd-severity high` | Skip NVD lookups for LOW/MEDIUM CVEs |
| Service isn't internet-facing | `--exposure internal` | Network BLOCKs capped at WARN (KEV still overrides) |
| Container runs rootless | `--privilege rootless` | Scope:Changed BLOCKs capped at WARN (KEV still overrides) |

### Separate EPSS thresholds for network vs local

Network-accessible and local CVEs have fundamentally different risk profiles. cvesieve uses separate thresholds for each:

- **`--network-epss-threshold`** (default: 0.001 = 0.1%) — controls when a network CVE is BLOCK vs WARN. Deliberately strict: a 1-in-1,000 exploitation probability is enough to fail the pipeline.
- **`--local-epss-threshold`** (default: 0.05 = 5%) — controls when a local CVE is WARN vs SUPPRESS. Much more relaxed: local CVEs require physical or authenticated access, so only those with a working exploit (high EPSS) warrant attention.

Use `--epss-threshold` to set a single value for both vectors at once, then override per-vector if needed:

```bash
# Set both to 1%
cvesieve --epss-threshold 0.01 scan.sarif.json

# Set base to 1%, but relax local to 10%
cvesieve --epss-threshold 0.01 --local-epss-threshold 0.10 scan.sarif.json
```

### Choosing an EPSS threshold

| EPSS | What it usually means |
|------|----------------------|
| < 0.1% | Theoretical CVE — nobody is actively exploiting it |
| 0.1–1% | Low activity — worth watching but rarely urgent |
| 1–10% | Elevated — PoC likely exists or exploitation is starting |
| > 10% | Active exploitation underway — patch immediately |

The real noise reduction in cvesieve comes from **attack vector and age**, not EPSS thresholds alone — most CVEs are suppressed because they're LOCAL vector and old. Raising the network threshold to 1% reduces additional noise without meaningfully increasing risk for most environments.

### The age-gate floor

By default, network CVEs younger than 14 days are held at BLOCK regardless of EPSS — this gives time for exploitation data to mature. But if you run cvesieve daily, the EPSS score is already refreshed every run, so the stabilisation window is effectively 24 hours, not 14 days.

`--age-gate-floor` lets you skip the age gate for CVEs whose EPSS is already so low they're almost certainly safe:

```bash
cvesieve --age-gate-floor 0.001 scan.sarif.json
```

With this set:
- A **network CVE** with EPSS < 0.1% and 3 days old → **WARN** immediately (instead of BLOCK for 14 days)
- A **local CVE** with EPSS < 0.1% and 3 days old → **SUPPRESS** immediately (instead of WARN for 14 days)

The floor only fires after the threshold check — high-EPSS CVEs still BLOCK regardless. And KEV always wins.

The reason string will say `(below age-gate floor)` so it's clear why the age gate was skipped.

### Deployment context

The same CVE isn't equally dangerous everywhere. `--exposure` and `--privilege` let you tell cvesieve about your deployment environment so it can apply appropriate context.

**`--exposure [public|internal]`**

If your service is not internet-facing, network-accessible CVEs are categorically less urgent — an attacker can't reach them from the outside. With `--exposure internal`, non-KEV NETWORK/ADJACENT BLOCKs are capped at WARN.

```bash
cvesieve --exposure internal scan.sarif.json
```

**`--privilege [root|rootless]`**

Container escape CVEs (CVSS Scope:Changed) are materially less dangerous in a rootless container — escaping only lands you as an unprivileged user on the host, not root. With `--privilege rootless`, non-KEV Scope:Changed BLOCKs are capped at WARN.

```bash
cvesieve --privilege rootless scan.sarif.json
```

Both flags can be combined:

```bash
cvesieve --exposure internal --privilege rootless scan.sarif.json
```

**KEV always wins** regardless of context — confirmed active exploitation is always BLOCK.

The reason string shows when a context modifier fired, e.g. `[capped at WARN — service is internal-only]`, so the audit trail is clear.

---

**Conservative (high-security environment):**
```bash
cvesieve --network-epss-threshold 0.0001 --age-threshold 30 scan.sarif.json
```

**Balanced (recommended starting point):**
```bash
cvesieve --min-block-severity high scan.sarif.json
```

**Daily CI with relaxed local sensitivity:**
```bash
cvesieve --epss-threshold 0.01 --age-gate-floor 0.001 scan.sarif.json
```

**Hardened internal service (rootless container, not internet-facing):**
```bash
cvesieve --exposure internal --privilege rootless scan.sarif.json
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
- **14-day stabilisation.** CVEs younger than 14 days are never downgraded — EPSS needs time to calibrate. Override with `--age-gate-floor` if you run daily and trust fresh EPSS scores.

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

  --epss-threshold FLOAT                         Set EPSS threshold for ALL vectors (default: uses
                                                 per-vector defaults). Overridden by --network-epss-threshold
                                                 or --local-epss-threshold.
  --network-epss-threshold FLOAT                 EPSS threshold for NETWORK/ADJACENT vectors (default: 0.001)
                                                 CVEs at or above this threshold are BLOCK.
  --local-epss-threshold FLOAT                   EPSS threshold for LOCAL/PHYSICAL vectors (default: 0.05)
                                                 CVEs at or above this threshold are WARN (not SUPPRESS).
  --age-threshold INT                            Minimum days since publication for downgrade (default: 14)
  --age-gate-floor FLOAT                         Skip the 14-day age gate for CVEs with EPSS below this value.
                                                 Network CVEs go straight to WARN; local CVEs go straight to
                                                 SUPPRESS. Useful when running cvesieve daily — EPSS already
                                                 refreshes every 24h so the gate is largely redundant for
                                                 very-low-EPSS findings. Disabled by default.

  --exposure [public|internal]                   Deployment exposure context (default: none / not set)
                                                 'internal': caps non-KEV NETWORK/ADJACENT BLOCKs at WARN.
                                                 Reason string updated to show why.
  --privilege [root|rootless]                    Container privilege context (default: none / not set)
                                                 'rootless': caps non-KEV Scope:Changed BLOCKs at WARN.
                                                 Scope:Changed CVEs can escape the container; rootless limits
                                                 the blast radius to an unprivileged host user.
                                                 Unknown scope (CVSS v2 or missing) is not downgraded.

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

# Raise EPSS threshold to 1% for both network and local
cvesieve --epss-threshold 0.01 scan.sarif.json

# Fine-grained: strict network threshold, relaxed local threshold
cvesieve --network-epss-threshold 0.001 --local-epss-threshold 0.10 scan.sarif.json

# Daily CI: skip age gate for very-low-EPSS CVEs (EPSS refreshes every 24h anyway)
cvesieve --age-gate-floor 0.001 scan.sarif.json

# Strict mode — tighter EPSS, longer stabilisation window
cvesieve --network-epss-threshold 0.0001 --age-threshold 30 scan.sarif.json

# Internal service — network BLOCKs capped at WARN
cvesieve --exposure internal scan.sarif.json

# Rootless container — Scope:Changed BLOCKs capped at WARN
cvesieve --privilege rootless scan.sarif.json

# Hardened internal service — both context modifiers together
cvesieve --exposure internal --privilege rootless scan.sarif.json

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
