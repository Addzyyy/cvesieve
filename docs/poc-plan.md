# cvesieve — PoC Implementation Plan

## What You're Building

A CLI tool called `cvesieve` that takes SARIF output from any container image scanner (Docker Scout, Trivy, Grype), enriches each CVE with real-world exploitability signals, and classifies each into one of three tiers: **BLOCK**, **WARN**, or **SUPPRESS**. The goal is to stop deployments only for CVEs that pose genuine risk, nag engineers about lower-priority issues without blocking them, and quietly deprioritise noise — while guaranteeing nothing actively exploited is ever missed.

**Language:** Python 3.11+  
**Package manager:** pip with pyproject.toml  
**Distribution:** Single installable CLI via `pip install .`  
**No external dependencies beyond:** `requests`, `click` (for CLI), and the Python standard library.

---

## Architecture

```
SARIF JSON (stdin or file)
        │
        ▼
┌─────────────┐
│   Ingest     │  ← Parse SARIF JSON, normalise to internal model
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Enrich     │  ← Look up EPSS scores (from local cache), extract attack vector from CVSS
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  KEV Check   │  ← Cross-reference against CISA KEV catalogue (local cache)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Classify   │  ← Assign tier: BLOCK, WARN, or SUPPRESS
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Output     │  ← Report split into three tiers with plain-English reasons
└─────────────┘
```

---

## Three-Tier Classification Model

Every CVE is classified into exactly one tier based on the following decision logic.

### Decision Table

| KEV? | Attack Vector | EPSS | Age > 14 days? | → Tier | CI Behaviour |
|------|--------------|------|----------------|--------|-------------|
| Yes | *any* | *any* | *any* | **BLOCK** | Fails pipeline |
| No | Network / Adjacent / Unknown | ≥ 0.1% | *any* | **BLOCK** | Fails pipeline |
| No | Network / Adjacent / Unknown | < 0.1% | No (≤ 14 days) | **BLOCK** | Fails pipeline — too new to trust low EPSS |
| No | Network / Adjacent / Unknown | < 0.1% | Yes (> 14 days) | **WARN** | Pipeline passes, PR comment |
| No | Network / Adjacent / Unknown | Unknown | *any* | **BLOCK** | Fail open — missing data blocks |
| No | Local | ≥ 0.1% | *any* | **WARN** | Pipeline passes, PR comment |
| No | Local | < 0.1% | No (≤ 14 days) | **WARN** | Pipeline passes, PR comment |
| No | Local | < 0.1% | Yes (> 14 days) | **SUPPRESS** | Full report only |
| No | Local | Unknown | *any* | **WARN** | Fail open — missing data warns |

### Decision Tree

```
                         ┌──────────┐
                         │  CVE In   │
                         │ CISA KEV? │
                         └─────┬─────┘
                               │
                          YES ─┤── NO ─────────────────────────┐
                               │                               │
                          ┌────▼────┐                  ┌───────▼────────┐
                          │  BLOCK  │                  │ Attack Vector?  │
                          └─────────┘                  └───────┬────────┘
                                                               │
                                          NETWORK / ADJACENT / UNKNOWN
                                                  │            │
                                                  │          LOCAL
                                                  │            │
                                           ┌──────▼──────┐  ┌─▼──────────┐
                                           │ EPSS known? │  │ EPSS known?│
                                           └──────┬──────┘  └──┬─────────┘
                                                  │             │
                                             NO ──┤        NO ──┤
                                                  │             │
                                           ┌──────▼──┐   ┌─────▼──┐
                                           │  BLOCK  │   │  WARN  │
                                           └─────────┘   └────────┘
                                                  │             │
                                             YES ─┘        YES ─┘
                                                  │             │
                                           ┌──────▼───────┐ ┌──▼───────────┐
                                           │ EPSS ≥ 0.1%? │ │ EPSS ≥ 0.1%? │
                                           └──────┬───────┘ └──┬───────────┘
                                                  │             │
                                             YES ─┤        YES ─┤
                                                  │             │
                                           ┌──────▼──┐   ┌─────▼──┐
                                           │  BLOCK  │   │  WARN  │
                                           └─────────┘   └────────┘
                                                  │             │
                                              NO ─┘         NO ─┘
                                                  │             │
                                           ┌──────▼───────┐ ┌──▼───────────┐
                                           │ Age > 14 d?  │ │ Age > 14 d?  │
                                           └──────┬───────┘ └──┬───────────┘
                                                  │             │
                                             NO ──┤        NO ──┤
                                                  │             │
                                           ┌──────▼──┐   ┌─────▼──┐
                                           │  BLOCK  │   │  WARN  │
                                           └─────────┘   └────────┘
                                                  │             │
                                             YES ─┘        YES ─┘
                                                  │             │
                                           ┌──────▼──┐   ┌─────▼─────┐
                                           │  WARN   │   │ SUPPRESS  │
                                           └─────────┘   └───────────┘
```

### Key Design Principles

- **KEV always wins.** Any CVE in the CISA KEV catalogue is BLOCK regardless of all other signals.
- **Attack vector sets the ceiling.** Network/adjacent CVEs can reach BLOCK. Local CVEs can only reach WARN at most.
- **EPSS + age determine placement within the ceiling.** Low EPSS and sufficient age lower the tier. Either missing → fail toward the higher tier.
- **Fail-open is asymmetric.** Missing EPSS on a network CVE → BLOCK. Missing EPSS on a local CVE → WARN. The blast radius of getting it wrong is different.
- **Nothing is hidden.** SUPPRESS findings are still visible in the full report. The three tiers determine CI behaviour and notification urgency, not visibility.

### Tier Definitions

| Tier | Meaning | CI Exit Code | Intended Action |
|------|---------|-------------|-----------------|
| **BLOCK** | Genuine risk — requires action before deployment | Exit 1 | Pipeline fails, must fix or explicitly accept risk |
| **WARN** | Low but non-zero risk — fix when convenient | Exit 0 | Pipeline passes, surfaces in PR comment / Slack notification |
| **SUPPRESS** | Near-zero risk — noise | Exit 0 | Visible in full report only, no notifications |

---

## SARIF as Universal Input

SARIF (Static Analysis Results Interchange Format) is an OASIS standard supported by all major scanners. By targeting SARIF instead of each scanner's native format, `cvesieve` supports multiple scanners with a single parser.

**Generating SARIF output from each scanner:**

```bash
# Docker Scout
docker scout cves --format sarif myimage:latest > scan.sarif.json

# Trivy
trivy image --format sarif myimage:latest > scan.sarif.json

# Grype
grype myimage:latest -o sarif > scan.sarif.json
```

**SARIF structure (what we care about):**

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "docker scout",
          "rules": [
            {
              "id": "CVE-2024-12345",
              "shortDescription": { "text": "..." },
              "helpUri": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
              "properties": {
                "cvssV3_severity": "HIGH",
                "tags": ["CVE-2024-12345", "vulnerability"]
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "CVE-2024-12345",
          "level": "error",
          "message": { "text": "..." },
          "locations": [
            {
              "logicalLocations": [
                {
                  "name": "openssl",
                  "kind": "module",
                  "fullyQualifiedName": "openssl@1.1.1k-1"
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

**Key extraction points from SARIF:**

| Field | SARIF Location |
|-------|----------------|
| CVE ID | `runs[].results[].ruleId` or `runs[].tool.driver.rules[].id` |
| Severity | `runs[].tool.driver.rules[].properties.cvssV3_severity` or map from `results[].level` |
| Package name | `runs[].results[].locations[].logicalLocations[].name` |
| Package version | `runs[].results[].locations[].logicalLocations[].fullyQualifiedName` (parse version after `@`) |
| CVSS vector | `runs[].tool.driver.rules[].properties.cvssV3_baseScore` or check `properties` for vector string |
| Scanner name | `runs[].tool.driver.name` |

**Important SARIF parser notes:**

- SARIF structure varies slightly between scanners — Docker Scout, Trivy, and Grype each put CVSS data and package info in slightly different places within `properties` and `locations`.
- The parser should check multiple known locations for each field and gracefully handle missing data.
- The CVSS vector string may not be in the SARIF at all for some scanners. If missing, the enrichment step should attempt to look it up from NVD data bundled with EPSS, or simply mark the attack vector as unknown (which means the CVE cannot be suppressed — fail open).
- Docker Scout uses `logicalLocations` with `fullyQualifiedName` for package identification. Trivy and Grype may use different structures. Normalise to `package_name` + `installed_version`.
- Deduplicate by CVE ID — the same CVE may appear in multiple results if it affects multiple packages.

---

## Project Structure

```
cvesieve/
├── pyproject.toml
├── README.md
├── LICENSE
├── src/
│   └── cvesieve/
│       ├── __init__.py
│       ├── cli.py              # Click CLI entrypoint
│       ├── models.py           # Dataclasses for normalised CVE data
│       ├── parser.py           # SARIF parser (single file — one format to parse)
│       ├── enrichment/
│       │   ├── __init__.py
│       │   ├── epss.py         # EPSS score lookup (bulk CSV cache)
│       │   ├── kev.py          # CISA KEV catalogue lookup (JSON cache)
│       │   └── cvss.py         # Extract attack vector from CVSS vector string
│       ├── engine.py           # Three-tier classification logic
│       └── output.py           # Format results (table, JSON, or summary)
├── tests/
│   ├── fixtures/               # Sample SARIF files from each scanner
│   │   ├── docker_scout.sarif.json
│   │   ├── trivy.sarif.json
│   │   └── grype.sarif.json
│   ├── test_parser.py
│   ├── test_enrichment.py
│   ├── test_engine.py
│   └── test_integration.py
└── cache/                      # Auto-created at runtime for EPSS/KEV data
```

---

## Step-by-Step Implementation

### Step 1: Data Models (`models.py`)

Define dataclasses representing the normalised internal format. Every CVE from any scanner gets normalised to this shape before enrichment.

```python
from enum import Enum

class Tier(Enum):
    BLOCK = "BLOCK"
    WARN = "WARN"
    SUPPRESS = "SUPPRESS"

@dataclass
class Finding:
    cve_id: str                     # e.g. "CVE-2024-12345"
    severity: str                   # CRITICAL/HIGH/MEDIUM/LOW
    package_name: str               # e.g. "openssl"
    installed_version: str          # e.g. "1.1.1k-1"
    fixed_version: str | None       # if available in SARIF
    cvss_vector: str | None         # e.g. "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    published_date: str | None      # ISO date string if available
    scanner: str                    # e.g. "docker scout", "trivy", "grype"
    description: str | None         # Short description from SARIF

@dataclass
class EnrichedFinding:
    finding: Finding
    epss_score: float | None        # 0.0 to 1.0
    epss_percentile: float | None   # 0.0 to 1.0
    attack_vector: str | None       # "NETWORK", "ADJACENT", "LOCAL", "PHYSICAL"
    in_kev: bool                    # True if CVE is in CISA KEV
    days_since_published: int | None

@dataclass
class ClassifiedFinding:
    enriched: EnrichedFinding
    tier: Tier                      # BLOCK, WARN, or SUPPRESS
    reason: str                     # Plain-English explanation of classification
```

### Step 2: SARIF Parser (`parser.py`)

A single parser that handles SARIF from Docker Scout, Trivy, and Grype. Returns a list of `Finding` objects.

**Core logic:**

1. Load JSON, validate it has `version: "2.1.0"` and `runs[]`
2. Extract the scanner name from `runs[0].tool.driver.name`
3. Build a rules lookup dict from `runs[0].tool.driver.rules[]` keyed by rule ID — this is where severity, CVSS data, and descriptions live
4. Iterate `runs[0].results[]`:
   - Get CVE ID from `ruleId`
   - Look up the matching rule for severity and CVSS vector
   - Extract package name and version from `locations[].logicalLocations[]`
   - Normalise into a `Finding`
5. Deduplicate by CVE ID (keep the highest severity if duplicated)

**Scanner-specific handling:**

Each scanner puts CVSS and package data in slightly different spots within SARIF. The parser should try multiple known paths:

- CVSS vector: check `rule.properties.cvssV3_vectorString`, then `rule.properties.security-severity` (Trivy), then `rule.properties.tags` for embedded vector strings
- Package info: check `logicalLocations[].name` and `fullyQualifiedName`, fall back to parsing the `message.text` field
- Published date: may be in `rule.properties.published` or similar — if not present, leave as None

**If a field can't be found, set it to None and move on. Never crash on missing data.**

### Step 3: CVSS Attack Vector Extraction (`enrichment/cvss.py`)

Parse the CVSS v3.x vector string to extract the attack vector. Simple string operation — no library needed.

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
              ^
              AV:N = Network, AV:A = Adjacent, AV:L = Local, AV:P = Physical
```

- Split vector string by `/`
- Find the component starting with `AV:`
- Map: `N` → `NETWORK`, `A` → `ADJACENT`, `L` → `LOCAL`, `P` → `PHYSICAL`
- Handle CVSS v2 vectors as a fallback. If no vector string exists, return None (treated as unknown in classification — fail open).

### Step 4: EPSS Lookup (`enrichment/epss.py`)

**Do NOT hit the EPSS API per-CVE.** Use the bulk download approach:

1. On first run (or if cache is older than 24 hours), download the full EPSS CSV from: `https://epss.cyentia.com/epss_scores-current.csv.gz`
2. Decompress and parse into a dict: `{cve_id: {"epss": float, "percentile": float}}`
3. Cache the parsed data locally (as JSON in the cache directory with a timestamp)
4. On subsequent runs, check cache age. If < 24 hours old, use cache. Otherwise re-download.
5. Lookup is then a simple dict lookup per CVE.

The CSV has a header comment line starting with `#` (skip it), then columns: `cve,epss,percentile`.

### Step 5: CISA KEV Lookup (`enrichment/kev.py`)

1. Download the KEV catalogue JSON from: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
2. Parse `vulnerabilities[].cveID` into a set for O(1) lookup
3. Cache locally with same 24-hour refresh strategy as EPSS
4. Lookup: `cve_id in kev_set`

### Step 6: Classification Engine (`engine.py`)

This is the core logic. For each `EnrichedFinding`, assign a `Tier` and generate a plain-English reason.

**Implement the decision table exactly as specified above. The logic in pseudocode:**

```python
def classify(finding: EnrichedFinding) -> ClassifiedFinding:

    # KEV always wins
    if finding.in_kev:
        return BLOCK, "In CISA KEV — confirmed active exploitation"

    is_local = finding.attack_vector == "LOCAL"
    is_physical = finding.attack_vector == "PHYSICAL"
    is_local_or_physical = is_local or is_physical

    epss_known = finding.epss_score is not None
    epss_low = epss_known and finding.epss_score < 0.001
    age_known = finding.days_since_published is not None
    age_stable = age_known and finding.days_since_published > 14

    # Network / Adjacent / Unknown vector
    if not is_local_or_physical:
        if not epss_known:
            return BLOCK, "Network-accessible, EPSS unknown — fail open"
        if not epss_low:
            return BLOCK, f"Network-accessible, EPSS {pct(finding.epss_score)} (above threshold)"
        if not age_stable:
            return BLOCK, f"Network-accessible, EPSS {pct(finding.epss_score)} but published {finding.days_since_published}d ago (below 14-day stabilisation)"
        return WARN, f"Network-accessible but EPSS {pct(finding.epss_score)} and {finding.days_since_published}d old — low risk, fix when convenient"

    # Local / Physical vector
    if not epss_known:
        return WARN, "Local vector, EPSS unknown — fail open"
    if not epss_low:
        return WARN, f"Local vector, EPSS {pct(finding.epss_score)} (above threshold) — fix when convenient"
    if not age_stable:
        return WARN, f"Local vector, EPSS {pct(finding.epss_score)} but published {finding.days_since_published}d ago — too new to suppress"
    return SUPPRESS, f"Local vector, EPSS {pct(finding.epss_score)}, not in KEV, {finding.days_since_published}d old — near-zero risk"
```

### Step 7: CLI (`cli.py`)

Use Click to build the CLI interface.

```
Usage: cvesieve [OPTIONS] [INPUT_FILE]

  Filter CVE scanner noise using real-world exploitability signals.

  INPUT_FILE: Path to SARIF JSON output from Docker Scout, Trivy, or Grype.
              If omitted, reads from stdin.

Options:
  -f, --format [table|json|summary]   Output format (default: table)
  -o, --output FILE                    Write output to file instead of stdout
  --epss-threshold FLOAT               EPSS threshold (default: 0.001)
  --age-threshold INT                  Minimum days since publication for downgrade (default: 14)
  --cache-dir PATH                     Cache directory for EPSS/KEV data (default: ~/.cvesieve/cache)
  --no-cache                           Force re-download of EPSS and KEV data
  --tier [block|warn|suppress|all]     Filter output to specific tier (default: all)
  --version                            Show version
  --help                               Show this message
```

**Pipeline usage (key UX goal):**
```bash
# Pipe from Docker Scout
docker scout cves --format sarif myimage:latest | cvesieve

# Pipe from Trivy
trivy image --format sarif myimage:latest | cvesieve

# Pipe from Grype
grype myimage:latest -o sarif | cvesieve

# From file
cvesieve scan.sarif.json

# JSON output for CI integration
cvesieve --format json scan.sarif.json

# Summary for quick checks
cvesieve --format summary scan.sarif.json

# Only show what's blocking the pipeline
cvesieve --tier block scan.sarif.json
```

### Step 8: Output Formatting (`output.py`)

**Table format (default for terminals):**
```
cvesieve v0.1.0
Scanner: docker scout | Image: myimage:latest | Total CVEs: 47

══ BLOCK (8) — pipeline will fail ════════════════════════════════
  CVE ID              SEVERITY  PACKAGE         EPSS     VECTOR    REASON
  CVE-2024-1234       CRITICAL  openssl 1.1.1k  34.2%    Network   In CISA KEV — active exploitation
  CVE-2024-5678       HIGH      curl 7.88.1     5.1%     Network   Network-accessible, EPSS above threshold
  ...

══ WARN (15) — fix when convenient ═══════════════════════════════
  CVE-2024-3456       HIGH      zlib 1.2.11     0.08%    Network   Network-accessible, low EPSS, 45d old
  CVE-2024-7777       MEDIUM    sudo 1.9.5      0.4%     Local     Local vector, EPSS above threshold
  ...

══ SUPPRESS (24) — near-zero risk ════════════════════════════════
  CVE-2024-9999       HIGH      glibc 2.31-13   0.02%    Local     Local vector, EPSS 0.02%, 67d old
  ...

Summary: 47 total → 8 block, 15 warn, 24 suppress (83.0% noise reduction)
```

**JSON format (for CI/CD):**
```json
{
  "metadata": {
    "tool": "cvesieve",
    "version": "0.1.0",
    "scanner": "docker scout",
    "timestamp": "2026-02-21T10:00:00Z",
    "thresholds": {
      "epss": 0.001,
      "age_days": 14
    }
  },
  "summary": {
    "total": 47,
    "block": 8,
    "warn": 15,
    "suppress": 24,
    "noise_reduction_pct": 83.0
  },
  "block": [...],
  "warn": [...],
  "suppress": [...]
}
```

**Summary format:**
Just the summary line — useful for CI logs:
```
cvesieve: 47 total → 8 block, 15 warn, 24 suppress (83.0% noise reduction) | 1 KEV hit
```

---

## Step 9: Tests

**Write tests BEFORE implementation. The tests encode the safety guarantees.**

### Test fixtures
Generate sample SARIF files by actually running each scanner against a known image (e.g. `node:18` or `python:3.11`). Trim to ~10-15 results for manageability. Place in `tests/fixtures/`.

Alternatively, construct minimal valid SARIF files by hand that cover the test scenarios.

### Key test cases for `test_engine.py`:

**BLOCK tier tests:**
1. **KEV override**: CVE in KEV with low EPSS and local vector → BLOCK
2. **KEV with no EPSS**: CVE in KEV, no EPSS data → BLOCK
3. **Network high EPSS**: Network vector, EPSS 5.0%, 30 days old → BLOCK
4. **Network unknown EPSS**: Network vector, no EPSS data → BLOCK (fail open)
5. **Network low EPSS but new**: Network vector, EPSS 0.05%, 5 days old → BLOCK

**WARN tier tests:**
6. **Network low EPSS and old**: Network vector, EPSS 0.05%, 30 days old → WARN
7. **Local high EPSS**: Local vector, EPSS 0.5%, 30 days old → WARN
8. **Local unknown EPSS**: Local vector, no EPSS data → WARN (fail open)
9. **Local low EPSS but new**: Local vector, EPSS 0.02%, 5 days old → WARN

**SUPPRESS tier tests:**
10. **Full suppress**: Local vector, EPSS 0.02%, not in KEV, 30 days old → SUPPRESS

**Edge case tests:**
11. **EPSS exactly at threshold**: EPSS exactly 0.001 (0.1%) → does NOT qualify as low (strictly less than)
12. **Age exactly at threshold**: Published exactly 14 days ago → does NOT qualify as stable (strictly greater than)
13. **Physical vector**: Physical attack vector → treated same as local
14. **Adjacent vector**: Adjacent network vector → treated same as network
15. **Missing CVSS vector entirely**: No vector string → attack vector is unknown → network-tier logic applies
16. **Missing published date**: No date available, local vector, low EPSS → WARN (can't confirm age)

### SARIF parser tests (`test_parser.py`):
1. Parse Docker Scout SARIF → correct number of findings, correct fields
2. Parse Trivy SARIF → correct number of findings, correct fields
3. Parse Grype SARIF → correct number of findings, correct fields
4. Invalid JSON → helpful error message
5. Valid JSON but not SARIF → helpful error message
6. SARIF with missing optional fields → parser doesn't crash, fields are None

### Integration test (`test_integration.py`):
- Feed sample Docker Scout SARIF through the full pipeline end-to-end
- Assert correct tier counts
- Assert KEV CVE is always BLOCK
- Assert no local vector CVE is ever BLOCK (unless in KEV)
- Assert no network vector CVE with unknown EPSS is ever below BLOCK
- Assert output JSON schema is valid

---

## Step 10: README.md

Write a clear README with:
- One-sentence description: "Filter CVE scanner noise using real-world exploitability signals."
- The problem (2-3 sentences)
- How it works (the three-tier model with decision table)
- Installation: `pip install .` or `pip install cvesieve`
- Usage examples showing Docker Scout, Trivy, and Grype pipelines
- The safety guarantee (KEV override, fail-open design, nothing hidden)
- Configuration options
- Licence: MIT

---

## Implementation Notes

- **Fail open everywhere.** If EPSS data is unavailable, if CVSS vector can't be parsed, if KEV can't be downloaded, if any SARIF field is missing — the CVE fails toward the higher tier. Never suppress or downgrade when data is incomplete.
- **Fail-open is asymmetric.** Missing data on a network CVE → BLOCK. Missing data on a local CVE → WARN. The blast radius of getting it wrong is fundamentally different.
- **No network calls at scan time if cache is fresh.** The EPSS and KEV data should be cached locally. The tool should work offline if the cache exists.
- **Keep it fast.** The enrichment is all local lookups against cached data. The only network calls are the daily cache refreshes. Processing 500 CVEs should take under a second.
- **Exit codes for CI:** Exit 1 if any BLOCK findings exist, exit 0 otherwise. WARN findings pass the pipeline.
- **Stderr for progress, stdout for results.** Cache download progress and info messages go to stderr so stdout remains clean for piping.
- **SARIF is the only input format.** Do not build native parsers for each scanner's custom JSON format. If a scanner supports SARIF output, it's supported. This keeps the parser simple and maintainable.
- **Physical vector treated as local.** Both require physical/local access. Same tier logic applies.

---

## What NOT to Build

- No web UI
- No database
- No daemon/server mode
- No Docker image (yet)
- No GitHub Action wrapper (yet)
- No config file (CLI flags are sufficient for PoC)
- No native scanner JSON parsers — SARIF only
- No weighted scoring — this is rule-based three-tier classification only
- No code reachability analysis