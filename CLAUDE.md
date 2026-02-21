# CLAUDE.md

## Project Overview

cvesieve is a CLI tool that filters CVE scanner noise using real-world exploitability signals. It takes SARIF output from Docker Scout, Trivy, or Grype, enriches each CVE with EPSS scores and CISA KEV data, and classifies findings into three tiers: BLOCK, WARN, or SUPPRESS.

# CVESieve
Read `docs/design-overview.md` for the problem statement and classification model. Read `docs/poc-plan.md` for the full implementation plan — follow it step by step.

## Tech Stack

- Python 3.11+
- Click (CLI framework)
- requests (HTTP for cache downloads)
- pytest (testing)
- No other external dependencies — keep it minimal

## Project Structure

```
src/cvesieve/
├── cli.py          # Click entrypoint
├── models.py       # Dataclasses: Finding, EnrichedFinding, ClassifiedFinding, Tier enum
├── parser.py       # SARIF parser (single file, handles Docker Scout/Trivy/Grype)
├── enrichment/
│   ├── epss.py     # EPSS bulk CSV cache + lookup
│   ├── kev.py      # CISA KEV JSON cache + lookup
│   └── cvss.py     # Extract attack vector from CVSS vector string
├── engine.py       # Three-tier classification logic
└── output.py       # Table, JSON, summary formatters
```

## Critical Design Rules

These are non-negotiable. Do not deviate from them.

### Fail Open

If any data is missing or unparseable, the CVE must be pushed toward the HIGHER tier, never suppressed or downgraded. Specifically:
- Missing EPSS on a network CVE → BLOCK
- Missing EPSS on a local CVE → WARN
- Missing CVSS vector → treat as unknown/network → BLOCK-tier logic
- Missing published date → cannot confirm age → no age-based downgrade
- KEV download fails → treat all CVEs as potentially in KEV? No — proceed without KEV but log a warning to stderr. Do NOT block everything.
- EPSS download fails → all EPSS scores are None → fail-open rules apply per CVE

### KEV Always Wins

Any CVE in the CISA KEV catalogue is BLOCK. No exceptions. No other signal can override this. Check KEV before evaluating any other condition.

### Classification Logic

The decision table in `docs/design-overview.md` is the source of truth. The engine must implement it exactly. Do not add additional rules, heuristics, or special cases beyond what the table specifies.

### SARIF Only

Do not build native parsers for Trivy JSON, Grype JSON, or Docker Scout's native format. SARIF is the only input format. If a scanner doesn't support SARIF, it's out of scope.

## Coding Guidelines

### Style
- Use dataclasses, not dicts, for structured data
- Type hints on all function signatures
- No classes where a function will do — keep it functional
- f-strings for formatting, not .format() or %

### Error Handling
- Never crash on malformed input — return helpful error messages via stderr
- Parser should skip unparseable CVEs with a warning, not abort
- Network failures (cache download) should warn and continue, not crash

### Output
- Stderr for progress messages, warnings, cache download status
- Stdout for results only — must be clean for piping
- Exit code 1 if any BLOCK findings, exit code 0 otherwise

### Caching
- Cache directory: `~/.cvesieve/cache/` by default
- EPSS: download bulk CSV from `https://epss.cyentia.com/epss_scores-current.csv.gz`, refresh if >24h old
- KEV: download JSON from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, refresh if >24h old
- Cache files should include a timestamp so freshness can be checked
- `--no-cache` flag forces re-download

### Testing
- Write tests FIRST, then implementation
- Tests for `engine.py` are the most important — they encode the safety guarantees
- Use pytest
- Test fixtures go in `tests/fixtures/` as `.sarif.json` files
- Mock network calls in tests — never hit real APIs during testing
- Every row in the decision table must have a corresponding test case
- Edge cases: EPSS exactly at threshold (0.001), age exactly at threshold (14 days), physical vector, adjacent vector, missing fields

## Commands

```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run the tool
cvesieve scan.sarif.json
cat scan.sarif.json | cvesieve
cvesieve --format json scan.sarif.json
cvesieve --format summary scan.sarif.json

# Force cache refresh
cvesieve --no-cache scan.sarif.json
```

## Common Pitfalls

- The EPSS bulk CSV has a comment line starting with `#` before the header — skip it
- CVSS v2 and v3 vector strings have different formats — handle both
- Docker Scout, Trivy, and Grype each put CVSS data in different SARIF `properties` fields — the parser must check multiple known paths
- The same CVE can appear multiple times in SARIF if it affects multiple packages — deduplicate by CVE ID
- EPSS scores are 0.0-1.0 (not percentages) — display as percentages in output but compare as decimals internally
- Thresholds are strictly less than / strictly greater than — EPSS of exactly 0.001 is NOT below threshold, age of exactly 14 is NOT above threshold
