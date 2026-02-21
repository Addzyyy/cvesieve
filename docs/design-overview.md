# cvesieve
**Problem Statement & Design Overview**  
*Version 0.2 | February 2026*

---

## Problem

Container image scanners (Docker Scout, Trivy, Grype) flag every CVE matching a package version — regardless of whether it's exploitable in context. A local-privilege-escalation CVE is given the same weight as a remotely exploitable one, even when every container runs in Kubernetes where local access is near-impossible. Research shows only 2–7% of published CVEs are ever exploited in the wild, yet scanners provide no signal to distinguish those from the rest.

The result: alert fatigue, blocked pipelines, and engineers who stop trusting scanner output entirely — meaning genuinely critical vulnerabilities get the same shrug as the noise.

---

## Solution

**cvesieve** is a lightweight CLI that sits between the scanner and the CI pipeline. It takes standard SARIF output, enriches each CVE with two exploitability signals, and classifies every finding into one of three tiers: **BLOCK**, **WARN**, or **SUPPRESS**.

Nothing is hidden. Nothing is deleted. The scanner still runs. cvesieve just makes the output usable.

```bash
docker scout cves --format sarif myimage:latest | cvesieve
```

---

## Signals

| Signal | Source | Purpose |
|--------|--------|---------|
| **EPSS Score** | FIRST (free public data, cached locally) | Probability the CVE will be exploited in the next 30 days. Below 0.1% = extremely unlikely to ever be exploited. |
| **Attack Vector** | CVSS string already in scan output | Local = attacker needs existing access. Network = remotely exploitable. No additional API call needed. |
| **CISA KEV** | CISA catalogue (free, cached locally) | CVEs with confirmed active exploitation in the wild. Hard override — always BLOCK. |

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
**WARN** → pipeline passes, surfaces in PR comments — fix when convenient.  
**SUPPRESS** → visible in full report only — near-zero risk.

---

## Safety Guarantees

- **KEV hard override.** Any CVE with confirmed active exploitation is always BLOCK, regardless of all other signals.
- **Fail open.** Missing EPSS data, unparseable CVSS vector, or unknown age → the CVE is pushed toward the higher tier, never suppressed.
- **Fail-open is asymmetric.** Missing data on a network CVE → BLOCK. Missing data on a local CVE → WARN. The blast radius is different.
- **Full audit trail.** Every classification includes a plain-English reason. Every suppressed CVE is visible in the report.
- **14-day stabilisation.** CVEs younger than 14 days are never downgraded — EPSS needs time to calibrate.

---

## Example Output

```
cvesieve v0.1.0
Scanner: docker scout | Image: myimage:latest | Total CVEs: 47

══ BLOCK (8) — pipeline will fail ════════════════════════
  CVE-2024-1234   CRITICAL  openssl 1.1.1k  34.2%  Network  In CISA KEV
  CVE-2024-5678   HIGH      curl 7.88.1     5.1%   Network  EPSS above threshold

══ WARN (15) — fix when convenient ═══════════════════════
  CVE-2024-3456   HIGH      zlib 1.2.11     0.08%  Network  Low EPSS, 45d old
  CVE-2024-7777   MEDIUM    sudo 1.9.5      0.4%   Local    EPSS above threshold

══ SUPPRESS (24) — near-zero risk ════════════════════════
  CVE-2024-9999   HIGH      glibc 2.31-13   0.02%  Local    EPSS 0.02%, 67d old

Summary: 47 total → 8 block, 15 warn, 24 suppress (83% noise reduction)
```

---

## Scope

**This version does:**
- Accept SARIF from Docker Scout, Trivy, and Grype
- Enrich with EPSS, attack vector, and CISA KEV
- Classify into BLOCK / WARN / SUPPRESS with reasons
- Output as table, JSON, or one-line summary
- Work as a CI pipeline gate (exit 1 on BLOCK findings)

**This version does not:**
- Perform code reachability or runtime analysis
- Replace security review for BLOCK-tier findings
- Require changes to existing scanners or CI infrastructure

**Future iterations may add:** weighted scoring across additional signals, AI-assisted reachability analysis, GitHub Action / PR comment integration.
