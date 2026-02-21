"""
Three-tier classification engine.

Decision table (source of truth — do not add rules beyond this):

  KEV?  | Vector                          | EPSS      | Age > 14d? | Tier
  ------|---------------------------------|-----------|------------|--------
  Yes   | any                             | any       | any        | BLOCK
  No    | Network / Adjacent / Unknown    | ≥ 0.1%    | any        | BLOCK
  No    | Network / Adjacent / Unknown    | < 0.1%    | No         | BLOCK
  No    | Network / Adjacent / Unknown    | < 0.1%    | Yes        | WARN
  No    | Network / Adjacent / Unknown    | Unknown   | any        | BLOCK
  No    | Local / Physical                | ≥ 0.1%    | any        | WARN
  No    | Local / Physical                | < 0.1%    | No         | WARN
  No    | Local / Physical                | < 0.1%    | Yes        | SUPPRESS
  No    | Local / Physical                | Unknown   | any        | WARN
"""
from cvesieve.models import ClassifiedFinding, EnrichedFinding, Tier

EPSS_THRESHOLD = 0.001  # 0.1%
AGE_THRESHOLD = 14      # days

_LOCAL_VECTORS = {"LOCAL", "PHYSICAL"}


def _pct(score: float) -> str:
    return f"{score * 100:.2f}%"


def classify(enriched: EnrichedFinding, epss_threshold: float = EPSS_THRESHOLD, age_threshold: int = AGE_THRESHOLD) -> ClassifiedFinding:
    # KEV always wins — check first, no exceptions
    if enriched.in_kev:
        return ClassifiedFinding(
            enriched=enriched,
            tier=Tier.BLOCK,
            reason="In CISA KEV — confirmed active exploitation in the wild",
        )

    is_local = enriched.attack_vector in _LOCAL_VECTORS

    epss_known = enriched.epss_score is not None
    epss_low = epss_known and enriched.epss_score < epss_threshold
    age_known = enriched.days_since_published is not None
    age_stable = age_known and enriched.days_since_published > age_threshold

    if not is_local:
        # Network / Adjacent / Unknown vector — ceiling is BLOCK
        if not epss_known:
            return ClassifiedFinding(
                enriched=enriched,
                tier=Tier.BLOCK,
                reason=f"Network-accessible ({enriched.attack_vector or 'unknown vector'}), EPSS unknown — fail open",
            )
        if not epss_low:
            return ClassifiedFinding(
                enriched=enriched,
                tier=Tier.BLOCK,
                reason=f"Network-accessible, EPSS {_pct(enriched.epss_score)} (≥ threshold)",
            )
        if not age_stable:
            age_desc = f"{enriched.days_since_published}d old" if age_known else "age unknown"
            return ClassifiedFinding(
                enriched=enriched,
                tier=Tier.BLOCK,
                reason=f"Network-accessible, EPSS {_pct(enriched.epss_score)} but {age_desc} — below 14-day stabilisation window",
            )
        return ClassifiedFinding(
            enriched=enriched,
            tier=Tier.WARN,
            reason=f"Network-accessible, EPSS {_pct(enriched.epss_score)}, {enriched.days_since_published}d old — low risk, fix when convenient",
        )

    # Local / Physical vector — ceiling is WARN
    if not epss_known:
        return ClassifiedFinding(
            enriched=enriched,
            tier=Tier.WARN,
            reason=f"Local vector ({enriched.attack_vector}), EPSS unknown — fail open",
        )
    if not epss_low:
        return ClassifiedFinding(
            enriched=enriched,
            tier=Tier.WARN,
            reason=f"Local vector, EPSS {_pct(enriched.epss_score)} (≥ threshold) — fix when convenient",
        )
    if not age_stable:
        age_desc = f"{enriched.days_since_published}d old" if age_known else "age unknown"
        return ClassifiedFinding(
            enriched=enriched,
            tier=Tier.WARN,
            reason=f"Local vector, EPSS {_pct(enriched.epss_score)}, {age_desc} — too new to suppress",
        )
    return ClassifiedFinding(
        enriched=enriched,
        tier=Tier.SUPPRESS,
        reason=f"Local vector, EPSS {_pct(enriched.epss_score)}, not in KEV, {enriched.days_since_published}d old — near-zero risk",
    )
