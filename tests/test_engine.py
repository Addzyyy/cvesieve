"""
Tests for engine.py — every row in the decision table plus edge cases.
These tests encode the safety guarantees of cvesieve.
"""
import pytest

from cvesieve.engine import classify
from cvesieve.models import EnrichedFinding, Finding, Tier


def make_finding(
    cve_id: str = "CVE-2024-1234",
    severity: str = "HIGH",
    package_name: str = "openssl",
    installed_version: str = "1.1.1k",
    cvss_vector: str | None = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    published_date: str | None = "2024-01-01",
    scanner: str = "trivy",
) -> Finding:
    return Finding(
        cve_id=cve_id,
        severity=severity,
        package_name=package_name,
        installed_version=installed_version,
        fixed_version=None,
        cvss_vector=cvss_vector,
        published_date=published_date,
        scanner=scanner,
        description=None,
    )


def make_enriched(
    epss_score: float | None = None,
    epss_percentile: float | None = None,
    attack_vector: str | None = "NETWORK",
    in_kev: bool = False,
    days_since_published: int | None = 30,
    **finding_kwargs,
) -> EnrichedFinding:
    return EnrichedFinding(
        finding=make_finding(**finding_kwargs),
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        attack_vector=attack_vector,
        in_kev=in_kev,
        days_since_published=days_since_published,
    )


# ── BLOCK tier tests ─────────────────────────────────────────────────────────

class TestBlock:
    def test_kev_override_with_local_vector_low_epss(self):
        """KEV always wins — even local vector + low EPSS is BLOCK."""
        ef = make_enriched(in_kev=True, attack_vector="LOCAL", epss_score=0.0001, days_since_published=60)
        result = classify(ef)
        assert result.tier == Tier.BLOCK
        assert "kev" in result.reason.lower()

    def test_kev_override_with_no_epss(self):
        """KEV always wins — even when EPSS is unknown."""
        ef = make_enriched(in_kev=True, epss_score=None, attack_vector="NETWORK")
        result = classify(ef)
        assert result.tier == Tier.BLOCK
        assert "kev" in result.reason.lower()

    def test_network_high_epss(self):
        """Network vector, EPSS 5.0%, 30 days old → BLOCK."""
        ef = make_enriched(attack_vector="NETWORK", epss_score=0.05, days_since_published=30, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.BLOCK

    def test_network_unknown_epss(self):
        """Network vector, no EPSS data → BLOCK (fail open)."""
        ef = make_enriched(attack_vector="NETWORK", epss_score=None, days_since_published=30, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.BLOCK

    def test_network_low_epss_but_new(self):
        """Network vector, low EPSS, only 5 days old → BLOCK (too new to trust)."""
        ef = make_enriched(attack_vector="NETWORK", epss_score=0.0005, days_since_published=5, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.BLOCK

    def test_adjacent_vector_high_epss(self):
        """Adjacent vector treated same as network — high EPSS → BLOCK."""
        ef = make_enriched(attack_vector="ADJACENT", epss_score=0.05, days_since_published=30, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.BLOCK

    def test_unknown_vector_unknown_epss(self):
        """Unknown attack vector with no EPSS → BLOCK (fail open)."""
        ef = make_enriched(attack_vector=None, epss_score=None, days_since_published=30, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.BLOCK

    def test_unknown_vector_low_epss_old(self):
        """Unknown attack vector treated as network — even low EPSS, old CVE → BLOCK for new, WARN for old."""
        # Unknown vector → network logic → low EPSS + old → WARN
        ef = make_enriched(attack_vector=None, epss_score=0.0005, days_since_published=30, in_kev=False)
        result = classify(ef)
        # Unknown vector uses network-tier logic; old + low EPSS → WARN
        assert result.tier == Tier.WARN


# ── WARN tier tests ───────────────────────────────────────────────────────────

class TestWarn:
    def test_network_low_epss_and_old(self):
        """Network vector, low EPSS, 30 days old → WARN."""
        ef = make_enriched(attack_vector="NETWORK", epss_score=0.0005, days_since_published=30, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.WARN

    def test_local_high_epss(self):
        """Local vector, EPSS 0.5%, 30 days old → WARN."""
        ef = make_enriched(attack_vector="LOCAL", epss_score=0.005, days_since_published=30, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.WARN

    def test_local_unknown_epss(self):
        """Local vector, no EPSS data → WARN (fail open, not BLOCK)."""
        ef = make_enriched(attack_vector="LOCAL", epss_score=None, days_since_published=30, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.WARN

    def test_local_low_epss_but_new(self):
        """Local vector, low EPSS, 5 days old → WARN (too new to suppress)."""
        ef = make_enriched(attack_vector="LOCAL", epss_score=0.0005, days_since_published=5, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.WARN

    def test_network_low_epss_missing_date(self):
        """Network vector, low EPSS, no published date → cannot confirm age → BLOCK (fail open)."""
        ef = make_enriched(attack_vector="NETWORK", epss_score=0.0005, days_since_published=None, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.BLOCK

    def test_local_low_epss_missing_date(self):
        """Local vector, low EPSS, no published date → cannot confirm age → WARN (fail open, local ceiling)."""
        ef = make_enriched(attack_vector="LOCAL", epss_score=0.0005, days_since_published=None, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.WARN


# ── SUPPRESS tier tests ───────────────────────────────────────────────────────

class TestSuppress:
    def test_full_suppress(self):
        """Local vector, low EPSS, not in KEV, 30 days old → SUPPRESS."""
        ef = make_enriched(attack_vector="LOCAL", epss_score=0.0002, days_since_published=30, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.SUPPRESS

    def test_physical_vector_full_suppress(self):
        """Physical vector treated same as local — low EPSS, old → SUPPRESS."""
        ef = make_enriched(attack_vector="PHYSICAL", epss_score=0.0002, days_since_published=30, in_kev=False)
        result = classify(ef)
        assert result.tier == Tier.SUPPRESS


# ── Edge case tests ───────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_epss_exactly_at_threshold_is_not_low(self):
        """EPSS of exactly 0.001 (0.1%) does NOT qualify as low — strictly less than."""
        ef = make_enriched(attack_vector="LOCAL", epss_score=0.001, days_since_published=30, in_kev=False)
        result = classify(ef)
        # 0.001 is NOT < 0.001, so epss_low is False → WARN
        assert result.tier == Tier.WARN

    def test_age_exactly_at_threshold_is_not_stable(self):
        """Age of exactly 14 days does NOT qualify as stable — strictly greater than."""
        ef = make_enriched(attack_vector="LOCAL", epss_score=0.0002, days_since_published=14, in_kev=False)
        result = classify(ef)
        # 14 is NOT > 14, so age_stable is False → WARN
        assert result.tier == Tier.WARN

    def test_physical_vector_treated_as_local(self):
        """Physical attack vector → treated same as local (not network)."""
        ef = make_enriched(attack_vector="PHYSICAL", epss_score=None, days_since_published=30, in_kev=False)
        result = classify(ef)
        # Physical + unknown EPSS → WARN (local fail-open), not BLOCK
        assert result.tier == Tier.WARN

    def test_adjacent_vector_treated_as_network(self):
        """Adjacent network vector → treated same as network."""
        ef = make_enriched(attack_vector="ADJACENT", epss_score=None, days_since_published=30, in_kev=False)
        result = classify(ef)
        # Adjacent + unknown EPSS → BLOCK (network fail-open)
        assert result.tier == Tier.BLOCK

    def test_missing_cvss_vector_treated_as_network(self):
        """No attack vector (None) → treated as unknown → network-tier logic applies."""
        ef = make_enriched(attack_vector=None, epss_score=0.05, days_since_published=30, in_kev=False)
        result = classify(ef)
        # Unknown vector + high EPSS → BLOCK
        assert result.tier == Tier.BLOCK

    def test_no_local_vector_cve_ever_blocks_without_kev(self):
        """Non-KEV local CVE can never be BLOCK — max tier is WARN."""
        for epss in [0.5, 0.9, 1.0]:
            ef = make_enriched(attack_vector="LOCAL", epss_score=epss, days_since_published=30, in_kev=False)
            result = classify(ef)
            assert result.tier != Tier.BLOCK, f"Local CVE with EPSS={epss} should never be BLOCK"

    def test_reason_is_always_populated(self):
        """Every classified finding must have a non-empty reason."""
        cases = [
            make_enriched(in_kev=True),
            make_enriched(attack_vector="NETWORK", epss_score=0.05),
            make_enriched(attack_vector="LOCAL", epss_score=0.0002, days_since_published=30),
            make_enriched(attack_vector="LOCAL", epss_score=None),
        ]
        for ef in cases:
            result = classify(ef)
            assert result.reason, f"Empty reason for {ef}"
