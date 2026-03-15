"""Tests for CVE allowlist — risk acceptance."""
from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from cvesieve.allowlist import AllowlistEntry, apply_allowlist, load_allowlist
from cvesieve.models import ClassifiedFinding, EnrichedFinding, Finding, Tier

FIXTURES = Path(__file__).parent / "fixtures"


def _make_cf(
    cve_id: str = "CVE-2024-TEST",
    tier: Tier = Tier.BLOCK,
    in_kev: bool = False,
    reason: str = "test reason",
) -> ClassifiedFinding:
    finding = Finding(
        cve_id=cve_id,
        severity="HIGH",
        package_name="testpkg",
        installed_version="1.0",
        fixed_version="1.1",
        cvss_vector=None,
        published_date=None,
        scanner="trivy",
        description=None,
    )
    enriched = EnrichedFinding(
        finding=finding,
        epss_score=0.05,
        epss_percentile=0.9,
        attack_vector="NETWORK",
        in_kev=in_kev,
        days_since_published=30,
    )
    return ClassifiedFinding(enriched=enriched, tier=tier, reason=reason)


class TestLoadAllowlist:
    def test_load_valid_toml(self):
        entries = load_allowlist(FIXTURES / "allowlist.toml")
        assert len(entries) == 2
        assert entries[0].cve_id == "CVE-2024-5678"
        assert entries[0].max_tier == Tier.SUPPRESS
        assert entries[0].approved_by == "jane.doe@example.com"
        assert entries[0].expires == date(2099, 12, 31)

    def test_load_entry_without_expires(self):
        entries = load_allowlist(FIXTURES / "allowlist.toml")
        no_expires = [e for e in entries if e.cve_id == "CVE-2024-1234"]
        assert len(no_expires) == 1
        assert no_expires[0].expires is None

    def test_load_nonexistent_file(self, capsys):
        entries = load_allowlist(Path("/nonexistent/allowlist.toml"))
        assert entries == []
        assert "cannot read" in capsys.readouterr().err

    def test_load_invalid_toml(self, tmp_path, capsys):
        bad = tmp_path / "bad.toml"
        bad.write_text("[[entry]\ncve_id = broken")
        entries = load_allowlist(bad)
        assert entries == []
        assert "invalid TOML" in capsys.readouterr().err

    def test_malformed_entry_skipped(self, tmp_path, capsys):
        toml = tmp_path / "partial.toml"
        toml.write_text(
            '[[entry]]\ncve_id = "CVE-2024-0001"\n'
            'max_tier = "SUPPRESS"\n'
            'reason = "ok"\n'
            'approved_by = "a@b.com"\n\n'
            '[[entry]]\ncve_id = "CVE-2024-0002"\n'
            '# missing required fields\n'
        )
        entries = load_allowlist(toml)
        assert len(entries) == 1
        assert "skipping" in capsys.readouterr().err

    def test_invalid_tier_skipped(self, tmp_path, capsys):
        toml = tmp_path / "bad_tier.toml"
        toml.write_text(
            '[[entry]]\ncve_id = "CVE-2024-0001"\n'
            'max_tier = "INVALID"\n'
            'reason = "test"\n'
            'approved_by = "a@b.com"\n'
        )
        entries = load_allowlist(toml)
        assert len(entries) == 0
        assert "invalid tier" in capsys.readouterr().err


class TestApplyAllowlist:
    def test_kev_stays_block(self):
        cf = _make_cf(cve_id="CVE-2024-1234", tier=Tier.BLOCK, in_kev=True)
        entry = AllowlistEntry(
            cve_id="CVE-2024-1234",
            max_tier=Tier.SUPPRESS,
            reason="accepted",
            approved_by="test@example.com",
        )
        result = apply_allowlist([cf], [entry])
        assert result[0].tier == Tier.BLOCK
        assert result[0].allowlist_note == "[allowlisted but KEV overrides]"

    def test_downgrade_block_to_warn(self):
        cf = _make_cf(tier=Tier.BLOCK)
        entry = AllowlistEntry(
            cve_id="CVE-2024-TEST",
            max_tier=Tier.WARN,
            reason="internal only",
            approved_by="eng@co.com",
        )
        result = apply_allowlist([cf], [entry])
        assert result[0].tier == Tier.WARN
        assert "eng@co.com" in result[0].reason
        assert "eng@co.com" in result[0].allowlist_note

    def test_downgrade_block_to_suppress(self):
        cf = _make_cf(tier=Tier.BLOCK)
        entry = AllowlistEntry(
            cve_id="CVE-2024-TEST",
            max_tier=Tier.SUPPRESS,
            reason="not applicable",
            approved_by="sec@co.com",
        )
        result = apply_allowlist([cf], [entry])
        assert result[0].tier == Tier.SUPPRESS

    def test_downgrade_warn_to_suppress(self):
        cf = _make_cf(tier=Tier.WARN)
        entry = AllowlistEntry(
            cve_id="CVE-2024-TEST",
            max_tier=Tier.SUPPRESS,
            reason="risk accepted",
            approved_by="sec@co.com",
        )
        result = apply_allowlist([cf], [entry])
        assert result[0].tier == Tier.SUPPRESS

    def test_already_at_or_below_tier_unchanged(self):
        cf = _make_cf(tier=Tier.SUPPRESS)
        entry = AllowlistEntry(
            cve_id="CVE-2024-TEST",
            max_tier=Tier.WARN,
            reason="something",
            approved_by="someone",
        )
        result = apply_allowlist([cf], [entry])
        assert result[0].tier == Tier.SUPPRESS

    def test_expired_entry_ignored(self, capsys):
        cf = _make_cf(tier=Tier.BLOCK)
        entry = AllowlistEntry(
            cve_id="CVE-2024-TEST",
            max_tier=Tier.SUPPRESS,
            reason="old",
            approved_by="old@co.com",
            expires=date(2020, 1, 1),
        )
        result = apply_allowlist([cf], [entry])
        assert result[0].tier == Tier.BLOCK
        assert "expired" in capsys.readouterr().err

    def test_reason_includes_approver(self):
        cf = _make_cf(tier=Tier.BLOCK)
        entry = AllowlistEntry(
            cve_id="CVE-2024-TEST",
            max_tier=Tier.WARN,
            reason="accepted risk",
            approved_by="jane@co.com",
        )
        result = apply_allowlist([cf], [entry])
        assert "jane@co.com" in result[0].reason
        assert "accepted risk" in result[0].reason

    def test_unmatched_cve_unchanged(self):
        cf = _make_cf(cve_id="CVE-2024-NOMATCH", tier=Tier.BLOCK)
        entry = AllowlistEntry(
            cve_id="CVE-2024-OTHER",
            max_tier=Tier.SUPPRESS,
            reason="irrelevant",
            approved_by="someone",
        )
        result = apply_allowlist([cf], [entry])
        assert result[0].tier == Tier.BLOCK
        assert result[0].allowlist_note is None
