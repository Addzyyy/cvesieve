"""Tests for CSV, Markdown, and SARIF output formats."""
from __future__ import annotations

import csv
import io
import json

import pytest

from cvesieve.models import ClassifiedFinding, EnrichedFinding, Finding, Tier
from cvesieve.output import format_csv, format_markdown, format_sarif


def _make_findings() -> list[ClassifiedFinding]:
    """Create a small set of findings covering all tiers."""
    items = []
    specs = [
        ("CVE-2024-1111", "CRITICAL", "openssl", "3.0.1", "3.0.2", 0.5, 0.98,
         "NETWORK", True, 90, Tier.BLOCK, "KEV hit"),
        ("CVE-2024-2222", "HIGH", "curl", "7.80", "7.81", 0.002, 0.60,
         "NETWORK", False, 30, Tier.WARN, "Network low EPSS, age > 14d"),
        ("CVE-2024-3333", "LOW", "tar", "1.35", None, 0.0001, 0.10,
         "LOCAL", False, 200, Tier.SUPPRESS, "Local low EPSS, old"),
    ]
    for (cve, sev, pkg, ver, fix, epss, pct, av, kev, days, tier, reason) in specs:
        f = Finding(
            cve_id=cve, severity=sev, package_name=pkg,
            installed_version=ver, fixed_version=fix,
            cvss_vector=None, published_date=None,
            scanner="trivy", description=None,
        )
        ef = EnrichedFinding(
            finding=f, epss_score=epss, epss_percentile=pct,
            attack_vector=av, in_kev=kev, days_since_published=days,
        )
        items.append(ClassifiedFinding(enriched=ef, tier=tier, reason=reason))
    return items


class TestCsvFormat:
    def test_valid_csv(self):
        findings = _make_findings()
        output = format_csv(findings)
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 4  # header + 3 findings

    def test_correct_headers(self):
        findings = _make_findings()
        output = format_csv(findings)
        reader = csv.reader(io.StringIO(output))
        headers = next(reader)
        expected = [
            "cve_id", "severity", "package", "version", "fixed_version",
            "epss_score", "epss_pct", "attack_vector", "in_kev",
            "days_since_published", "tier", "reason",
        ]
        assert headers == expected

    def test_data_rows_match_findings(self):
        findings = _make_findings()
        output = format_csv(findings)
        reader = csv.reader(io.StringIO(output))
        next(reader)  # skip header
        rows = list(reader)
        assert rows[0][0] == "CVE-2024-1111"
        assert rows[0][1] == "CRITICAL"
        assert rows[0][10] == "BLOCK"

    def test_special_characters_escaped(self):
        """Commas and quotes in reason field should be properly escaped."""
        f = Finding(
            cve_id="CVE-2024-SPECIAL", severity="HIGH", package_name="test",
            installed_version="1.0", fixed_version=None, cvss_vector=None,
            published_date=None, scanner="trivy", description=None,
        )
        ef = EnrichedFinding(
            finding=f, epss_score=0.01, epss_percentile=0.5,
            attack_vector="NETWORK", in_kev=False, days_since_published=10,
        )
        cf = ClassifiedFinding(
            enriched=ef, tier=Tier.BLOCK,
            reason='Contains "quotes" and, commas',
        )
        output = format_csv([cf])
        reader = csv.reader(io.StringIO(output))
        next(reader)
        row = next(reader)
        assert row[11] == 'Contains "quotes" and, commas'

    def test_none_values(self):
        findings = _make_findings()
        output = format_csv(findings)
        # CVE-2024-3333 has fixed_version=None
        reader = csv.reader(io.StringIO(output))
        next(reader)
        rows = list(reader)
        assert rows[2][4] == ""  # None → empty string


class TestMarkdownFormat:
    def test_contains_pipe_tables(self):
        findings = _make_findings()
        output = format_markdown(findings, scanner="trivy")
        assert "|" in output
        assert "---" in output

    def test_cve_links_to_nvd(self):
        findings = _make_findings()
        output = format_markdown(findings, scanner="trivy")
        assert "https://nvd.nist.gov/vuln/detail/CVE-2024-1111" in output

    def test_tier_sections(self):
        findings = _make_findings()
        output = format_markdown(findings, scanner="trivy")
        assert "BLOCK" in output
        assert "WARN" in output
        assert "SUPPRESS" in output

    def test_noise_reduction_line(self):
        findings = _make_findings()
        output = format_markdown(findings, scanner="trivy")
        assert "noise reduction" in output.lower()

    def test_tier_filter(self):
        findings = _make_findings()
        output = format_markdown(findings, scanner="trivy", tier_filter="block")
        assert "BLOCK" in output
        # WARN and SUPPRESS sections should not appear
        lines = output.split("\n")
        section_headers = [l for l in lines if l.startswith("##")]
        warn_headers = [h for h in section_headers if "WARN" in h]
        assert len(warn_headers) == 0


class TestSarifFormat:
    def test_valid_json(self):
        findings = _make_findings()
        output = format_sarif(findings, scanner="trivy")
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_schema_version(self):
        findings = _make_findings()
        output = format_sarif(findings, scanner="trivy")
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_tool_info(self):
        findings = _make_findings()
        output = format_sarif(findings, scanner="trivy")
        data = json.loads(output)
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "cvesieve"

    def test_levels_match_tiers(self):
        findings = _make_findings()
        output = format_sarif(findings, scanner="trivy")
        data = json.loads(output)
        results = data["runs"][0]["results"]
        level_by_id = {r["ruleId"]: r["level"] for r in results}
        assert level_by_id["CVE-2024-1111"] == "error"    # BLOCK
        assert level_by_id["CVE-2024-2222"] == "warning"  # WARN
        assert level_by_id["CVE-2024-3333"] == "note"     # SUPPRESS

    def test_properties_contain_enrichment(self):
        findings = _make_findings()
        output = format_sarif(findings, scanner="trivy")
        data = json.loads(output)
        results = data["runs"][0]["results"]
        for r in results:
            props = r["properties"]
            assert "epss_score" in props
            assert "attack_vector" in props
            assert "in_kev" in props
            assert "tier" in props

    def test_result_count_matches_findings(self):
        findings = _make_findings()
        output = format_sarif(findings, scanner="trivy")
        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) == 3
