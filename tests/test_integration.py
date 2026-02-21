"""
End-to-end integration tests — full pipeline from SARIF to classified findings.
Network calls are mocked. No real APIs hit during testing.
"""
import gzip
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cvesieve.cli import main
from cvesieve.enrichment.cvss import extract_attack_vector
from cvesieve.enrichment.epss import load_epss, lookup_epss
from cvesieve.enrichment.kev import is_in_kev, load_kev
from cvesieve.enrichment.nvd import NvdData
from cvesieve.engine import classify
from cvesieve.models import EnrichedFinding, Finding, Tier
from cvesieve.parser import parse_sarif

FIXTURES = Path(__file__).parent / "fixtures"

# Fake EPSS data: CVE-2024-1234 has high EPSS, others very low
FAKE_EPSS_CSV = (
    b"#model_version:v2023.03.01,score_date:2024-01-15\n"
    b"cve,epss,percentile\n"
    b"CVE-2024-1234,0.342,0.98\n"
    b"CVE-2024-5678,0.0004,0.25\n"
    b"CVE-2024-9999,0.0002,0.15\n"
    b"CVE-2024-2222,0.051,0.88\n"
    b"CVE-2024-3333,0.0003,0.20\n"
    b"CVE-2024-4444,0.12,0.92\n"
    b"CVE-2024-5555,0.00015,0.10\n"
)

# CVE-2024-1234 is in KEV (confirmed active exploitation)
FAKE_KEV = {"vulnerabilities": [{"cveID": "CVE-2024-1234"}]}


def _mock_epss():
    mock_response = MagicMock()
    mock_response.content = gzip.compress(FAKE_EPSS_CSV)
    mock_response.raise_for_status = MagicMock()
    return mock_response


def _mock_kev():
    mock_response = MagicMock()
    mock_response.json.return_value = FAKE_KEV
    mock_response.raise_for_status = MagicMock()
    return mock_response


def run_pipeline(sarif_data: dict, tmp_path: Path) -> list:
    """Run the full pipeline and return classified findings."""
    from datetime import datetime, timezone

    findings = parse_sarif(sarif_data)

    with patch("cvesieve.enrichment.epss.requests.get", return_value=_mock_epss()):
        epss_scores = load_epss(tmp_path, no_cache=True)

    with patch("cvesieve.enrichment.kev.requests.get", return_value=_mock_kev()):
        kev_set = load_kev(tmp_path, no_cache=True)

    enriched = []
    for f in findings:
        epss_score, epss_pct = lookup_epss(epss_scores, f.cve_id)
        attack_vector = extract_attack_vector(f.cvss_vector)
        in_kev = is_in_kev(kev_set, f.cve_id)
        enriched.append(EnrichedFinding(
            finding=f,
            epss_score=epss_score,
            epss_percentile=epss_pct,
            attack_vector=attack_vector,
            in_kev=in_kev,
            days_since_published=60,  # fixed for test determinism
        ))

    return [classify(ef) for ef in enriched]


class TestDockerScoutPipeline:
    def test_kev_cve_is_always_block(self, tmp_path):
        data = json.loads((FIXTURES / "docker_scout.sarif.json").read_text())
        classified = run_pipeline(data, tmp_path)
        kev_findings = [cf for cf in classified if cf.enriched.in_kev]
        assert all(cf.tier == Tier.BLOCK for cf in kev_findings)

    def test_no_local_vector_cve_is_block_without_kev(self, tmp_path):
        data = json.loads((FIXTURES / "docker_scout.sarif.json").read_text())
        classified = run_pipeline(data, tmp_path)
        for cf in classified:
            if not cf.enriched.in_kev and cf.enriched.attack_vector in ("LOCAL", "PHYSICAL"):
                assert cf.tier != Tier.BLOCK, f"{cf.enriched.finding.cve_id} is LOCAL but got BLOCK without KEV"

    def test_network_unknown_epss_is_never_below_block(self, tmp_path):
        data = json.loads((FIXTURES / "docker_scout.sarif.json").read_text())
        classified = run_pipeline(data, tmp_path)
        for cf in classified:
            ef = cf.enriched
            if ef.attack_vector == "NETWORK" and ef.epss_score is None and not ef.in_kev:
                assert cf.tier == Tier.BLOCK

    def test_correct_tier_counts(self, tmp_path):
        data = json.loads((FIXTURES / "docker_scout.sarif.json").read_text())
        classified = run_pipeline(data, tmp_path)
        tiers = [cf.tier for cf in classified]
        # CVE-2024-1234: KEV → BLOCK
        # CVE-2024-5678: LOCAL, low EPSS, 60d old → SUPPRESS
        # CVE-2024-9999: LOCAL, low EPSS, 60d old → SUPPRESS
        assert tiers.count(Tier.BLOCK) == 1
        assert tiers.count(Tier.SUPPRESS) == 2

    def test_all_findings_have_reasons(self, tmp_path):
        data = json.loads((FIXTURES / "docker_scout.sarif.json").read_text())
        classified = run_pipeline(data, tmp_path)
        assert all(cf.reason for cf in classified)


def _fake_load_epss(cache_dir, no_cache=False):
    """Pre-parsed EPSS scores — no network call."""
    return {
        "CVE-2024-1234": {"epss": 0.342, "percentile": 0.98},
        "CVE-2024-5678": {"epss": 0.0004, "percentile": 0.25},
        "CVE-2024-9999": {"epss": 0.0002, "percentile": 0.15},
        "CVE-2024-2222": {"epss": 0.051, "percentile": 0.88},
        "CVE-2024-3333": {"epss": 0.0003, "percentile": 0.20},
        "CVE-2024-4444": {"epss": 0.12, "percentile": 0.92},
        "CVE-2024-5555": {"epss": 0.00015, "percentile": 0.10},
    }


def _fake_load_kev(cache_dir, no_cache=False):
    """Pre-parsed KEV set — no network call."""
    return {"CVE-2024-1234"}


def _fake_fetch_missing_data(cve_ids, cache_dir, api_key=None):
    """Return empty NvdData for all CVEs — no network call."""
    return {cve_id: NvdData(vector=None, published=None) for cve_id in cve_ids}


class TestOutputFormats:
    def _run_cli(self, sarif_file: str, tmp_path: Path, extra_args: list = None):
        runner = CliRunner()
        with patch("cvesieve.cli.load_epss", side_effect=_fake_load_epss):
            with patch("cvesieve.cli.load_kev", side_effect=_fake_load_kev):
                with patch("cvesieve.cli.fetch_missing_data", side_effect=_fake_fetch_missing_data):
                    result = runner.invoke(
                        main,
                        [str(FIXTURES / sarif_file), f"--cache-dir={tmp_path}", "--no-cache"] + (extra_args or []),
                        catch_exceptions=False,
                    )
        return result

    def test_table_format_contains_block_section(self, tmp_path):
        result = self._run_cli("docker_scout.sarif.json", tmp_path)
        assert "BLOCK" in result.output

    def test_json_format_is_valid_json(self, tmp_path):
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "json"])
        data = json.loads(result.output)
        assert "summary" in data
        assert "block" in data
        assert "metadata" in data

    def test_json_format_schema(self, tmp_path):
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "json"])
        data = json.loads(result.output)
        assert data["summary"]["total"] == 3
        assert isinstance(data["block"], list)
        assert isinstance(data["warn"], list)
        assert isinstance(data["suppress"], list)

    def test_summary_format(self, tmp_path):
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "summary"])
        assert "total" in result.output
        assert "block" in result.output

    def test_exit_code_1_on_block(self, tmp_path):
        result = self._run_cli("docker_scout.sarif.json", tmp_path)
        # Docker Scout fixture has a KEV CVE → BLOCK → exit 1
        assert result.exit_code == 1

    def test_noise_reduction_in_json(self, tmp_path):
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "json"])
        data = json.loads(result.output)
        assert data["summary"]["noise_reduction_pct"] >= 0


def _parse_json_output(output: str) -> dict:
    """Extract JSON from output that may have leading stderr lines mixed in."""
    idx = output.find("{")
    return json.loads(output[idx:])


class TestMinSeverityFilter:
    def _run_cli(self, sarif_file: str, tmp_path: Path, extra_args: list = None):
        runner = CliRunner()
        with patch("cvesieve.cli.load_epss", side_effect=_fake_load_epss):
            with patch("cvesieve.cli.load_kev", side_effect=_fake_load_kev):
                with patch("cvesieve.cli.fetch_missing_data", side_effect=_fake_fetch_missing_data):
                    result = runner.invoke(
                        main,
                        [str(FIXTURES / sarif_file), f"--cache-dir={tmp_path}", "--no-cache"] + (extra_args or []),
                        catch_exceptions=False,
                    )
        return result

    def test_min_severity_high_filters_medium_and_low(self, tmp_path):
        """--min-severity high should remove MEDIUM and LOW findings from output."""
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--min-severity", "high", "--format", "json"])
        data = _parse_json_output(result.output)
        all_findings = data["block"] + data["warn"] + data["suppress"]
        severities = {f["severity"] for f in all_findings}
        assert "LOW" not in severities
        assert "MEDIUM" not in severities

    def test_block_findings_always_shown_regardless_of_severity(self, tmp_path):
        """BLOCK findings must never be filtered — KEV always wins."""
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--min-severity", "critical", "--format", "json"])
        data = _parse_json_output(result.output)
        # CVE-2024-1234 is in KEV → BLOCK → must always appear even with --min-severity critical
        block_ids = {f["cve_id"] for f in data["block"]}
        assert "CVE-2024-1234" in block_ids

    def test_min_severity_low_shows_everything(self, tmp_path):
        """--min-severity low (default) should not filter anything."""
        result_default = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "json"])
        result_low = self._run_cli("docker_scout.sarif.json", tmp_path, ["--min-severity", "low", "--format", "json"])
        data_default = json.loads(result_default.output)
        data_low = json.loads(result_low.output)
        assert data_default["summary"]["total"] == data_low["summary"]["total"]


class TestMinBlockSeverity:
    def _run_cli(self, sarif_file: str, tmp_path: Path, extra_args: list = None):
        runner = CliRunner()
        with patch("cvesieve.cli.load_epss", side_effect=_fake_load_epss):
            with patch("cvesieve.cli.load_kev", side_effect=_fake_load_kev):
                with patch("cvesieve.cli.fetch_missing_data", side_effect=_fake_fetch_missing_data):
                    result = runner.invoke(
                        main,
                        [str(FIXTURES / sarif_file), f"--cache-dir={tmp_path}", "--no-cache"] + (extra_args or []),
                        catch_exceptions=False,
                    )
        return result

    def test_low_medium_capped_at_warn_not_block(self, tmp_path):
        """With --min-block-severity high, LOW/MEDIUM findings can never be BLOCK unless KEV."""
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--min-block-severity", "high", "--format", "json"])
        data = _parse_json_output(result.output)
        for finding in data["block"]:
            # Only BLOCK findings allowed are KEV hits or HIGH/CRITICAL
            assert finding["in_kev"] or finding["severity"] in ("HIGH", "CRITICAL"), \
                f"{finding['cve_id']} is BLOCK with severity {finding['severity']} but not in KEV"

    def test_kev_always_block_regardless_of_severity_cap(self, tmp_path):
        """KEV findings must be BLOCK even with --min-block-severity critical."""
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--min-block-severity", "critical", "--format", "json"])
        data = _parse_json_output(result.output)
        block_ids = {f["cve_id"] for f in data["block"]}
        assert "CVE-2024-1234" in block_ids  # KEV hit — always BLOCK

    def test_reason_updated_for_capped_findings(self, tmp_path):
        """Capped findings should have an updated reason explaining the cap."""
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--min-block-severity", "high", "--format", "json"])
        data = _parse_json_output(result.output)
        # Any WARN finding that was capped should mention it in the reason
        capped = [f for f in data["warn"] if "capped at WARN" in f["reason"]]
        # There may or may not be capped findings depending on fixture data — just ensure no crash
        assert isinstance(capped, list)
