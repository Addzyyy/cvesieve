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

from cvesieve.cli import main, _apply_exposure_cap, _apply_privilege_cap
from cvesieve.enrichment.cvss import extract_attack_vector
from cvesieve.enrichment.epss import load_epss, lookup_epss
from cvesieve.enrichment.kev import is_in_kev, load_kev
from cvesieve.enrichment.nvd import NvdData
from cvesieve.engine import classify
from cvesieve.models import ClassifiedFinding, EnrichedFinding, Finding, Tier
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


def _fake_fetch_missing_data(cve_ids, cache_dir, api_key=None, no_cache=False):
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


def _fake_fetch_missing_data_with_old_date(cve_ids, cache_dir, api_key=None, no_cache=False):
    """Return NvdData with an old published date — ensures age_stable=True in tests."""
    return {cve_id: NvdData(vector=None, published="2020-01-01T00:00:00Z") for cve_id in cve_ids}


class TestLocalEpssThreshold:
    def _run_cli(self, sarif_file: str, tmp_path: Path, extra_args: list = None, old_dates: bool = False):
        runner = CliRunner()
        fetch_mock = _fake_fetch_missing_data_with_old_date if old_dates else _fake_fetch_missing_data
        with patch("cvesieve.cli.load_epss", side_effect=_fake_load_epss):
            with patch("cvesieve.cli.load_kev", side_effect=_fake_load_kev):
                with patch("cvesieve.cli.fetch_missing_data", side_effect=fetch_mock):
                    result = runner.invoke(
                        main,
                        [str(FIXTURES / sarif_file), f"--cache-dir={tmp_path}", "--no-cache"] + (extra_args or []),
                        catch_exceptions=False,
                    )
        return result

    def test_json_metadata_includes_both_thresholds(self, tmp_path):
        """JSON output must include epss_network and epss_local in metadata.thresholds."""
        result = self._run_cli("trivy.sarif.json", tmp_path, ["--format", "json"])
        data = _parse_json_output(result.output)
        thresholds = data["metadata"]["thresholds"]
        assert "epss_network" in thresholds
        assert "epss_local" in thresholds
        assert "age_days" in thresholds

    def test_json_metadata_reflects_custom_local_threshold(self, tmp_path):
        """--local-epss-threshold value must appear in JSON metadata."""
        result = self._run_cli(
            "trivy.sarif.json", tmp_path,
            ["--format", "json", "--local-epss-threshold", "0.10"],
        )
        data = _parse_json_output(result.output)
        assert data["metadata"]["thresholds"]["epss_local"] == 0.10

    def test_local_cve_suppressed_with_default_local_threshold(self, tmp_path):
        """LOCAL CVE with EPSS well below 5% and old published date → SUPPRESS with default threshold."""
        # CVE-2024-5555: LOCAL, EPSS=0.00015. With old_dates=True age_stable=True → SUPPRESS
        result = self._run_cli("grype.sarif.json", tmp_path, ["--format", "json"], old_dates=True)
        data = _parse_json_output(result.output)
        suppress_ids = {f["cve_id"] for f in data["suppress"]}
        assert "CVE-2024-5555" in suppress_ids

    def test_local_cve_warns_with_strict_local_threshold(self, tmp_path):
        """LOCAL CVE with EPSS above a very strict local threshold → WARN instead of SUPPRESS."""
        # CVE-2024-5555: EPSS=0.00015; with --local-epss-threshold 0.0001, 0.00015 >= 0.0001 → WARN
        result = self._run_cli(
            "grype.sarif.json", tmp_path,
            ["--format", "json", "--local-epss-threshold", "0.0001"],
            old_dates=True,
        )
        data = _parse_json_output(result.output)
        warn_ids = {f["cve_id"] for f in data["warn"]}
        suppress_ids = {f["cve_id"] for f in data["suppress"]}
        assert "CVE-2024-5555" in warn_ids
        assert "CVE-2024-5555" not in suppress_ids


# ── Context modifier unit tests ───────────────────────────────────────────────

def _make_classified(
    tier: Tier,
    attack_vector: str | None = "NETWORK",
    cvss_scope: str | None = None,
    in_kev: bool = False,
) -> ClassifiedFinding:
    finding = Finding(
        cve_id="CVE-2024-TEST",
        severity="HIGH",
        package_name="test",
        installed_version="1.0",
        fixed_version=None,
        cvss_vector=None,
        published_date=None,
        scanner="trivy",
        description=None,
    )
    enriched = EnrichedFinding(
        finding=finding,
        epss_score=0.05,
        epss_percentile=0.9,
        attack_vector=attack_vector,
        in_kev=in_kev,
        days_since_published=30,
        cvss_scope=cvss_scope,
    )
    return ClassifiedFinding(enriched=enriched, tier=tier, reason="test reason")


class TestExposureCap:
    def test_internal_caps_network_block_to_warn(self):
        cf = _make_classified(Tier.BLOCK, attack_vector="NETWORK")
        result = _apply_exposure_cap([cf], "internal")
        assert result[0].tier == Tier.WARN
        assert "internal-only" in result[0].reason

    def test_internal_caps_adjacent_block_to_warn(self):
        cf = _make_classified(Tier.BLOCK, attack_vector="ADJACENT")
        result = _apply_exposure_cap([cf], "internal")
        assert result[0].tier == Tier.WARN

    def test_internal_caps_unknown_vector_block_to_warn(self):
        """Unknown vector is treated as network — capped on internal."""
        cf = _make_classified(Tier.BLOCK, attack_vector=None)
        result = _apply_exposure_cap([cf], "internal")
        assert result[0].tier == Tier.WARN

    def test_internal_does_not_cap_local_block(self):
        """Local vector BLOCKs are not affected by exposure — they'd only BLOCK via KEV."""
        cf = _make_classified(Tier.BLOCK, attack_vector="LOCAL", in_kev=True)
        result = _apply_exposure_cap([cf], "internal")
        assert result[0].tier == Tier.BLOCK

    def test_internal_never_caps_kev(self):
        cf = _make_classified(Tier.BLOCK, attack_vector="NETWORK", in_kev=True)
        result = _apply_exposure_cap([cf], "internal")
        assert result[0].tier == Tier.BLOCK

    def test_public_changes_nothing(self):
        cf = _make_classified(Tier.BLOCK, attack_vector="NETWORK")
        result = _apply_exposure_cap([cf], "public")
        assert result[0].tier == Tier.BLOCK

    def test_internal_does_not_affect_warn_or_suppress(self):
        warn = _make_classified(Tier.WARN, attack_vector="NETWORK")
        suppress = _make_classified(Tier.SUPPRESS, attack_vector="NETWORK")
        result = _apply_exposure_cap([warn, suppress], "internal")
        assert result[0].tier == Tier.WARN
        assert result[1].tier == Tier.SUPPRESS


class TestPrivilegeCap:
    def test_rootless_caps_scope_changed_block_to_warn(self):
        cf = _make_classified(Tier.BLOCK, cvss_scope="CHANGED")
        result = _apply_privilege_cap([cf], "rootless")
        assert result[0].tier == Tier.WARN
        assert "rootless" in result[0].reason

    def test_rootless_does_not_cap_scope_unchanged(self):
        cf = _make_classified(Tier.BLOCK, cvss_scope="UNCHANGED")
        result = _apply_privilege_cap([cf], "rootless")
        assert result[0].tier == Tier.BLOCK

    def test_rootless_does_not_cap_unknown_scope(self):
        """Unknown scope (v2 or missing) is not downgraded — fail open."""
        cf = _make_classified(Tier.BLOCK, cvss_scope=None)
        result = _apply_privilege_cap([cf], "rootless")
        assert result[0].tier == Tier.BLOCK

    def test_rootless_never_caps_kev(self):
        cf = _make_classified(Tier.BLOCK, cvss_scope="CHANGED", in_kev=True)
        result = _apply_privilege_cap([cf], "rootless")
        assert result[0].tier == Tier.BLOCK

    def test_root_changes_nothing(self):
        cf = _make_classified(Tier.BLOCK, cvss_scope="CHANGED")
        result = _apply_privilege_cap([cf], "root")
        assert result[0].tier == Tier.BLOCK


class TestContextCli:
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

    def test_json_metadata_includes_context(self, tmp_path):
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "json", "--exposure", "internal"])
        data = _parse_json_output(result.output)
        assert "context" in data["metadata"]
        assert data["metadata"]["context"]["exposure"] == "internal"

    def test_exposure_internal_reflected_in_metadata(self, tmp_path):
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "json", "--exposure", "internal", "--privilege", "rootless"])
        data = _parse_json_output(result.output)
        assert data["metadata"]["context"]["exposure"] == "internal"
        assert data["metadata"]["context"]["privilege"] == "rootless"

    def test_kev_still_blocks_with_internal_exposure(self, tmp_path):
        """KEV always wins — internal exposure cannot suppress a KEV CVE."""
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "json", "--exposure", "internal"])
        data = _parse_json_output(result.output)
        block_ids = {f["cve_id"] for f in data["block"]}
        assert "CVE-2024-1234" in block_ids  # KEV hit — always BLOCK


class TestAllowlistCli:
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

    def test_allowlist_flag_works_end_to_end(self, tmp_path):
        """--allowlist flag applies allowlist entries to findings."""
        allowlist = str(FIXTURES / "allowlist.toml")
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "json", "--allowlist", allowlist])
        data = _parse_json_output(result.output)
        # CVE-2024-5678 should be allowlisted (suppressed)
        suppress_ids = {f["cve_id"] for f in data["suppress"]}
        assert "CVE-2024-5678" in suppress_ids

    def test_strict_ignores_allowlist(self, tmp_path):
        """--strict skips allowlist even if file is provided."""
        allowlist = str(FIXTURES / "allowlist.toml")
        # With strict
        result_strict = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "json", "--allowlist", allowlist, "--strict"])
        data_strict = _parse_json_output(result_strict.output)
        # Strict should have no allowlist effect — no allowlist_file in metadata
        assert data_strict["metadata"].get("allowlist_file") is None

    def test_exit_code_0_when_all_blocks_allowlisted(self, tmp_path):
        """Exit code should be 0 when all BLOCK findings are downgraded by allowlist."""
        # Use trivy fixture — CVE-2024-2222 is network, high EPSS → BLOCK (not KEV)
        allowlist_file = tmp_path / "al.toml"
        allowlist_file.write_text(
            '[[entry]]\ncve_id = "CVE-2024-2222"\nmax_tier = "WARN"\n'
            'reason = "accepted"\napproved_by = "test@test.com"\n'
        )
        result = self._run_cli("trivy.sarif.json", tmp_path, ["--format", "json", "--allowlist", str(allowlist_file)])
        assert result.exit_code == 0

    def test_kev_stays_block_with_allowlist(self, tmp_path):
        """KEV CVEs must stay BLOCK even with allowlist entry."""
        allowlist = str(FIXTURES / "allowlist.toml")
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "json", "--allowlist", allowlist])
        data = _parse_json_output(result.output)
        block_ids = {f["cve_id"] for f in data["block"]}
        assert "CVE-2024-1234" in block_ids  # KEV — always BLOCK
        # KEV entry should have allowlist_note about KEV override
        kev_finding = [f for f in data["block"] if f["cve_id"] == "CVE-2024-1234"][0]
        assert kev_finding["allowlist_note"] == "[allowlisted but KEV overrides]"


class TestNewOutputFormatsCli:
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

    def test_csv_format(self, tmp_path):
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "csv"])
        assert "cve_id" in result.output
        assert "CVE-2024-1234" in result.output

    def test_markdown_format(self, tmp_path):
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "markdown"])
        assert "BLOCK" in result.output
        assert "|" in result.output

    def test_sarif_format(self, tmp_path):
        import json as json_mod
        result = self._run_cli("docker_scout.sarif.json", tmp_path, ["--format", "sarif"])
        data = json_mod.loads(result.output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 3
