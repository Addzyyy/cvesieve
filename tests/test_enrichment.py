"""Tests for enrichment modules — all network calls are mocked."""
import gzip
import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cvesieve.enrichment.cvss import extract_attack_vector, extract_scope
from cvesieve.enrichment.epss import load_epss, lookup_epss
from cvesieve.enrichment.kev import is_in_kev, load_kev


# ── cvss.py ──────────────────────────────────────────────────────────────────

class TestExtractAttackVector:
    def test_network(self):
        assert extract_attack_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "NETWORK"

    def test_adjacent(self):
        assert extract_attack_vector("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "ADJACENT"

    def test_local(self):
        assert extract_attack_vector("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == "LOCAL"

    def test_physical(self):
        assert extract_attack_vector("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "PHYSICAL"

    def test_cvss_v2_network(self):
        assert extract_attack_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P") == "NETWORK"

    def test_none_input(self):
        assert extract_attack_vector(None) is None

    def test_empty_string(self):
        assert extract_attack_vector("") is None

    def test_no_av_component(self):
        assert extract_attack_vector("CVSS:3.1/AC:L/PR:N") is None

    def test_unknown_av_code(self):
        assert extract_attack_vector("CVSS:3.1/AV:X/AC:L") is None


class TestExtractScope:
    def test_scope_changed(self):
        assert extract_scope("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == "CHANGED"

    def test_scope_unchanged(self):
        assert extract_scope("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "UNCHANGED"

    def test_none_input(self):
        assert extract_scope(None) is None

    def test_cvss_v2_returns_none(self):
        """CVSS v2 has no Scope field — always returns None."""
        assert extract_scope("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None

    def test_missing_scope_component(self):
        assert extract_scope("CVSS:3.1/AV:N/AC:L/PR:N") is None

    def test_unknown_scope_code(self):
        assert extract_scope("CVSS:3.1/AV:N/S:X/C:H") is None


# ── epss.py ──────────────────────────────────────────────────────────────────

SAMPLE_CSV = b"#model_version:v2023.03.01,score_date:2024-01-15\ncve,epss,percentile\nCVE-2024-1234,0.05123,0.95\nCVE-2024-5678,0.00042,0.30\n"


class TestEpss:
    def test_lookup_found(self):
        scores = {"CVE-2024-1234": {"epss": 0.05123, "percentile": 0.95}}
        epss, pct = lookup_epss(scores, "CVE-2024-1234")
        assert epss == pytest.approx(0.05123)
        assert pct == pytest.approx(0.95)

    def test_lookup_not_found(self):
        epss, pct = lookup_epss({}, "CVE-9999-9999")
        assert epss is None
        assert pct is None

    def test_download_and_parse(self, tmp_path):
        mock_response = MagicMock()
        mock_response.content = gzip.compress(SAMPLE_CSV)
        mock_response.raise_for_status = MagicMock()

        with patch("cvesieve.enrichment.epss.requests.get", return_value=mock_response):
            scores = load_epss(tmp_path, no_cache=True)

        assert "CVE-2024-1234" in scores
        assert scores["CVE-2024-1234"]["epss"] == pytest.approx(0.05123)
        assert "CVE-2024-5678" in scores

    def test_uses_cache_when_fresh(self, tmp_path):
        # Write a fresh cache
        payload = {
            "timestamp": time.time(),
            "scores": {"CVE-2024-1234": {"epss": 0.05, "percentile": 0.9}},
        }
        (tmp_path / "epss.json").write_text(json.dumps(payload))

        with patch("cvesieve.enrichment.epss.requests.get") as mock_get:
            scores = load_epss(tmp_path)
            mock_get.assert_not_called()

        assert "CVE-2024-1234" in scores

    def test_re_downloads_stale_cache(self, tmp_path):
        # Write a stale cache (25 hours old)
        payload = {
            "timestamp": time.time() - 90000,
            "scores": {},
        }
        (tmp_path / "epss.json").write_text(json.dumps(payload))

        mock_response = MagicMock()
        mock_response.content = gzip.compress(SAMPLE_CSV)
        mock_response.raise_for_status = MagicMock()

        with patch("cvesieve.enrichment.epss.requests.get", return_value=mock_response):
            load_epss(tmp_path)

        # Should have re-downloaded
        mock_response.raise_for_status.assert_called()

    def test_returns_empty_dict_on_download_failure(self, tmp_path):
        with patch("cvesieve.enrichment.epss.requests.get", side_effect=Exception("network error")):
            scores = load_epss(tmp_path, no_cache=True)
        assert scores == {}


# ── kev.py ───────────────────────────────────────────────────────────────────

SAMPLE_KEV = {
    "vulnerabilities": [
        {"cveID": "CVE-2024-1234"},
        {"cveID": "CVE-2021-44228"},
    ]
}


class TestKev:
    def test_is_in_kev(self):
        kev_set = {"CVE-2024-1234", "CVE-2021-44228"}
        assert is_in_kev(kev_set, "CVE-2024-1234") is True

    def test_not_in_kev(self):
        kev_set = {"CVE-2024-1234"}
        assert is_in_kev(kev_set, "CVE-9999-9999") is False

    def test_empty_set(self):
        assert is_in_kev(set(), "CVE-2024-1234") is False

    def test_download_and_parse(self, tmp_path):
        mock_response = MagicMock()
        mock_response.json.return_value = SAMPLE_KEV
        mock_response.raise_for_status = MagicMock()

        with patch("cvesieve.enrichment.kev.requests.get", return_value=mock_response):
            kev_set = load_kev(tmp_path, no_cache=True)

        assert "CVE-2024-1234" in kev_set
        assert "CVE-2021-44228" in kev_set

    def test_uses_cache_when_fresh(self, tmp_path):
        payload = {
            "timestamp": time.time(),
            "cve_ids": ["CVE-2024-1234"],
        }
        (tmp_path / "kev.json").write_text(json.dumps(payload))

        with patch("cvesieve.enrichment.kev.requests.get") as mock_get:
            kev_set = load_kev(tmp_path)
            mock_get.assert_not_called()

        assert "CVE-2024-1234" in kev_set

    def test_returns_empty_set_on_download_failure(self, tmp_path):
        with patch("cvesieve.enrichment.kev.requests.get", side_effect=Exception("network error")):
            kev_set = load_kev(tmp_path, no_cache=True)
        assert kev_set == set()
