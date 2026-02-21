"""Tests for NVD CVSS vector/published date lookup and PURL parsing."""
import json
import time
from unittest.mock import MagicMock, patch

import pytest

from cvesieve.enrichment.nvd import NvdData, fetch_missing_data
from cvesieve.parser import _parse_purl, parse_sarif


# ── PURL parsing ──────────────────────────────────────────────────────────────

class TestParsePurl:
    def test_debian_package(self):
        purl = "pkg:deb/debian/tar@1.35%2Bdfsg-3.1?os_distro=trixie&os_name=debian"
        name, version = _parse_purl(purl)
        assert name == "tar"
        assert version == "1.35+dfsg-3.1"

    def test_npm_package(self):
        purl = "pkg:npm/lodash@4.17.21"
        name, version = _parse_purl(purl)
        assert name == "lodash"
        assert version == "4.17.21"

    def test_no_version(self):
        purl = "pkg:deb/debian/tar"
        name, version = _parse_purl(purl)
        assert name == "tar"
        assert version == ""

    def test_invalid_purl(self):
        name, version = _parse_purl("not-a-purl")
        assert isinstance(name, str)


class TestDockerScoutSarifParsing:
    def _make_docker_scout_sarif(self, cve_id="CVE-2024-1234", severity="LOW", purl="pkg:deb/debian/tar@1.35%2Bdfsg-3.1"):
        return {
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "docker scout",
                        "rules": [{
                            "id": cve_id,
                            "shortDescription": {"text": "Test CVE"},
                            "properties": {
                                "cvssV3_severity": severity,
                                "security-severity": "3.1",
                                "purls": [purl],
                                "fixed_version": "not fixed",
                            }
                        }]
                    }
                },
                "results": [{
                    "ruleId": cve_id,
                    "level": "note",
                    "message": {"text": "Test message"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "Dockerfile"}
                        }
                    }]
                }]
            }]
        }

    def test_package_name_from_purl(self):
        data = self._make_docker_scout_sarif()
        findings = parse_sarif(data)
        assert len(findings) == 1
        assert findings[0].package_name == "tar"
        assert findings[0].installed_version == "1.35+dfsg-3.1"

    def test_no_cvss_vector_is_none(self):
        data = self._make_docker_scout_sarif()
        findings = parse_sarif(data)
        assert findings[0].cvss_vector is None

    def test_severity_extracted(self):
        data = self._make_docker_scout_sarif(severity="CRITICAL")
        findings = parse_sarif(data)
        assert findings[0].severity == "CRITICAL"

    def test_scanner_name(self):
        data = self._make_docker_scout_sarif()
        findings = parse_sarif(data)
        assert findings[0].scanner == "docker scout"


# ── NVD lookup ────────────────────────────────────────────────────────────────

def _make_nvd_response(cve_id: str, vector: str, published: str = "2024-01-15T10:15:00.000") -> dict:
    return {
        "vulnerabilities": [{
            "cve": {
                "id": cve_id,
                "published": published,
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"vectorString": vector}
                    }]
                }
            }
        }]
    }


class TestNvdLookup:
    def test_fetches_vector_and_published_date(self, tmp_path):
        vector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        published = "2024-01-15T10:15:00.000"
        mock_response = MagicMock()
        mock_response.json.return_value = _make_nvd_response("CVE-2024-1234", vector, published)
        mock_response.raise_for_status = MagicMock()

        with patch("cvesieve.enrichment.nvd.requests.get", return_value=mock_response):
            with patch("cvesieve.enrichment.nvd.time.sleep"):
                result = fetch_missing_data(["CVE-2024-1234"], tmp_path)

        assert result["CVE-2024-1234"].vector == vector
        assert result["CVE-2024-1234"].published == published

    def test_uses_cache_on_second_call(self, tmp_path):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        cache = {"CVE-2024-1234": {"vector": vector, "published": "2024-01-15T10:15:00.000"}}
        (tmp_path / "nvd_cvss.json").write_text(json.dumps(cache))

        with patch("cvesieve.enrichment.nvd.requests.get") as mock_get:
            result = fetch_missing_data(["CVE-2024-1234"], tmp_path)
            mock_get.assert_not_called()

        assert result["CVE-2024-1234"].vector == vector

    def test_migrates_old_cache_format(self, tmp_path):
        """Old cache stored just a vector string — should migrate gracefully."""
        old_cache = {"CVE-2024-1234": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        (tmp_path / "nvd_cvss.json").write_text(json.dumps(old_cache))

        with patch("cvesieve.enrichment.nvd.requests.get") as mock_get:
            result = fetch_missing_data(["CVE-2024-1234"], tmp_path)
            mock_get.assert_not_called()

        assert result["CVE-2024-1234"].vector == old_cache["CVE-2024-1234"]
        assert result["CVE-2024-1234"].published is None

    def test_caches_none_for_unknown_cve(self, tmp_path):
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_response.raise_for_status = MagicMock()

        with patch("cvesieve.enrichment.nvd.requests.get", return_value=mock_response):
            with patch("cvesieve.enrichment.nvd.time.sleep"):
                result = fetch_missing_data(["CVE-9999-9999"], tmp_path)

        assert result["CVE-9999-9999"].vector is None
        assert result["CVE-9999-9999"].published is None
        cache = json.loads((tmp_path / "nvd_cvss.json").read_text())
        assert "CVE-9999-9999" in cache

    def test_returns_none_on_network_failure(self, tmp_path):
        with patch("cvesieve.enrichment.nvd.requests.get", side_effect=Exception("network error")):
            with patch("cvesieve.enrichment.nvd.time.sleep"):
                result = fetch_missing_data(["CVE-2024-1234"], tmp_path)

        # Result is still returned as NvdData(None, None) for the caller
        assert result["CVE-2024-1234"].vector is None
        assert result["CVE-2024-1234"].published is None
        # But it must NOT be cached — so next run will retry
        cache_file = tmp_path / "nvd_cvss.json"
        if cache_file.exists():
            cache = json.loads(cache_file.read_text())
            assert "CVE-2024-1234" not in cache

    def test_prefers_v31_over_v2(self, tmp_path):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "published": "2024-01-15T10:15:00.000",
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
                        "cvssMetricV2": [{"cvssData": {"vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}],
                    }
                }
            }]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("cvesieve.enrichment.nvd.requests.get", return_value=mock_response):
            with patch("cvesieve.enrichment.nvd.time.sleep"):
                result = fetch_missing_data(["CVE-2024-1234"], tmp_path)

        assert result["CVE-2024-1234"].vector.startswith("CVSS:3.1")

    def test_uses_api_key_in_header(self, tmp_path):
        mock_response = MagicMock()
        mock_response.json.return_value = _make_nvd_response("CVE-2024-1234", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        mock_response.raise_for_status = MagicMock()

        with patch("cvesieve.enrichment.nvd.requests.get", return_value=mock_response) as mock_get:
            with patch("cvesieve.enrichment.nvd.time.sleep"):
                fetch_missing_data(["CVE-2024-1234"], tmp_path, api_key="test-key-123")

        call_kwargs = mock_get.call_args
        assert call_kwargs.kwargs["headers"]["apiKey"] == "test-key-123"
