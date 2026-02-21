"""Tests for the SARIF parser."""
import json
from pathlib import Path

import pytest

from cvesieve.parser import parse_sarif

FIXTURES = Path(__file__).parent / "fixtures"


class TestDockerScout:
    def test_parses_correct_count(self):
        data = json.loads((FIXTURES / "docker_scout.sarif.json").read_text())
        findings = parse_sarif(data)
        assert len(findings) == 3

    def test_scanner_name(self):
        data = json.loads((FIXTURES / "docker_scout.sarif.json").read_text())
        findings = parse_sarif(data)
        assert all(f.scanner == "docker scout" for f in findings)

    def test_cve_ids(self):
        data = json.loads((FIXTURES / "docker_scout.sarif.json").read_text())
        ids = {f.cve_id for f in parse_sarif(data)}
        assert ids == {"CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9999"}

    def test_package_extraction(self):
        data = json.loads((FIXTURES / "docker_scout.sarif.json").read_text())
        findings = {f.cve_id: f for f in parse_sarif(data)}
        assert findings["CVE-2024-1234"].package_name == "openssl"
        assert findings["CVE-2024-1234"].installed_version == "1.1.1k"

    def test_cvss_vector_extracted(self):
        data = json.loads((FIXTURES / "docker_scout.sarif.json").read_text())
        findings = {f.cve_id: f for f in parse_sarif(data)}
        assert findings["CVE-2024-1234"].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_severity_extracted(self):
        data = json.loads((FIXTURES / "docker_scout.sarif.json").read_text())
        findings = {f.cve_id: f for f in parse_sarif(data)}
        assert findings["CVE-2024-1234"].severity == "CRITICAL"


class TestTrivy:
    def test_parses_correct_count(self):
        data = json.loads((FIXTURES / "trivy.sarif.json").read_text())
        findings = parse_sarif(data)
        assert len(findings) == 2

    def test_scanner_name(self):
        data = json.loads((FIXTURES / "trivy.sarif.json").read_text())
        findings = parse_sarif(data)
        assert all(f.scanner == "Trivy" for f in findings)

    def test_cvss_vector_extracted(self):
        data = json.loads((FIXTURES / "trivy.sarif.json").read_text())
        findings = {f.cve_id: f for f in parse_sarif(data)}
        assert "AV:N" in findings["CVE-2024-2222"].cvss_vector


class TestGrype:
    def test_parses_correct_count(self):
        data = json.loads((FIXTURES / "grype.sarif.json").read_text())
        findings = parse_sarif(data)
        assert len(findings) == 2

    def test_scanner_name(self):
        data = json.loads((FIXTURES / "grype.sarif.json").read_text())
        findings = parse_sarif(data)
        assert all(f.scanner == "grype" for f in findings)


class TestErrorHandling:
    def test_invalid_json_structure(self):
        with pytest.raises(ValueError, match="not valid SARIF"):
            parse_sarif({"not": "sarif"})

    def test_empty_runs(self):
        data = {"version": "2.1.0", "runs": []}
        findings = parse_sarif(data)
        assert findings == []

    def test_missing_optional_fields_does_not_crash(self):
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test", "rules": [
                        {"id": "CVE-2024-0001", "properties": {}}
                    ]}},
                    "results": [
                        {
                            "ruleId": "CVE-2024-0001",
                            "level": "error",
                            "message": {"text": "test"},
                            "locations": [
                                {"logicalLocations": [{"name": "pkg", "fullyQualifiedName": "pkg@1.0"}]}
                            ]
                        }
                    ]
                }
            ]
        }
        findings = parse_sarif(data)
        assert len(findings) == 1
        assert findings[0].cvss_vector is None
        assert findings[0].published_date is None

    def test_deduplicates_by_cve_id(self):
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test", "rules": [
                        {"id": "CVE-2024-0001", "properties": {"cvssV3_severity": "HIGH"}}
                    ]}},
                    "results": [
                        {
                            "ruleId": "CVE-2024-0001",
                            "level": "error",
                            "message": {"text": "pkg-a"},
                            "locations": [{"logicalLocations": [{"name": "pkg-a", "fullyQualifiedName": "pkg-a@1.0"}]}]
                        },
                        {
                            "ruleId": "CVE-2024-0001",
                            "level": "error",
                            "message": {"text": "pkg-b"},
                            "locations": [{"logicalLocations": [{"name": "pkg-b", "fullyQualifiedName": "pkg-b@2.0"}]}]
                        }
                    ]
                }
            ]
        }
        findings = parse_sarif(data)
        assert len(findings) == 1
