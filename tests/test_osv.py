"""Tests for OSV database client — hydration and CVSS parsing."""

from unittest.mock import patch, MagicMock

from repo_security_scanner.vulndb.osv import OSVDatabase
from repo_security_scanner.models import Dependency, Ecosystem, Severity


class TestCVSSParsing:
    def setup_method(self):
        self.db = OSVDatabase()

    def test_plain_float(self):
        assert self.db._extract_cvss_score("7.5") == 7.5

    def test_plain_float_critical(self):
        assert self.db._extract_cvss_score("9.8") == 9.8

    def test_garbage_returns_none(self):
        assert self.db._extract_cvss_score("not_a_score") is None

    def test_empty_returns_none(self):
        assert self.db._extract_cvss_score("") is None

    def test_cvss_v31_high(self):
        # AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H -> should be ~7.5 HIGH
        score = self.db._extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
        assert score is not None
        assert 7.0 <= score <= 8.0

    def test_cvss_v31_critical(self):
        # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H -> should be 10.0 CRITICAL
        score = self.db._extract_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score is not None
        assert score == 10.0

    def test_cvss_v31_low(self):
        # AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N -> should be LOW
        score = self.db._extract_cvss_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
        assert score is not None
        assert score < 4.0

    def test_cvss_v30_works(self):
        score = self.db._extract_cvss_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        assert score is not None
        assert score >= 7.0

    def test_cvss_v2_returns_none(self):
        assert self.db._extract_cvss_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None

    def test_severity_from_cvss(self):
        vuln = {
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]
        }
        assert self.db._extract_severity(vuln) == Severity.CRITICAL

    def test_severity_from_database_specific(self):
        vuln = {"database_specific": {"severity": "HIGH"}}
        assert self.db._extract_severity(vuln) == Severity.HIGH

    def test_severity_database_specific_takes_priority(self):
        vuln = {
            "database_specific": {"severity": "CRITICAL"},
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}],
        }
        assert self.db._extract_severity(vuln) == Severity.CRITICAL


class TestHydration:
    def test_hydrate_fetches_full_details(self):
        db = OSVDatabase()
        stubs = [{"id": "GHSA-test-1234", "modified": "2026-01-01T00:00:00Z"}]

        full_vuln = {
            "id": "GHSA-test-1234",
            "summary": "Test vulnerability description",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}],
            "references": [{"url": "https://example.com/advisory"}],
            "database_specific": {"severity": "HIGH"},
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = full_vuln
        mock_response.raise_for_status = MagicMock()

        with patch("repo_security_scanner.vulndb.osv.requests.get", return_value=mock_response) as mock_get:
            result = db._hydrate_vulns(stubs)
            mock_get.assert_called_once()
            assert len(result) == 1
            assert result[0]["summary"] == "Test vulnerability description"
            assert result[0]["database_specific"]["severity"] == "HIGH"

    def test_hydrate_handles_empty_stubs(self):
        db = OSVDatabase()
        result = db._hydrate_vulns([])
        assert result == []

    def test_hydrate_returns_empty_on_failure(self):
        db = OSVDatabase()
        stubs = [{"id": "GHSA-fail"}]

        with patch("repo_security_scanner.vulndb.osv.requests.get", side_effect=Exception("Network error")):
            result = db._hydrate_vulns(stubs)
            assert result == []  # Returns empty, not stubs with incomplete data

    def test_parse_vulns_with_hydrated_data(self):
        db = OSVDatabase()
        hydrated = [{
            "id": "GHSA-8cf7-32gw-wr33",
            "summary": "jsonwebtoken unrestricted key type could lead to legacy keys usage",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"}],
            "affected": [{
                "package": {"name": "jsonwebtoken", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.0.0"}]}],
            }],
            "references": [{"url": "https://github.com/advisories/GHSA-8cf7-32gw-wr33"}],
            "database_specific": {"severity": "HIGH"},
        }]

        vulns = db._parse_vulns(hydrated)
        assert len(vulns) == 1
        v = vulns[0]
        assert v.id == "GHSA-8cf7-32gw-wr33"
        assert v.severity == Severity.HIGH
        assert "jsonwebtoken" in v.summary
        assert v.fixed_version == "9.0.0"
        assert len(v.references) >= 1
