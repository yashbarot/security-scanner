from __future__ import annotations

import requests

from repo_security_scanner.models import Dependency, Ecosystem, Severity, Vulnerability
from repo_security_scanner.vulndb.base import VulnDatabase

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
BATCH_SIZE = 1000

# Map our ecosystem enum to OSV ecosystem strings
ECOSYSTEM_MAP = {
    Ecosystem.PYPI: "PyPI",
    Ecosystem.NPM: "npm",
    Ecosystem.MAVEN: "Maven",
    Ecosystem.GO: "Go",
    Ecosystem.RUBYGEMS: "RubyGems",
    Ecosystem.CRATES_IO: "crates.io",
    Ecosystem.PACKAGIST: "Packagist",
}


class OSVDatabase(VulnDatabase):
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["Content-Type"] = "application/json"

    def query_batch(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        results: dict[str, list[Vulnerability]] = {}

        for i in range(0, len(dependencies), BATCH_SIZE):
            chunk = dependencies[i : i + BATCH_SIZE]
            queries = []
            for dep in chunk:
                eco = ECOSYSTEM_MAP.get(dep.ecosystem)
                if not eco:
                    continue
                q: dict = {"package": {"name": dep.name, "ecosystem": eco}}
                # Only include version if it's an exact version (not a range)
                version = self._clean_version(dep.version)
                if version:
                    q["version"] = version
                queries.append(q)

            if not queries:
                continue

            try:
                resp = self.session.post(OSV_BATCH_URL, json={"queries": queries}, timeout=self.timeout)
                resp.raise_for_status()
                data = resp.json()
            except (requests.RequestException, ValueError):
                continue

            batch_results = data.get("results", [])
            for dep, result in zip(chunk, batch_results):
                vulns = self._parse_vulns(result.get("vulns", []))
                if vulns:
                    results[dep.key] = vulns

        return results

    def _clean_version(self, version: str) -> str | None:
        """Extract a clean version string, returning None for ranges."""
        v = version.strip()
        if not v or v == "*":
            return None
        # Strip leading operators: ==, >=, ~=, ^, ~, >=
        for prefix in ("==", ">=", "<=", "~=", "!=", "^", "~", ">", "<"):
            if v.startswith(prefix):
                v = v[len(prefix):].strip()
                break
        # If it still contains operators, it's a range - skip
        if any(op in v for op in (",", "||", " ")):
            return None
        # Must look like a version number
        if v and v[0].isdigit():
            return v
        return None

    def _parse_vulns(self, vulns: list[dict]) -> list[Vulnerability]:
        parsed = []
        for vuln in vulns:
            vuln_id = vuln.get("id", "")
            summary = vuln.get("summary", vuln.get("details", "No description available"))
            severity = self._extract_severity(vuln)
            affected_str = self._extract_affected_versions(vuln)
            fixed = self._extract_fixed_version(vuln)
            refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

            parsed.append(Vulnerability(
                id=vuln_id,
                summary=summary[:200] if summary else "No description",
                severity=severity,
                affected_versions=affected_str,
                fixed_version=fixed,
                references=refs[:5],
                source="osv",
            ))
        return parsed

    def _extract_severity(self, vuln: dict) -> Severity:
        # Check database_specific severity
        db_specific = vuln.get("database_specific", {})
        if "severity" in db_specific:
            return Severity.from_string(db_specific["severity"])

        # Check CVSS from severity array
        for sev in vuln.get("severity", []):
            score_str = sev.get("score", "")
            # Parse CVSS vector for score
            if "CVSS" in sev.get("type", ""):
                score = self._extract_cvss_score(score_str)
                if score is not None:
                    if score >= 9.0:
                        return Severity.CRITICAL
                    elif score >= 7.0:
                        return Severity.HIGH
                    elif score >= 4.0:
                        return Severity.MEDIUM
                    else:
                        return Severity.LOW

        # Check affected[].ecosystem_specific or database_specific
        for affected in vuln.get("affected", []):
            eco_specific = affected.get("ecosystem_specific", {})
            if "severity" in eco_specific:
                return Severity.from_string(eco_specific["severity"])

        return Severity.UNKNOWN

    def _extract_cvss_score(self, vector: str) -> float | None:
        """Extract base score from CVSS vector string."""
        # Some OSV entries include the score directly
        try:
            return float(vector)
        except (ValueError, TypeError):
            pass
        # Try to find a numeric score in the vector
        return None

    def _extract_affected_versions(self, vuln: dict) -> str:
        ranges_str = []
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                events = r.get("events", [])
                introduced = None
                fixed = None
                for event in events:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                if introduced and fixed:
                    ranges_str.append(f">={introduced}, <{fixed}")
                elif introduced:
                    ranges_str.append(f">={introduced}")
            # Also check versions list
            versions = affected.get("versions", [])
            if versions and not ranges_str:
                if len(versions) <= 3:
                    ranges_str.append(", ".join(versions))
                else:
                    ranges_str.append(f"{versions[0]} ... {versions[-1]}")
        return "; ".join(ranges_str) if ranges_str else "unknown"

    def _extract_fixed_version(self, vuln: dict) -> str | None:
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return None
