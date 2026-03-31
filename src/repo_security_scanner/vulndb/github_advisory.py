from __future__ import annotations

import os

import requests

from repo_security_scanner.models import Dependency, Ecosystem, Severity, Vulnerability
from repo_security_scanner.version_utils import clean_version, version_in_range
from repo_security_scanner.vulndb.base import VulnDatabase

GITHUB_API_URL = "https://api.github.com/advisories"

ECOSYSTEM_MAP = {
    Ecosystem.PYPI: "pip",
    Ecosystem.NPM: "npm",
    Ecosystem.MAVEN: "maven",
    Ecosystem.GO: "go",
    Ecosystem.RUBYGEMS: "rubygems",
    Ecosystem.CRATES_IO: "rust",
    Ecosystem.PACKAGIST: "composer",
}


class GitHubAdvisoryDatabase(VulnDatabase):
    def __init__(self, token: str | None = None, timeout: int = 30):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["Accept"] = "application/vnd.github+json"
        if self.token:
            self.session.headers["Authorization"] = f"Bearer {self.token}"

    def query_batch(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        results: dict[str, list[Vulnerability]] = {}

        # Group dependencies by ecosystem for efficient querying
        by_ecosystem: dict[Ecosystem, list[Dependency]] = {}
        for dep in dependencies:
            by_ecosystem.setdefault(dep.ecosystem, []).append(dep)

        for ecosystem, deps in by_ecosystem.items():
            gh_eco = ECOSYSTEM_MAP.get(ecosystem)
            if not gh_eco:
                continue

            try:
                advisories = self._fetch_advisories(gh_eco)
            except requests.RequestException:
                continue

            for dep in deps:
                matching = self._match_advisories(dep, advisories)
                if matching:
                    results[dep.key] = matching

        return results

    def _fetch_advisories(self, ecosystem: str) -> list[dict]:
        """Fetch recent advisories for an ecosystem."""
        advisories = []
        params = {
            "ecosystem": ecosystem,
            "per_page": 100,
            "severity": "critical,high",
        }
        try:
            resp = self.session.get(GITHUB_API_URL, params=params, timeout=self.timeout)
            resp.raise_for_status()
            advisories = resp.json()
        except (requests.RequestException, ValueError):
            pass
        return advisories

    def _match_advisories(self, dep: Dependency, advisories: list[dict]) -> list[Vulnerability]:
        matched = []
        dep_name_lower = dep.name.lower()

        for adv in advisories:
            for vuln_pkg in adv.get("vulnerabilities", []):
                pkg = vuln_pkg.get("package", {})
                if pkg.get("name", "").lower() == dep_name_lower:
                    # Check if dependency version falls within vulnerable range
                    vuln_range = vuln_pkg.get("vulnerable_version_range", "")
                    dep_version = clean_version(dep.version)
                    if dep_version and vuln_range:
                        if not version_in_range(dep_version, vuln_range):
                            continue  # Version not in vulnerable range

                    severity = Severity.from_string(adv.get("severity", "unknown"))
                    refs = [adv.get("html_url", "")]
                    for ref in adv.get("references", []):
                        if isinstance(ref, str):
                            refs.append(ref)

                    matched.append(Vulnerability(
                        id=adv.get("ghsa_id", adv.get("cve_id", "unknown")),
                        summary=adv.get("summary", "")[:200],
                        severity=severity,
                        affected_versions=vuln_pkg.get("vulnerable_version_range", "unknown"),
                        fixed_version=vuln_pkg.get("first_patched_version"),
                        references=[r for r in refs if r],
                        source="github_advisory",
                    ))
        return matched
