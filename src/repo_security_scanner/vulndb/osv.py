from __future__ import annotations

import concurrent.futures
import math
import time

import requests

from repo_security_scanner.models import Dependency, Ecosystem, Severity, Vulnerability
from repo_security_scanner.vulndb.base import VulnDatabase

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
BATCH_SIZE = 1000
MAX_HYDRATION_WORKERS = 10

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

# CVSS v3.x metric weights per specification
_CVSS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS_AC = {"L": 0.77, "H": 0.44}
_CVSS_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
_CVSS_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Scope Changed
_CVSS_UI = {"N": 0.85, "R": 0.62}
_CVSS_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


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
                raw_vulns = result.get("vulns", [])
                if raw_vulns:
                    # Batch API returns only {id, modified} stubs.
                    # Hydrate with full details from /v1/vulns/{id}.
                    raw_vulns = self._hydrate_vulns(raw_vulns)
                vulns = self._parse_vulns(raw_vulns)
                if vulns:
                    results[dep.key] = vulns

        return results

    def _hydrate_vulns(self, vuln_stubs: list[dict]) -> list[dict]:
        """Fetch full vulnerability details for batch result stubs."""
        ids = [v.get("id") for v in vuln_stubs if v.get("id")]
        if not ids:
            return vuln_stubs

        def fetch_one(vuln_id: str) -> dict | None:
            url = f"{OSV_VULN_URL}/{vuln_id}"
            for attempt in range(2):
                try:
                    # Use requests.get directly (not self.session) for thread safety
                    resp = requests.get(url, timeout=self.timeout)
                    if resp.status_code == 429:
                        retry_after = int(resp.headers.get("Retry-After", 1))
                        time.sleep(min(retry_after, 5))
                        continue
                    resp.raise_for_status()
                    return resp.json()
                except Exception:
                    return None
            return None

        full_vulns = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_HYDRATION_WORKERS) as executor:
            future_to_id = {executor.submit(fetch_one, vid): vid for vid in ids}
            for future in concurrent.futures.as_completed(future_to_id):
                result = future.result()
                if result:
                    full_vulns.append(result)

        return full_vulns if full_vulns else vuln_stubs

    def _clean_version(self, version: str) -> str | None:
        """Extract a clean version string, returning None for ranges."""
        v = version.strip()
        if not v or v == "*":
            return None
        for prefix in ("==", ">=", "<=", "~=", "!=", "^", "~", ">", "<"):
            if v.startswith(prefix):
                v = v[len(prefix):].strip()
                break
        if any(op in v for op in (",", "||", " ")):
            return None
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
        # Check database_specific severity (most reliable for GitHub Advisory sourced data)
        db_specific = vuln.get("database_specific", {})
        if "severity" in db_specific:
            return Severity.from_string(db_specific["severity"])

        # Check CVSS from severity array
        for sev in vuln.get("severity", []):
            score_str = sev.get("score", "")
            sev_type = sev.get("type", "")
            if "CVSS" in sev_type:
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

        # Check affected[].ecosystem_specific
        for affected in vuln.get("affected", []):
            eco_specific = affected.get("ecosystem_specific", {})
            if "severity" in eco_specific:
                return Severity.from_string(eco_specific["severity"])

        # Check affected[].database_specific
        for affected in vuln.get("affected", []):
            db = affected.get("database_specific", {})
            if "cvss" in db:
                try:
                    score = float(db["cvss"].get("score", 0))
                    if score >= 9.0:
                        return Severity.CRITICAL
                    elif score >= 7.0:
                        return Severity.HIGH
                    elif score >= 4.0:
                        return Severity.MEDIUM
                    else:
                        return Severity.LOW
                except (ValueError, TypeError, AttributeError):
                    pass

        return Severity.UNKNOWN

    def _extract_cvss_score(self, vector: str) -> float | None:
        """Extract base score from CVSS vector string or plain float."""
        # Try plain float first (some entries provide score directly)
        try:
            return float(vector)
        except (ValueError, TypeError):
            pass

        # Parse CVSS v3.x vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        if not vector or not vector.startswith("CVSS:3"):
            return None

        try:
            parts = vector.split("/")
            metrics = {}
            for part in parts[1:]:  # Skip "CVSS:3.x"
                if ":" in part:
                    key, val = part.split(":", 1)
                    metrics[key] = val

            av = _CVSS_AV.get(metrics.get("AV", ""), None)
            ac = _CVSS_AC.get(metrics.get("AC", ""), None)
            ui = _CVSS_UI.get(metrics.get("UI", ""), None)
            scope = metrics.get("S", "")
            c = _CVSS_CIA.get(metrics.get("C", ""), None)
            i = _CVSS_CIA.get(metrics.get("I", ""), None)
            a = _CVSS_CIA.get(metrics.get("A", ""), None)

            if scope == "U":
                pr = _CVSS_PR_U.get(metrics.get("PR", ""), None)
            else:
                pr = _CVSS_PR_C.get(metrics.get("PR", ""), None)

            if any(v is None for v in (av, ac, pr, ui, c, i, a)):
                return None

            # Impact Sub-Score
            iss = 1 - ((1 - c) * (1 - i) * (1 - a))

            if scope == "U":
                impact = 6.42 * iss
            else:
                impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

            # Exploitability
            exploitability = 8.22 * av * ac * pr * ui

            if impact <= 0:
                return 0.0

            if scope == "U":
                score = impact + exploitability
            else:
                score = 1.08 * (impact + exploitability)

            # Cap at 10.0 and round up to nearest 0.1
            score = min(score, 10.0)
            return math.ceil(score * 10) / 10

        except (KeyError, ValueError, ZeroDivisionError):
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
