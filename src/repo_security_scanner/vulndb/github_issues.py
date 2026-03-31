from __future__ import annotations

import os
import time
from datetime import datetime, timezone

import requests

from repo_security_scanner.cache import FileCache
from repo_security_scanner.filters import should_search_web
from repo_security_scanner.models import Dependency, Severity, Vulnerability
from repo_security_scanner.vulndb.base import VulnDatabase

SEARCH_URL = "https://api.github.com/search/issues"
CACHE_TTL = 1800  # 30 minutes
SCORE_THRESHOLD = 0.5
DEFAULT_MAX_DEPS = 20


class GitHubIssuesDatabase(VulnDatabase):
    def __init__(self, token: str = None, cache: FileCache = None, timeout: int = 15, max_deps: int = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.cache = cache or FileCache()
        self.timeout = timeout
        self.max_deps = max_deps if max_deps is not None else DEFAULT_MAX_DEPS
        self.session = requests.Session()
        self.session.headers["Accept"] = "application/vnd.github+json"
        if self.token:
            self.session.headers["Authorization"] = f"Bearer {self.token}"

    def query_batch(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        results: dict[str, list[Vulnerability]] = {}
        searchable = [d for d in dependencies if should_search_web(d)]
        if self.max_deps > 0:
            searchable = searchable[:self.max_deps]

        for dep in searchable:
            vulns = self._search(dep)
            if vulns:
                results[dep.key] = vulns
            time.sleep(0.5)  # Reduced from 2s, rely on cache + cap

        return results

    def _search(self, dep: Dependency) -> list[Vulnerability]:
        name = dep.name.split("/")[-1].split(":")[-1]
        cache_key = f"gh_issues_{name}"
        cached = self.cache.get(cache_key, CACHE_TTL)

        if cached is None:
            q = f'"{name}" vulnerability OR CVE OR security OR compromised OR malicious in:title,body'
            params = {
                "q": q,
                "sort": "updated",
                "order": "desc",
                "per_page": 5,
            }
            try:
                resp = self.session.get(SEARCH_URL, params=params, timeout=self.timeout)
                if resp.status_code == 403:  # Rate limited
                    return []
                resp.raise_for_status()
                cached = resp.json().get("items", [])
                self.cache.set(cache_key, cached)
            except (requests.RequestException, ValueError):
                return []

        vulns = []
        for issue in cached:
            score = self._score_issue(issue, name)
            if score < SCORE_THRESHOLD:
                continue

            vulns.append(Vulnerability(
                id=f"GH-ISSUE-{issue.get('number', '')}",
                summary=issue.get("title", "")[:200],
                severity=Severity.UNKNOWN,
                affected_versions="unknown",
                fixed_version=None,
                references=[issue.get("html_url", "")],
                source="github_issues",
                confidence="early_signal",
            ))

        return vulns

    def _score_issue(self, issue: dict, package_name: str) -> float:
        score = 0.0
        title = (issue.get("title") or "").lower()
        name_lower = package_name.lower()

        # Package name in title
        if name_lower in title:
            score += 0.15

        # Issue is in the package's own repo
        repo_url = issue.get("repository_url", "")
        if name_lower in repo_url.lower():
            score += 0.3

        # Has security-related labels
        labels = [l.get("name", "").lower() for l in issue.get("labels", [])]
        security_labels = {"security", "vulnerability", "cve", "bug", "critical"}
        if any(l in security_labels for l in labels):
            score += 0.2

        # Recency (created within last 7 days)
        created = issue.get("created_at", "")
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - dt).days
                if age_days <= 7:
                    score += 0.15
            except ValueError:
                pass

        # Reactions / comments as engagement signal
        comments = issue.get("comments", 0) or 0
        if comments >= 5:
            score += 0.2
        elif comments >= 2:
            score += 0.1

        return score
