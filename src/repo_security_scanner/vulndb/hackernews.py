from __future__ import annotations

import time

import requests

from repo_security_scanner.cache import FileCache
from repo_security_scanner.filters import matches_package, relevance_score, should_search_web
from repo_security_scanner.models import Dependency, Severity, Vulnerability
from repo_security_scanner.vulndb.base import VulnDatabase

HN_SEARCH_URL = "https://hn.algolia.com/api/v1/search"
CACHE_TTL = 1800  # 30 minutes
MIN_POINTS = 5
RELEVANCE_THRESHOLD = 0.5
DEFAULT_MAX_DEPS = 30


class HackerNewsDatabase(VulnDatabase):
    def __init__(self, cache: FileCache = None, timeout: int = 15, max_deps: int = None):
        self.cache = cache or FileCache()
        self.timeout = timeout
        self.max_deps = max_deps if max_deps is not None else DEFAULT_MAX_DEPS
        self.session = requests.Session()

    def query_batch(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        import concurrent.futures

        results: dict[str, list[Vulnerability]] = {}
        searchable = [d for d in dependencies if should_search_web(d)]
        if self.max_deps > 0:
            searchable = searchable[:self.max_deps]

        def _query_one(dep):
            return dep.key, self._search(dep)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            for key, vulns in executor.map(lambda d: _query_one(d), searchable):
                if vulns:
                    results[key] = vulns

        return results

    def _search(self, dep: Dependency) -> list[Vulnerability]:
        name = dep.name.split("/")[-1].split(":")[-1]  # clean scoped/maven names
        cache_key = f"hn_{name}"
        cached = self.cache.get(cache_key, CACHE_TTL)

        if cached is None:
            seven_days_ago = int(time.time()) - (7 * 86400)
            params = {
                "query": f'"{name}" (vulnerability OR CVE OR exploit OR malicious OR compromised)',
                "tags": "story",
                "numericFilters": f"created_at_i>{seven_days_ago}",
                "hitsPerPage": 10,
            }
            try:
                resp = self.session.get(HN_SEARCH_URL, params=params, timeout=self.timeout)
                resp.raise_for_status()
                cached = resp.json().get("hits", [])
                self.cache.set(cache_key, cached)
            except (requests.RequestException, ValueError):
                return []

        vulns = []
        for hit in cached:
            title = hit.get("title", "")
            points = hit.get("points", 0) or 0
            story_id = hit.get("objectID", "")
            url = hit.get("url") or f"https://news.ycombinator.com/item?id={story_id}"
            created_at = hit.get("created_at_i", 0)
            age_days = (time.time() - created_at) / 86400 if created_at else 7

            if points < MIN_POINTS:
                continue

            if not matches_package(title, name):
                continue

            score = relevance_score(title, name, age_days=age_days, engagement=points)
            if score < RELEVANCE_THRESHOLD:
                continue

            vulns.append(Vulnerability(
                id=f"HN-{story_id}",
                summary=title[:200],
                severity=Severity.UNKNOWN,
                affected_versions="unknown",
                fixed_version=None,
                references=[url],
                source="hackernews",
                confidence="early_signal",
            ))

        return vulns
