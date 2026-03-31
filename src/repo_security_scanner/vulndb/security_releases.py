"""Monitor official security release feeds from major runtime/framework maintainers."""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests

from repo_security_scanner.cache import FileCache
from repo_security_scanner.filters import matches_package
from repo_security_scanner.models import Dependency, Ecosystem, Severity, Vulnerability
from repo_security_scanner.vulndb.base import VulnDatabase

CACHE_TTL = 14400  # 4 hours
MAX_AGE_DAYS = 30

# Map ecosystem -> list of (feed_url, feed_name, runtime_keywords)
# runtime_keywords: if any dependency name contains these, the feed is relevant
ECOSYSTEM_FEEDS = {
    Ecosystem.NPM: [
        ("https://nodejs.org/en/feed/vulnerability.xml", "nodejs",
         ["node", "nodejs", "npm"]),
    ],
    Ecosystem.PYPI: [
        ("https://blog.python.org/feeds/posts/default/-/security", "cpython",
         ["python", "cpython"]),
        ("https://www.djangoproject.com/weblog/feeds/security/", "django",
         ["django"]),
        ("https://flask.palletsprojects.com/en/stable/changes/", "flask",
         ["flask"]),
    ],
    Ecosystem.RUBYGEMS: [
        ("https://rubyonrails.org/feed.xml", "rails",
         ["rails", "actionpack", "activerecord", "activesupport"]),
    ],
    Ecosystem.GO: [
        ("https://groups.google.com/g/golang-announce/feed/rss_v2_0", "golang",
         ["go", "golang"]),
    ],
    Ecosystem.MAVEN: [
        ("https://spring.io/blog.atom", "spring",
         ["spring-core", "spring-boot", "spring-framework", "spring-security"]),
    ],
}

SECURITY_TERMS = {
    "security", "vulnerability", "cve", "patch", "fix", "advisory",
    "release", "critical", "urgent", "exploit",
}


class SecurityReleasesDatabase(VulnDatabase):
    def __init__(self, cache: FileCache = None, timeout: int = 15):
        self.cache = cache or FileCache()
        self.timeout = timeout
        self.session = requests.Session()

    def query_batch(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        # Determine which ecosystems are present
        ecosystems = {dep.ecosystem for dep in dependencies}
        dep_names = {dep.name.lower() for dep in dependencies}

        results: dict[str, list[Vulnerability]] = {}

        for eco in ecosystems:
            feeds = ECOSYSTEM_FEEDS.get(eco, [])
            for feed_url, feed_name, runtime_keywords in feeds:
                # Check if any dependency matches this runtime
                if not any(kw in name for kw in runtime_keywords for name in dep_names):
                    continue

                articles = self._fetch_feed(feed_url, feed_name)
                if not articles:
                    continue

                # For runtime feeds (nodejs, cpython, golang), create ONE entry
                # per article attached to the first matching dep — don't fan out
                # to every dep in the ecosystem (that causes 973 duplicates).
                is_runtime_feed = feed_name in ("nodejs", "cpython", "golang")

                if is_runtime_feed:
                    # Find the first dep in this ecosystem to attach results to
                    first_dep = next((d for d in dependencies if d.ecosystem == eco), None)
                    if first_dep:
                        seen_articles = set()
                        for article in articles:
                            aid = article.get("link", article.get("title", ""))
                            if aid not in seen_articles:
                                seen_articles.add(aid)
                                article_hash = hashlib.md5(aid.encode()).hexdigest()[:8]
                                vuln = Vulnerability(
                                    id=f"SECREL-{feed_name}-{article_hash}",
                                    summary=f"[{feed_name.upper()}] {article['title'][:180]}",
                                    severity=Severity.UNKNOWN,
                                    affected_versions="see advisory",
                                    fixed_version=None,
                                    references=[article.get("link", "")],
                                    source=f"security_releases_{feed_name}",
                                    confidence="confirmed",
                                )
                                if first_dep.key not in results:
                                    results[first_dep.key] = []
                                results[first_dep.key].append(vuln)
                else:
                    # For framework feeds (django, rails, spring), match by dep name
                    for dep in dependencies:
                        if dep.ecosystem != eco:
                            continue
                        matched = self._match_articles(dep, articles, feed_name)
                        if matched:
                            if dep.key not in results:
                                results[dep.key] = []
                            results[dep.key].extend(matched)

        return results

    def _fetch_feed(self, url: str, feed_name: str) -> list[dict]:
        cache_key = f"secrel_{feed_name}"
        cached = self.cache.get(cache_key, CACHE_TTL)
        if cached is not None:
            return cached

        try:
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
            articles = self._parse_feed(resp.text, feed_name)
            self.cache.set(cache_key, articles)
            return articles
        except (requests.RequestException, ET.ParseError):
            return []

    def _parse_feed(self, xml_text: str, feed_name: str) -> list[dict]:
        articles = []
        now = datetime.now(timezone.utc)

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return articles

        # RSS 2.0: <channel><item>
        for item in root.iter("item"):
            title = item.findtext("title", "")
            link = item.findtext("link", "")
            desc = item.findtext("description", "")
            pub_date = item.findtext("pubDate", "")
            age_days = self._parse_age_rss(pub_date, now)
            if self._is_security_related(title, desc) and age_days is not None and age_days <= MAX_AGE_DAYS:
                articles.append({
                    "title": title, "link": link, "description": desc,
                    "feed": feed_name, "age_days": age_days,
                })

        # Atom: <entry>
        atom_ns = "{http://www.w3.org/2005/Atom}"
        for entry in root.iter(f"{atom_ns}entry"):
            title = entry.findtext(f"{atom_ns}title", "")
            link_el = entry.find(f"{atom_ns}link")
            link = link_el.get("href", "") if link_el is not None else ""
            summary = entry.findtext(f"{atom_ns}summary", "")
            content = entry.findtext(f"{atom_ns}content", "")
            updated = entry.findtext(f"{atom_ns}updated", "")
            age_days = self._parse_age_iso(updated, now)
            if self._is_security_related(title, summary or content) and age_days is not None and age_days <= MAX_AGE_DAYS:
                articles.append({
                    "title": title, "link": link,
                    "description": summary or content,
                    "feed": feed_name, "age_days": age_days,
                })

        return articles

    def _is_security_related(self, title: str, description: str) -> bool:
        text = f"{title} {description}".lower()
        return any(term in text for term in SECURITY_TERMS)

    def _parse_age_rss(self, date_str: str, now: datetime) -> float | None:
        if not date_str:
            return None
        try:
            dt = parsedate_to_datetime(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (now - dt).total_seconds() / 86400
        except (ValueError, TypeError):
            return None

    def _parse_age_iso(self, date_str: str, now: datetime) -> float | None:
        if not date_str:
            return None
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            return (now - dt).total_seconds() / 86400
        except ValueError:
            return None

    def _match_articles(self, dep: Dependency, articles: list[dict], feed_name: str) -> list[Vulnerability]:
        matched = []
        dep_name = dep.name.lower().split("/")[-1].split(":")[-1]

        for article in articles:
            text = f"{article['title']} {article.get('description', '')}"
            # For runtime feeds, the article is relevant if it's a security release
            # for the runtime the project uses (not necessarily matching a specific package)
            if self._is_relevant(text, dep_name, feed_name):
                article_hash = hashlib.md5(article["link"].encode()).hexdigest()[:8]
                matched.append(Vulnerability(
                    id=f"SECREL-{feed_name}-{article_hash}",
                    summary=f"[{feed_name.upper()}] {article['title'][:180]}",
                    severity=Severity.UNKNOWN,
                    affected_versions="see advisory",
                    fixed_version=None,
                    references=[article["link"]],
                    source=f"security_releases_{feed_name}",
                    confidence="confirmed",
                ))
        return matched

    def _is_relevant(self, text: str, dep_name: str, feed_name: str) -> bool:
        """Check if an article is relevant to a dependency."""
        text_lower = text.lower()
        # For runtime feeds (nodejs, cpython, golang), any security article is relevant
        # because the project uses that runtime
        if feed_name in ("nodejs", "cpython", "golang"):
            return True  # Already filtered to security articles
        # For framework feeds, check if the dep name matches
        if dep_name in text_lower:
            return True
        return False
