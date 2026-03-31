from __future__ import annotations

import time

import requests

from repo_security_scanner.cache import FileCache
from repo_security_scanner.models import Dependency, Ecosystem, Severity, Vulnerability
from repo_security_scanner.vulndb.base import VulnDatabase

CACHE_TTL = 3600  # 1 hour
DEFAULT_MAX_DEPS = 40


class RegistryHealthDatabase(VulnDatabase):
    def __init__(self, cache: FileCache = None, timeout: int = 15, max_deps: int = None):
        self.cache = cache or FileCache()
        self.timeout = timeout
        self.max_deps = max_deps if max_deps is not None else DEFAULT_MAX_DEPS
        self.session = requests.Session()

    def query_batch(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        import concurrent.futures

        results: dict[str, list[Vulnerability]] = {}
        checkable = [d for d in dependencies if d.ecosystem in (Ecosystem.PYPI, Ecosystem.NPM)]
        if self.max_deps > 0:
            checkable = checkable[:self.max_deps]

        def _check_one(dep):
            if dep.ecosystem == Ecosystem.PYPI:
                return dep.key, self._check_pypi(dep)
            else:
                return dep.key, self._check_npm(dep)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            for key, vuln in executor.map(lambda d: _check_one(d), checkable):
                if vuln:
                    results[key] = [vuln]

        return results

    def _check_pypi(self, dep: Dependency) -> Vulnerability | None:
        cache_key = f"pypi_health_{dep.name}"
        cached = self.cache.get(cache_key, CACHE_TTL)

        if cached is None:
            try:
                resp = self.session.get(
                    f"https://pypi.org/pypi/{dep.name}/json",
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                cached = resp.json()
                self.cache.set(cache_key, cached)
            except (requests.RequestException, ValueError):
                return None

        # Check if the specific version is yanked
        version = self._clean_version(dep.version)
        if not version:
            return None

        releases = cached.get("releases", {})
        version_files = releases.get(version, [])
        if version_files and all(f.get("yanked", False) for f in version_files):
            reason = version_files[0].get("yanked_reason", "No reason provided")
            return Vulnerability(
                id=f"YANKED-{dep.name}-{version}",
                summary=f"Version {version} has been yanked from PyPI. Reason: {reason}",
                severity=Severity.HIGH,
                affected_versions=version,
                fixed_version=self._find_latest_safe(releases, version),
                references=[f"https://pypi.org/project/{dep.name}/{version}/"],
                source="pypi_registry",
                confidence="high_signal",
            )
        return None

    def _check_npm(self, dep: Dependency) -> Vulnerability | None:
        cache_key = f"npm_health_{dep.name}"
        cached = self.cache.get(cache_key, CACHE_TTL)

        if cached is None:
            try:
                resp = self.session.get(
                    f"https://registry.npmjs.org/{dep.name}",
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                cached = resp.json()
                self.cache.set(cache_key, cached)
            except (requests.RequestException, ValueError):
                return None

        version = self._clean_version(dep.version)
        if not version:
            return None

        versions = cached.get("versions", {})
        ver_data = versions.get(version, {})
        deprecated = ver_data.get("deprecated")
        if deprecated:
            return Vulnerability(
                id=f"DEPRECATED-{dep.name}-{version}",
                summary=f"Version {version} is deprecated on npm. {deprecated}",
                severity=Severity.MEDIUM,
                affected_versions=version,
                fixed_version=cached.get("dist-tags", {}).get("latest"),
                references=[f"https://www.npmjs.com/package/{dep.name}/v/{version}"],
                source="npm_registry",
                confidence="high_signal",
            )
        return None

    def _clean_version(self, version: str) -> str | None:
        v = version.strip()
        for prefix in ("==", ">=", "<=", "~=", "!=", "^", "~", ">", "<"):
            if v.startswith(prefix):
                v = v[len(prefix):].strip()
                break
        if v and v[0].isdigit():
            return v.split(",")[0].strip()
        return None

    def _find_latest_safe(self, releases: dict, bad_version: str) -> str | None:
        """Find the latest non-yanked version."""
        safe_versions = []
        for ver, files in releases.items():
            if ver == bad_version:
                continue
            if files and not all(f.get("yanked", False) for f in files):
                safe_versions.append(ver)
        return safe_versions[-1] if safe_versions else None
