from __future__ import annotations

from repo_security_scanner.cache import FileCache
from repo_security_scanner.models import Dependency, Ecosystem, Severity, Vulnerability
from repo_security_scanner.vulndb.base import VulnDatabase

# Known EOL/outdated base images: {image_name: {version_prefix: suggested_replacement}}
EOL_IMAGES = {
    "node": {
        "10": "22", "12": "22", "14": "22", "16": "22",
    },
    "python": {
        "2.7": "3.13", "3.6": "3.13", "3.7": "3.13", "3.8": "3.13",
    },
    "ubuntu": {
        "14.04": "24.04", "16.04": "24.04", "18.04": "24.04", "20.04": "24.04",
    },
    "alpine": {
        "3.14": "3.20", "3.15": "3.20", "3.16": "3.20", "3.17": "3.20",
    },
    "nginx": {
        "1.18": "1.27", "1.19": "1.27", "1.20": "1.27", "1.21": "1.27",
    },
    "debian": {
        "stretch": "bookworm", "buster": "bookworm", "jessie": "bookworm",
    },
    "ruby": {
        "2.6": "3.3", "2.7": "3.3", "3.0": "3.3",
    },
    "golang": {
        "1.18": "1.22", "1.19": "1.22", "1.20": "1.22",
    },
    "php": {
        "7.4": "8.3", "8.0": "8.3",
    },
    "postgres": {
        "11": "16", "12": "16", "13": "16",
    },
    "mysql": {
        "5.7": "8.0",
    },
    "redis": {
        "5": "7", "6": "7",
    },
}


class DockerImageDatabase(VulnDatabase):
    def __init__(self, cache: FileCache = None):
        self.cache = cache

    def query_batch(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        results: dict[str, list[Vulnerability]] = {}

        for dep in dependencies:
            if dep.ecosystem != Ecosystem.DOCKER:
                continue

            vulns = []

            # Check unpinned images
            if dep.version in ("latest", ""):
                vulns.append(Vulnerability(
                    id=f"DOCKER-UNPINNED-{dep.name}",
                    summary=f"Image '{dep.name}' uses unpinned tag '{dep.version}'. "
                            f"Pin to a specific version for reproducible builds.",
                    severity=Severity.MEDIUM,
                    affected_versions=dep.version,
                    fixed_version=None,
                    references=[],
                    source="docker_unpinned",
                    confidence="high_signal",
                ))

            # Check EOL images
            image_name = dep.name.split("/")[-1]  # handle registry/name
            eol_versions = EOL_IMAGES.get(image_name, {})
            for eol_prefix, replacement in eol_versions.items():
                if dep.version.startswith(eol_prefix):
                    vulns.append(Vulnerability(
                        id=f"DOCKER-EOL-{dep.name}-{dep.version}",
                        summary=f"Base image '{dep.name}:{dep.version}' is end-of-life or outdated. "
                                f"Upgrade to {image_name}:{replacement} or later.",
                        severity=Severity.HIGH,
                        affected_versions=dep.version,
                        fixed_version=replacement,
                        references=[],
                        source="docker_eol",
                        confidence="confirmed",
                    ))
                    break

            if vulns:
                results[dep.key] = vulns

        return results
