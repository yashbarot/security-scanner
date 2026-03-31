from __future__ import annotations

import json

from repo_security_scanner.models import Dependency, Ecosystem
from repo_security_scanner.parsers.base import DependencyParser, register_parser


@register_parser
class ComposerJsonParser(DependencyParser):
    filenames = ["composer.json"]
    ecosystem = Ecosystem.PACKAGIST

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps
        for section in ("require", "require-dev"):
            for name, version in data.get(section, {}).items():
                # Skip php and extension requirements
                if name == "php" or name.startswith("ext-"):
                    continue
                deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
        return deps


@register_parser
class ComposerLockParser(DependencyParser):
    filenames = ["composer.lock"]
    ecosystem = Ecosystem.PACKAGIST

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps
        for section in ("packages", "packages-dev"):
            for pkg in data.get(section, []):
                name = pkg.get("name", "")
                version = pkg.get("version", "").lstrip("v")
                if name and version:
                    deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
        return deps
