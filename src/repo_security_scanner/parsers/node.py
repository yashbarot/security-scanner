from __future__ import annotations

import json
import re

from repo_security_scanner.models import Dependency, Ecosystem
from repo_security_scanner.parsers.base import DependencyParser, register_parser


@register_parser
class PackageJsonParser(DependencyParser):
    filenames = ["package.json"]
    ecosystem = Ecosystem.NPM

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps
        for section in ("dependencies", "devDependencies"):
            for name, version in data.get(section, {}).items():
                deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
        return deps


@register_parser
class PackageLockJsonParser(DependencyParser):
    filenames = ["package-lock.json"]
    ecosystem = Ecosystem.NPM

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps

        # v2/v3 format: "packages" field
        packages = data.get("packages", {})
        if packages:
            for path, info in packages.items():
                if not path:  # root package
                    continue
                name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
                version = info.get("version", "")
                if name and version:
                    deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
            return deps

        # v1 format: "dependencies" field
        self._parse_v1_deps(data.get("dependencies", {}), deps, filename)
        return deps

    def _parse_v1_deps(self, dependencies: dict, deps: list[Dependency], filename: str) -> None:
        for name, info in dependencies.items():
            version = info.get("version", "")
            if version:
                deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
            # Recurse into nested dependencies
            if "dependencies" in info:
                self._parse_v1_deps(info["dependencies"], deps, filename)


@register_parser
class YarnLockParser(DependencyParser):
    filenames = ["yarn.lock"]
    ecosystem = Ecosystem.NPM

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        seen = set()
        # Match patterns like: "package@^1.0.0": or package@^1.0.0:
        current_name = None
        for line in content.splitlines():
            # Header line: "name@version", "name@version":
            header = re.match(r'^"?(@?[^@\s"]+)@', line)
            if header:
                current_name = header.group(1)
                continue
            # Version line under a header
            if current_name:
                ver_match = re.match(r'^\s+version\s+"?([^"]+)"?', line)
                if ver_match:
                    version = ver_match.group(1)
                    if current_name not in seen:
                        seen.add(current_name)
                        deps.append(Dependency(name=current_name, version=version, ecosystem=self.ecosystem, source_file=filename))
                    current_name = None
        return deps
