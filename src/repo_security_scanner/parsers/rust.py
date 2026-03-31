from __future__ import annotations

import re

from repo_security_scanner.models import Dependency, Ecosystem
from repo_security_scanner.parsers.base import DependencyParser, register_parser


@register_parser
class CargoTomlParser(DependencyParser):
    filenames = ["Cargo.toml"]
    ecosystem = Ecosystem.CRATES_IO

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()

            # Check for dependency sections
            if re.match(r'^\[(.*dependencies.*)\]', stripped):
                in_deps = True
                continue
            if stripped.startswith("[") and in_deps:
                in_deps = False
                continue

            if in_deps and stripped and not stripped.startswith("#"):
                # name = "version"
                m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*"([^"]+)"', stripped)
                if m:
                    deps.append(Dependency(name=m.group(1), version=m.group(2), ecosystem=self.ecosystem, source_file=filename))
                    continue
                # name = { version = "1.0", ... }
                m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*\{.*?version\s*=\s*"([^"]+)"', stripped)
                if m:
                    deps.append(Dependency(name=m.group(1), version=m.group(2), ecosystem=self.ecosystem, source_file=filename))
        return deps


@register_parser
class CargoLockParser(DependencyParser):
    filenames = ["Cargo.lock"]
    ecosystem = Ecosystem.CRATES_IO

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        blocks = re.split(r'\[\[package\]\]', content)
        for block in blocks[1:]:
            name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
            ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
            if name_m and ver_m:
                deps.append(Dependency(
                    name=name_m.group(1),
                    version=ver_m.group(1),
                    ecosystem=self.ecosystem,
                    source_file=filename,
                ))
        return deps
