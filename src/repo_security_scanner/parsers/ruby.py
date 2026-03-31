from __future__ import annotations

import re

from repo_security_scanner.models import Dependency, Ecosystem
from repo_security_scanner.parsers.base import DependencyParser, register_parser


@register_parser
class GemfileParser(DependencyParser):
    filenames = ["Gemfile"]
    ecosystem = Ecosystem.RUBYGEMS

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # gem 'name', '~> 1.0'  or  gem "name", ">= 2.0"
            m = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", line)
            if m:
                name = m.group(1)
                version = m.group(2) or "*"
                deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
        return deps


@register_parser
class GemfileLockParser(DependencyParser):
    filenames = ["Gemfile.lock"]
    ecosystem = Ecosystem.RUBYGEMS

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        in_specs = False
        for line in content.splitlines():
            # Look for "specs:" section under GEM
            if line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs:
                # Top-level gem: "    name (version)"
                m = re.match(r'^    ([a-zA-Z0-9_.\-]+) \((\S+)\)$', line)
                if m:
                    deps.append(Dependency(name=m.group(1), version=m.group(2), ecosystem=self.ecosystem, source_file=filename))
                    continue
                # End of specs section (non-indented or different section)
                if line and not line.startswith("  "):
                    in_specs = False
        return deps
