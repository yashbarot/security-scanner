from __future__ import annotations

import re

from repo_security_scanner.models import Dependency, Ecosystem
from repo_security_scanner.parsers.base import DependencyParser, register_parser


@register_parser
class GoModParser(DependencyParser):
    filenames = ["go.mod"]
    ecosystem = Ecosystem.GO

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        in_require = False
        for line in content.splitlines():
            line = line.strip()

            # Single-line require
            m = re.match(r'^require\s+(\S+)\s+(\S+)', line)
            if m:
                deps.append(Dependency(name=m.group(1), version=m.group(2), ecosystem=self.ecosystem, source_file=filename))
                continue

            # Start of require block
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            if in_require:
                # Skip comments and indirect markers
                line = re.sub(r'//.*', '', line).strip()
                parts = line.split()
                if len(parts) >= 2:
                    deps.append(Dependency(name=parts[0], version=parts[1], ecosystem=self.ecosystem, source_file=filename))
        return deps
