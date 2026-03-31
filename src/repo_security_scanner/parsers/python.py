from __future__ import annotations

import json
import re

from repo_security_scanner.models import Dependency, Ecosystem
from repo_security_scanner.parsers.base import DependencyParser, register_parser


@register_parser
class RequirementsTxtParser(DependencyParser):
    filenames = ["requirements.txt", "requirements-dev.txt", "requirements_dev.txt"]
    ecosystem = Ecosystem.PYPI

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle: package==1.0, package>=1.0, package~=1.0, package!=1.0
            match = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([=!<>~]=?\s*[\d.*]+(?:\s*,\s*[=!<>~]=?\s*[\d.*]+)*)", line)
            if match:
                name = re.sub(r"\[.*\]", "", match.group(1)).strip()
                version = match.group(2).strip()
                deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
        return deps


@register_parser
class PyprojectTomlParser(DependencyParser):
    filenames = ["pyproject.toml"]
    ecosystem = Ecosystem.PYPI

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        # Match dependencies in [project] dependencies array
        deps.extend(self._parse_project_deps(content, filename))
        # Match [tool.poetry.dependencies]
        deps.extend(self._parse_poetry_deps(content, filename))
        return deps

    def _parse_project_deps(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
        if not match:
            return deps
        block = match.group(1)
        for item in re.findall(r'"([^"]+)"', block):
            parsed = self._parse_dep_string(item)
            if parsed:
                name, version = parsed
                deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
        return deps

    def _parse_poetry_deps(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        match = re.search(r'\[tool\.poetry\.dependencies\](.*?)(?:\n\[|\Z)', content, re.DOTALL)
        if not match:
            return deps
        block = match.group(1)
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # name = "^1.0" or name = {version = "^1.0", ...}
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*"([^"]+)"', line)
            if m:
                name, version = m.group(1), m.group(2)
                if name.lower() != "python":
                    deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
                continue
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*\{.*?version\s*=\s*"([^"]+)"', line)
            if m:
                name, version = m.group(1), m.group(2)
                if name.lower() != "python":
                    deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
        return deps

    def _parse_dep_string(self, dep: str) -> tuple[str, str] | None:
        match = re.match(r'^([A-Za-z0-9_.\-\[\]]+)\s*([=!<>~]=?\s*.*)?$', dep.strip())
        if match:
            name = re.sub(r"\[.*\]", "", match.group(1)).strip()
            version = (match.group(2) or "").strip()
            return name, version if version else "*"
        return None


@register_parser
class PipfileLockParser(DependencyParser):
    filenames = ["Pipfile.lock"]
    ecosystem = Ecosystem.PYPI

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps
        for section in ("default", "develop"):
            packages = data.get(section, {})
            for name, info in packages.items():
                version = info.get("version", "").lstrip("=")
                if version:
                    deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
        return deps


@register_parser
class PoetryLockParser(DependencyParser):
    filenames = ["poetry.lock"]
    ecosystem = Ecosystem.PYPI

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        blocks = re.split(r'\[\[package\]\]', content)
        for block in blocks[1:]:  # skip preamble
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
