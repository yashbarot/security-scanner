from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from repo_security_scanner.models import Dependency, Ecosystem
from repo_security_scanner.parsers.base import DependencyParser, register_parser


@register_parser
class PomXmlParser(DependencyParser):
    filenames = ["pom.xml"]
    ecosystem = Ecosystem.MAVEN

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return deps

        # Handle Maven namespace
        ns = ""
        m = re.match(r'\{(.+?)\}', root.tag)
        if m:
            ns = m.group(1)

        prefix = f"{{{ns}}}" if ns else ""

        for dep in root.iter(f"{prefix}dependency"):
            group_id = dep.findtext(f"{prefix}groupId", "")
            artifact_id = dep.findtext(f"{prefix}artifactId", "")
            version = dep.findtext(f"{prefix}version", "")
            if group_id and artifact_id:
                name = f"{group_id}:{artifact_id}"
                deps.append(Dependency(
                    name=name,
                    version=version or "*",
                    ecosystem=self.ecosystem,
                    source_file=filename,
                ))
        return deps


@register_parser
class BuildGradleParser(DependencyParser):
    filenames = ["build.gradle", "build.gradle.kts"]
    ecosystem = Ecosystem.MAVEN

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        # Match: implementation 'group:artifact:version'
        # Match: implementation "group:artifact:version"
        # Match: api("group:artifact:version")
        pattern = r"(?:implementation|api|compile|runtimeOnly|testImplementation|compileOnly)\s*[\(]?\s*['\"]([^'\"]+)['\"]"
        for match in re.finditer(pattern, content):
            parts = match.group(1).split(":")
            if len(parts) >= 2:
                name = f"{parts[0]}:{parts[1]}"
                version = parts[2] if len(parts) >= 3 else "*"
                deps.append(Dependency(name=name, version=version, ecosystem=self.ecosystem, source_file=filename))
        return deps
