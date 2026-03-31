from __future__ import annotations

import re

from repo_security_scanner.models import Dependency, Ecosystem
from repo_security_scanner.parsers.base import DependencyParser, register_parser


@register_parser
class DockerfileParser(DependencyParser):
    filenames = ["Dockerfile", "Dockerfile.prod", "Dockerfile.dev", "Dockerfile.staging"]
    ecosystem = Ecosystem.DOCKER

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        seen = set()
        for line in content.splitlines():
            line = line.strip()
            # Match: FROM [--platform=...] image[:tag] [AS stage]
            m = re.match(
                r'^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)(?:\s+AS\s+\S+)?',
                line, re.IGNORECASE,
            )
            if not m:
                continue
            image_ref = m.group(1).strip()

            # Skip scratch and ARG-based dynamic images
            if image_ref.lower() == "scratch":
                continue
            if image_ref.startswith("$") or image_ref.startswith("{"):
                continue

            name, version = self._split_image_ref(image_ref)
            if name and name not in seen:
                seen.add(name)
                deps.append(Dependency(
                    name=name, version=version,
                    ecosystem=self.ecosystem, source_file=filename,
                ))
        return deps

    def _split_image_ref(self, ref: str) -> tuple:
        """Split image:tag into (name, tag). Default tag is 'latest'."""
        # Handle digest references: image@sha256:abc
        if "@" in ref:
            name = ref.split("@")[0]
            return name, "pinned-digest"
        if ":" in ref:
            parts = ref.rsplit(":", 1)
            return parts[0], parts[1]
        return ref, "latest"


@register_parser
class DockerComposeParser(DependencyParser):
    filenames = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
    ecosystem = Ecosystem.DOCKER

    def parse(self, content: str, filename: str) -> list[Dependency]:
        deps = []
        seen = set()
        # Match: image: name:tag or image: "name:tag"
        for m in re.finditer(r'^\s+image:\s*["\']?([^"\'#\n\r]+)', content, re.MULTILINE):
            image_ref = m.group(1).strip()
            # Skip variable interpolation
            if "${" in image_ref or "$" in image_ref:
                continue
            name, version = self._split_image_ref(image_ref)
            if name and name not in seen:
                seen.add(name)
                deps.append(Dependency(
                    name=name, version=version,
                    ecosystem=self.ecosystem, source_file=filename,
                ))
        return deps

    def _split_image_ref(self, ref: str) -> tuple:
        if "@" in ref:
            name = ref.split("@")[0]
            return name, "pinned-digest"
        if ":" in ref:
            parts = ref.rsplit(":", 1)
            return parts[0], parts[1]
        return ref, "latest"
