"""Tests for Dockerfile/docker-compose parsing and Docker image vulnerability detection."""

from repo_security_scanner.models import Ecosystem, Severity
from repo_security_scanner.parsers.docker import DockerfileParser, DockerComposeParser
from repo_security_scanner.vulndb.docker_images import DockerImageDatabase


class TestDockerfileParser:
    def test_basic_from(self):
        content = "FROM nginx:1.18\n"
        deps = DockerfileParser().parse(content, "Dockerfile")
        assert len(deps) == 1
        assert deps[0].name == "nginx"
        assert deps[0].version == "1.18"
        assert deps[0].ecosystem == Ecosystem.DOCKER

    def test_multi_stage(self):
        content = "FROM node:18 AS builder\nRUN npm install\nFROM nginx:1.25\nCOPY --from=builder /app .\n"
        deps = DockerfileParser().parse(content, "Dockerfile")
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "node" in names
        assert "nginx" in names

    def test_platform_flag(self):
        content = "FROM --platform=linux/amd64 ubuntu:22.04\n"
        deps = DockerfileParser().parse(content, "Dockerfile")
        assert len(deps) == 1
        assert deps[0].name == "ubuntu"
        assert deps[0].version == "22.04"

    def test_skip_scratch(self):
        content = "FROM scratch\nCOPY binary /\n"
        deps = DockerfileParser().parse(content, "Dockerfile")
        assert len(deps) == 0

    def test_skip_arg_variable(self):
        content = "ARG BASE=ubuntu:22.04\nFROM $BASE\n"
        deps = DockerfileParser().parse(content, "Dockerfile")
        assert len(deps) == 0

    def test_unpinned_latest(self):
        content = "FROM ubuntu\n"
        deps = DockerfileParser().parse(content, "Dockerfile")
        assert len(deps) == 1
        assert deps[0].version == "latest"

    def test_explicit_latest(self):
        content = "FROM nginx:latest\n"
        deps = DockerfileParser().parse(content, "Dockerfile")
        assert deps[0].version == "latest"

    def test_digest_reference(self):
        content = "FROM nginx@sha256:abc123\n"
        deps = DockerfileParser().parse(content, "Dockerfile")
        assert len(deps) == 1
        assert deps[0].version == "pinned-digest"

    def test_registry_prefix(self):
        content = "FROM ghcr.io/myorg/myimage:1.0\n"
        deps = DockerfileParser().parse(content, "Dockerfile")
        assert deps[0].name == "ghcr.io/myorg/myimage"
        assert deps[0].version == "1.0"

    def test_case_insensitive(self):
        content = "from python:3.11\n"
        deps = DockerfileParser().parse(content, "Dockerfile")
        assert len(deps) == 1


class TestDockerComposeParser:
    def test_basic(self):
        content = """version: '3'
services:
  web:
    image: nginx:1.25
  db:
    image: postgres:15
"""
        deps = DockerComposeParser().parse(content, "docker-compose.yml")
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "nginx" in names
        assert "postgres" in names

    def test_quoted_image(self):
        content = """services:
  app:
    image: "redis:7"
"""
        deps = DockerComposeParser().parse(content, "compose.yml")
        assert len(deps) == 1
        assert deps[0].name == "redis"

    def test_skip_variables(self):
        content = """services:
  app:
    image: ${REGISTRY}/myapp:${TAG}
"""
        deps = DockerComposeParser().parse(content, "docker-compose.yml")
        assert len(deps) == 0


class TestDockerImageDatabase:
    def test_eol_node14(self):
        from repo_security_scanner.models import Dependency
        dep = Dependency(name="node", version="14.21.0", ecosystem=Ecosystem.DOCKER, source_file="Dockerfile")
        db = DockerImageDatabase()
        results = db.query_batch([dep])
        assert dep.key in results
        vulns = results[dep.key]
        eol = [v for v in vulns if "EOL" in v.id]
        assert len(eol) == 1
        assert eol[0].severity == Severity.HIGH
        assert "22" in eol[0].fixed_version

    def test_eol_python38(self):
        from repo_security_scanner.models import Dependency
        dep = Dependency(name="python", version="3.8.18", ecosystem=Ecosystem.DOCKER, source_file="Dockerfile")
        db = DockerImageDatabase()
        results = db.query_batch([dep])
        assert dep.key in results

    def test_unpinned_latest(self):
        from repo_security_scanner.models import Dependency
        dep = Dependency(name="ubuntu", version="latest", ecosystem=Ecosystem.DOCKER, source_file="Dockerfile")
        db = DockerImageDatabase()
        results = db.query_batch([dep])
        assert dep.key in results
        vulns = results[dep.key]
        unpinned = [v for v in vulns if "UNPINNED" in v.id]
        assert len(unpinned) == 1
        assert unpinned[0].severity == Severity.MEDIUM

    def test_clean_image(self):
        from repo_security_scanner.models import Dependency
        dep = Dependency(name="nginx", version="1.27", ecosystem=Ecosystem.DOCKER, source_file="Dockerfile")
        db = DockerImageDatabase()
        results = db.query_batch([dep])
        assert dep.key not in results

    def test_skips_non_docker(self):
        from repo_security_scanner.models import Dependency
        dep = Dependency(name="requests", version="2.31.0", ecosystem=Ecosystem.PYPI, source_file="requirements.txt")
        db = DockerImageDatabase()
        results = db.query_batch([dep])
        assert len(results) == 0
