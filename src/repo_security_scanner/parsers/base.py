from __future__ import annotations

from abc import ABC, abstractmethod

from repo_security_scanner.models import Dependency, Ecosystem

PARSER_REGISTRY: dict[str, DependencyParser] = {}


class DependencyParser(ABC):
    filenames: list[str]
    ecosystem: Ecosystem

    @abstractmethod
    def parse(self, content: str, filename: str) -> list[Dependency]:
        ...


def register_parser(cls: type[DependencyParser]) -> type[DependencyParser]:
    instance = cls()
    for fname in instance.filenames:
        PARSER_REGISTRY[fname] = instance
    return cls
