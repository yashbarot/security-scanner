from __future__ import annotations

from abc import ABC, abstractmethod

from repo_security_scanner.models import Dependency, Vulnerability


class VulnDatabase(ABC):
    @abstractmethod
    def query_batch(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        """Query vulnerabilities for a batch of dependencies.

        Returns a dict mapping dependency key -> list of vulnerabilities.
        """
        ...
