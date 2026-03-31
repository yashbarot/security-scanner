from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Ecosystem(Enum):
    PYPI = "PyPI"
    NPM = "npm"
    MAVEN = "Maven"
    GO = "Go"
    RUBYGEMS = "RubyGems"
    CRATES_IO = "crates.io"
    PACKAGIST = "Packagist"
    DOCKER = "Docker"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError:
            return cls.UNKNOWN


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.UNKNOWN: 4,
}


class SignalConfidence(Enum):
    CONFIRMED = "confirmed"
    HIGH_SIGNAL = "high_signal"
    EARLY_SIGNAL = "early_signal"


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: Ecosystem
    source_file: str

    @property
    def key(self) -> str:
        return f"{self.ecosystem.value}:{self.name}"


@dataclass
class Vulnerability:
    id: str
    summary: str
    severity: Severity
    affected_versions: str
    fixed_version: str | None
    references: list[str] = field(default_factory=list)
    source: str = "osv"
    confidence: str = "confirmed"


@dataclass
class ScanResult:
    dependency: Dependency
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


@dataclass
class ScanReport:
    directory: str
    scanned_at: datetime
    results: list[ScanResult] = field(default_factory=list)

    @property
    def total_dependencies(self) -> int:
        return len(self.results)

    @property
    def vulnerable_dependencies(self) -> list[ScanResult]:
        return [r for r in self.results if r.vulnerabilities]

    @property
    def total_vulns(self) -> int:
        return sum(len(r.vulnerabilities) for r in self.results)

    @property
    def critical_count(self) -> int:
        return self._count_by_severity(Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return self._count_by_severity(Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return self._count_by_severity(Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return self._count_by_severity(Severity.LOW)

    @property
    def is_clean(self) -> bool:
        return self.total_vulns == 0

    @property
    def has_critical_or_high(self) -> bool:
        return self.critical_count > 0 or self.high_count > 0

    @property
    def early_signals(self) -> list[ScanResult]:
        out = []
        for r in self.results:
            signals = [v for v in r.vulnerabilities if v.confidence != "confirmed"]
            if signals:
                out.append(ScanResult(dependency=r.dependency, vulnerabilities=signals))
        return out

    @property
    def confirmed_results(self) -> list[ScanResult]:
        out = []
        for r in self.results:
            confirmed = [v for v in r.vulnerabilities if v.confidence == "confirmed"]
            if confirmed:
                out.append(ScanResult(dependency=r.dependency, vulnerabilities=confirmed))
        return out

    @property
    def early_signal_count(self) -> int:
        return sum(len(r.vulnerabilities) for r in self.early_signals)

    def _count_by_severity(self, severity: Severity) -> int:
        count = 0
        for r in self.results:
            for v in r.vulnerabilities:
                if v.severity == severity:
                    count += 1
        return count
