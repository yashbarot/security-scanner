"""Version comparison utilities for semver and PEP 440 formats."""

from __future__ import annotations

import re


def parse_version(version_str: str) -> tuple:
    """Parse version string into a comparable tuple of integers.

    Handles: 1.2.3, v1.2.3, 1.2.3-beta.1, 1.0.0a1, 1.0.0rc1
    """
    v = version_str.strip().lstrip("vV")
    # Strip build metadata (+xxx)
    v = v.split("+")[0]

    # Split version from pre-release: 1.2.3-beta.1 or 1.0.0a1
    pre_release = None
    # Semver style: 1.2.3-alpha.1
    if "-" in v:
        parts = v.split("-", 1)
        v = parts[0]
        pre_release = parts[1]
    else:
        # PEP 440 style: 1.0.0a1, 1.0.0b2, 1.0.0rc1
        m = re.match(r'^(\d+(?:\.\d+)*)(?:(a|b|rc|alpha|beta|dev)(\d*))', v)
        if m:
            v = m.group(1)
            pre_release = f"{m.group(2)}{m.group(3)}"

    # Parse numeric parts
    numeric = []
    for part in v.split("."):
        try:
            numeric.append(int(part))
        except ValueError:
            numeric.append(0)

    # Pad to at least 3 parts
    while len(numeric) < 3:
        numeric.append(0)

    # Pre-release sorts lower than release: (0, pre_str) vs (1,)
    if pre_release:
        return tuple(numeric) + (0, pre_release)
    return tuple(numeric) + (1,)


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1."""
    t1 = parse_version(v1)
    t2 = parse_version(v2)
    if t1 < t2:
        return -1
    elif t1 > t2:
        return 1
    return 0


def clean_version(version: str) -> str | None:
    """Strip version range operators to get a plain version string."""
    v = version.strip()
    if not v or v == "*":
        return None
    for prefix in ("==", ">=", "<=", "~=", "!=", "^", "~", ">", "<"):
        if v.startswith(prefix):
            v = v[len(prefix):].strip()
            break
    # Take first version if comma-separated range
    if "," in v:
        v = v.split(",")[0].strip()
    if v and v[0].isdigit():
        return v
    return None


def version_in_range(version: str, range_spec: str) -> bool:
    """Check if version falls within a GitHub Advisory version range.

    Format examples:
        ">= 1.0.0, < 1.6.0"
        "< 2.0.0"
        "= 1.2.3"
        ">= 4.0.0, < 4.1.8"
    """
    version = clean_version(version)
    if not version:
        return True  # Can't determine, assume vulnerable (conservative)

    constraints = [c.strip() for c in range_spec.split(",") if c.strip()]
    if not constraints:
        return True  # No range specified, assume vulnerable

    for constraint in constraints:
        m = re.match(r'^([><=!]+)\s*(.+)$', constraint.strip())
        if not m:
            continue

        op = m.group(1).strip()
        target = m.group(2).strip()
        cmp = compare_versions(version, target)

        if op == ">=" and not (cmp >= 0):
            return False
        elif op == "<=" and not (cmp <= 0):
            return False
        elif op == ">" and not (cmp > 0):
            return False
        elif op == "<" and not (cmp < 0):
            return False
        elif op in ("=", "==") and not (cmp == 0):
            return False
        elif op == "!=" and not (cmp != 0):
            return False

    return True
