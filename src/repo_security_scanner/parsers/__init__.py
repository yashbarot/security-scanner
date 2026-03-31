"""Dependency file parsers with auto-registration."""

# Import all parsers to trigger @register_parser decorators
from repo_security_scanner.parsers import (  # noqa: F401
    go,
    java,
    node,
    php,
    python,
    ruby,
    rust,
)
from repo_security_scanner.parsers.base import PARSER_REGISTRY

__all__ = ["PARSER_REGISTRY"]
