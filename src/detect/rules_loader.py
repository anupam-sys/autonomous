"""Load detection rules from gitleaks-compatible TOML files."""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from ..models import SecretType


@dataclass
class Rule:
    id: str
    description: str
    regex: str
    keywords: list[str]
    service: str
    secret_type: SecretType
    severity: str
    confidence: float = 0.7
    entropy: float | None = None
    group: int | None = None
    pattern: re.Pattern = field(init=False, repr=False)
    keywords_lower: list[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.pattern = re.compile(self.regex)
        self.keywords_lower = [k.lower() for k in (self.keywords or [])]


def load_rules(rules_dir: str | Path) -> list[Rule]:
    rules: list[Rule] = []
    for toml_file in sorted(Path(rules_dir).glob("*.toml")):
        data = tomllib.loads(toml_file.read_text(encoding="utf-8"))
        for raw in data.get("rules", []):
            rules.append(
                Rule(
                    id=raw["id"],
                    description=raw.get("description", raw["id"]),
                    regex=raw["regex"],
                    keywords=raw.get("keywords", []),
                    service=raw.get("service", "generic"),
                    secret_type=SecretType(raw.get("secret_type", "other")),
                    severity=raw.get("severity", "medium"),
                    confidence=float(raw.get("confidence", 0.7)),
                    entropy=raw.get("entropy"),
                    group=raw.get("group"),
                )
            )
    return rules
