from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Tier(Enum):
    BLOCK = "BLOCK"
    WARN = "WARN"
    SUPPRESS = "SUPPRESS"


@dataclass
class Finding:
    cve_id: str
    severity: str
    package_name: str
    installed_version: str
    fixed_version: str | None
    cvss_vector: str | None
    published_date: str | None
    scanner: str
    description: str | None


@dataclass
class EnrichedFinding:
    finding: Finding
    epss_score: float | None
    epss_percentile: float | None
    attack_vector: str | None  # "NETWORK", "ADJACENT", "LOCAL", "PHYSICAL", or None
    in_kev: bool
    days_since_published: int | None
    cvss_scope: str | None = None  # "CHANGED", "UNCHANGED", or None (v2/unknown)


@dataclass
class ClassifiedFinding:
    enriched: EnrichedFinding
    tier: Tier
    reason: str
