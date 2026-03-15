"""
CVE allowlist — risk acceptance via TOML config.

Teams can accept risk on specific CVEs so they aren't re-classified every run.
KEV CVEs always stay BLOCK regardless of allowlist entries.
"""
from __future__ import annotations

import sys
import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from cvesieve.models import ClassifiedFinding, Tier

_TIER_RANK = {Tier.SUPPRESS: 0, Tier.WARN: 1, Tier.BLOCK: 2}


@dataclass
class AllowlistEntry:
    cve_id: str
    max_tier: Tier
    reason: str
    approved_by: str
    expires: date | None = None


def load_allowlist(path: Path) -> list[AllowlistEntry]:
    """Parse a TOML allowlist file. Malformed entries are skipped with a warning on stderr."""
    try:
        text = path.read_text()
    except Exception as e:
        print(f"Warning: cannot read allowlist {path}: {e}", file=sys.stderr)
        return []

    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        print(f"Warning: invalid TOML in allowlist {path}: {e}", file=sys.stderr)
        return []

    entries: list[AllowlistEntry] = []
    for i, raw in enumerate(data.get("entry", [])):
        try:
            cve_id = raw["cve_id"]
            tier_str = raw["max_tier"].upper()
            try:
                max_tier = Tier(tier_str)
            except ValueError:
                print(f"Warning: allowlist entry {i}: invalid tier '{tier_str}', skipping", file=sys.stderr)
                continue
            reason = raw["reason"]
            approved_by = raw["approved_by"]
            expires_raw = raw.get("expires")
            expires = None
            if expires_raw is not None:
                if isinstance(expires_raw, date):
                    expires = expires_raw
                else:
                    expires = date.fromisoformat(str(expires_raw))
            entries.append(AllowlistEntry(
                cve_id=cve_id,
                max_tier=max_tier,
                reason=reason,
                approved_by=approved_by,
                expires=expires,
            ))
        except (KeyError, ValueError, TypeError) as e:
            print(f"Warning: allowlist entry {i}: {e}, skipping", file=sys.stderr)
            continue

    return entries


def apply_allowlist(
    classified: list[ClassifiedFinding],
    entries: list[AllowlistEntry],
) -> list[ClassifiedFinding]:
    """Apply allowlist entries to classified findings. KEV CVEs stay BLOCK."""
    today = date.today()
    lookup: dict[str, AllowlistEntry] = {}
    for entry in entries:
        if entry.expires and entry.expires < today:
            print(
                f"Warning: allowlist entry for {entry.cve_id} expired {entry.expires}, ignoring",
                file=sys.stderr,
            )
            continue
        lookup[entry.cve_id] = entry

    result: list[ClassifiedFinding] = []
    for cf in classified:
        cve_id = cf.enriched.finding.cve_id
        entry = lookup.get(cve_id)
        if entry is None:
            result.append(cf)
            continue

        # KEV CVEs stay BLOCK — append note but don't downgrade
        if cf.enriched.in_kev:
            result.append(ClassifiedFinding(
                enriched=cf.enriched,
                tier=cf.tier,
                reason=cf.reason,
                allowlist_note="[allowlisted but KEV overrides]",
            ))
            continue

        # Only downgrade, never upgrade
        if _TIER_RANK[entry.max_tier] >= _TIER_RANK[cf.tier]:
            result.append(ClassifiedFinding(
                enriched=cf.enriched,
                tier=cf.tier,
                reason=cf.reason,
                allowlist_note=f"[allowlisted -> {entry.max_tier.value} by {entry.approved_by}: {entry.reason}]",
            ))
            continue

        # Downgrade
        note = f"[allowlisted -> {entry.max_tier.value} by {entry.approved_by}: {entry.reason}]"
        result.append(ClassifiedFinding(
            enriched=cf.enriched,
            tier=entry.max_tier,
            reason=cf.reason + f" {note}",
            allowlist_note=note,
        ))

    return result
