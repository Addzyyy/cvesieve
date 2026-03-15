"""
Output formatters: table, JSON, summary.

Stdout: results only (clean for piping).
Stderr: progress, warnings (handled by callers).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from cvesieve import __version__
from cvesieve.models import ClassifiedFinding, Tier


def _pct(score: float | None) -> str:
    if score is None:
        return "N/A"
    return f"{score * 100:.2f}%"


def _vector_short(vector: str | None) -> str:
    if vector is None:
        return "Unknown"
    labels = {
        "NETWORK": "Network",
        "ADJACENT": "Adjacent",
        "LOCAL": "Local",
        "PHYSICAL": "Physical",
    }
    return labels.get(vector, vector.title())


def _noise_reduction(total: int, block: int, warn: int) -> float:
    """Percentage of CVEs that won't fail the pipeline (WARN + SUPPRESS)."""
    if total == 0:
        return 0.0
    return (total - block) / total * 100


def format_table(
    findings: list[ClassifiedFinding],
    scanner: str = "unknown",
    tier_filter: str = "all",
) -> str:
    by_tier: dict[Tier, list[ClassifiedFinding]] = {
        Tier.BLOCK: [],
        Tier.WARN: [],
        Tier.SUPPRESS: [],
    }
    for f in findings:
        by_tier[f.tier].append(f)

    total = len(findings)
    n_block = len(by_tier[Tier.BLOCK])
    n_warn = len(by_tier[Tier.WARN])
    n_suppress = len(by_tier[Tier.SUPPRESS])
    noise_pct = _noise_reduction(total, n_block, n_warn)

    lines = [
        f"cvesieve v{__version__}",
        f"Scanner: {scanner} | Total CVEs: {total}",
        "",
    ]

    def render_tier(tier: Tier, header: str, items: list[ClassifiedFinding]) -> None:
        lines.append(header)
        if not items:
            lines.append("  (none)")
        else:
            col_w = [20, 10, 20, 8, 10]
            lines.append(
                f"  {'CVE ID':<{col_w[0]}} {'SEVERITY':<{col_w[1]}} {'PACKAGE':<{col_w[2]}} {'EPSS':<{col_w[3]}} {'VECTOR':<{col_w[4]}} REASON"
            )
            for cf in items:
                ef = cf.enriched
                f = ef.finding
                pkg = f"{f.package_name} {f.installed_version}"
                lines.append(
                    f"  {f.cve_id:<{col_w[0]}} {f.severity:<{col_w[1]}} {pkg:<{col_w[2]}} {_pct(ef.epss_score):<{col_w[3]}} {_vector_short(ef.attack_vector):<{col_w[4]}} {cf.reason}"
                )
        lines.append("")

    show_all = tier_filter == "all"

    if show_all or tier_filter == "block":
        render_tier(
            Tier.BLOCK,
            f"\u2550\u2550 BLOCK ({n_block}) \u2014 pipeline will fail {'=' * 40}",
            by_tier[Tier.BLOCK],
        )
    if show_all or tier_filter == "warn":
        render_tier(
            Tier.WARN,
            f"\u2550\u2550 WARN ({n_warn}) \u2014 fix when convenient {'=' * 38}",
            by_tier[Tier.WARN],
        )
    if show_all or tier_filter == "suppress":
        render_tier(
            Tier.SUPPRESS,
            f"\u2550\u2550 SUPPRESS ({n_suppress}) \u2014 near-zero risk {'=' * 41}",
            by_tier[Tier.SUPPRESS],
        )

    lines.append(
        f"Summary: {total} total \u2192 {n_block} block, {n_warn} warn, {n_suppress} suppress ({noise_pct:.1f}% noise reduction)"
    )
    return "\n".join(lines)


def _finding_to_dict(cf: ClassifiedFinding) -> dict:
    ef = cf.enriched
    f = ef.finding
    return {
        "cve_id": f.cve_id,
        "severity": f.severity,
        "package": f.package_name,
        "version": f.installed_version,
        "fixed_version": f.fixed_version,
        "epss_score": ef.epss_score,
        "epss_pct": _pct(ef.epss_score),
        "attack_vector": ef.attack_vector,
        "in_kev": ef.in_kev,
        "days_since_published": ef.days_since_published,
        "tier": cf.tier.value,
        "reason": cf.reason,
        "allowlist_note": cf.allowlist_note,
    }


def format_json(
    findings: list[ClassifiedFinding],
    scanner: str = "unknown",
    epss_threshold: float = 0.001,
    local_epss_threshold: float = 0.05,
    age_threshold: int = 14,
    age_gate_floor: float | None = None,
    exposure: str | None = None,
    privilege: str | None = None,
    allowlist_file: str | None = None,
) -> str:
    by_tier: dict[Tier, list] = {Tier.BLOCK: [], Tier.WARN: [], Tier.SUPPRESS: []}
    for f in findings:
        by_tier[f.tier].append(_finding_to_dict(f))

    total = len(findings)
    n_block = len(by_tier[Tier.BLOCK])
    n_warn = len(by_tier[Tier.WARN])
    n_suppress = len(by_tier[Tier.SUPPRESS])

    output = {
        "metadata": {
            "tool": "cvesieve",
            "version": __version__,
            "scanner": scanner,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "thresholds": {
                "epss_network": epss_threshold,
                "epss_local": local_epss_threshold,
                "age_days": age_threshold,
                "age_gate_floor": age_gate_floor,
            },
            "context": {
                "exposure": exposure,
                "privilege": privilege,
            },
            "allowlist_file": allowlist_file,
        },
        "summary": {
            "total": total,
            "block": n_block,
            "warn": n_warn,
            "suppress": n_suppress,
            "noise_reduction_pct": round(_noise_reduction(total, n_block, n_warn), 1),
            "allowlisted": sum(1 for f in findings if f.allowlist_note),
        },
        "block": by_tier[Tier.BLOCK],
        "warn": by_tier[Tier.WARN],
        "suppress": by_tier[Tier.SUPPRESS],
    }
    return json.dumps(output, indent=2)


def format_summary(findings: list[ClassifiedFinding], scanner: str = "unknown") -> str:
    total = len(findings)
    n_block = sum(1 for f in findings if f.tier == Tier.BLOCK)
    n_warn = sum(1 for f in findings if f.tier == Tier.WARN)
    n_suppress = sum(1 for f in findings if f.tier == Tier.SUPPRESS)
    n_kev = sum(1 for f in findings if f.enriched.in_kev)
    noise_pct = _noise_reduction(total, n_block, n_warn)

    kev_part = f" | {n_kev} KEV hit{'s' if n_kev != 1 else ''}" if n_kev else ""
    n_allowlisted = sum(1 for f in findings if f.allowlist_note)
    allowlist_part = f" | {n_allowlisted} allowlisted" if n_allowlisted else ""
    return (
        f"cvesieve: {total} total \u2192 {n_block} block, {n_warn} warn, "
        f"{n_suppress} suppress ({noise_pct:.1f}% noise reduction){kev_part}{allowlist_part}"
    )
