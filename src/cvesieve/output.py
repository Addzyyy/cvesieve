"""
Output formatters: table, JSON, summary, CSV, Markdown, SARIF.

Stdout: results only (clean for piping).
Stderr: progress, warnings (handled by callers).
"""
from __future__ import annotations

import csv
import io
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
        },
        "summary": {
            "total": total,
            "block": n_block,
            "warn": n_warn,
            "suppress": n_suppress,
            "noise_reduction_pct": round(_noise_reduction(total, n_block, n_warn), 1),
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
    return (
        f"cvesieve: {total} total \u2192 {n_block} block, {n_warn} warn, "
        f"{n_suppress} suppress ({noise_pct:.1f}% noise reduction){kev_part}"
    )


_CSV_COLUMNS = [
    "cve_id", "severity", "package", "version", "fixed_version",
    "epss_score", "epss_pct", "attack_vector", "in_kev",
    "days_since_published", "tier", "reason",
]


def format_csv(findings: list[ClassifiedFinding], **kwargs: object) -> str:
    """RFC 4180 CSV output."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(_CSV_COLUMNS)
    for cf in findings:
        d = _finding_to_dict(cf)
        writer.writerow(
            "" if d[col] is None else d[col]
            for col in _CSV_COLUMNS
        )
    return buf.getvalue()


def format_markdown(
    findings: list[ClassifiedFinding],
    scanner: str = "unknown",
    tier_filter: str = "all",
    **kwargs: object,
) -> str:
    """GitHub-flavored Markdown with pipe tables grouped by tier."""
    by_tier: dict[Tier, list[ClassifiedFinding]] = {
        Tier.BLOCK: [], Tier.WARN: [], Tier.SUPPRESS: [],
    }
    for f in findings:
        by_tier[f.tier].append(f)

    total = len(findings)
    n_block = len(by_tier[Tier.BLOCK])
    n_warn = len(by_tier[Tier.WARN])
    noise_pct = _noise_reduction(total, n_block, n_warn)

    lines = [
        f"# cvesieve v{__version__}",
        f"**Scanner:** {scanner} | **Total CVEs:** {total}",
        "",
    ]

    def _nvd_link(cve_id: str) -> str:
        return f"[{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})"

    def render_tier(tier: Tier, label: str, items: list[ClassifiedFinding]) -> None:
        lines.append(f"## {label} ({len(items)})")
        lines.append("")
        if not items:
            lines.append("_(none)_")
        else:
            lines.append("| CVE ID | Severity | Package | EPSS | Vector | Reason |")
            lines.append("|--------|----------|---------|------|--------|--------|")
            for cf in items:
                ef = cf.enriched
                f = ef.finding
                pkg = f"{f.package_name} {f.installed_version}"
                lines.append(
                    f"| {_nvd_link(f.cve_id)} | {f.severity} | {pkg} "
                    f"| {_pct(ef.epss_score)} | {_vector_short(ef.attack_vector)} | {cf.reason} |"
                )
        lines.append("")

    show_all = tier_filter == "all"
    if show_all or tier_filter == "block":
        render_tier(Tier.BLOCK, "BLOCK", by_tier[Tier.BLOCK])
    if show_all or tier_filter == "warn":
        render_tier(Tier.WARN, "WARN", by_tier[Tier.WARN])
    if show_all or tier_filter == "suppress":
        render_tier(Tier.SUPPRESS, "SUPPRESS", by_tier[Tier.SUPPRESS])

    lines.append(f"**Summary:** {total} total → {n_block} block, {len(by_tier[Tier.WARN])} warn, "
                 f"{len(by_tier[Tier.SUPPRESS])} suppress ({noise_pct:.1f}% noise reduction)")
    return "\n".join(lines)


_TIER_TO_SARIF_LEVEL = {
    Tier.BLOCK: "error",
    Tier.WARN: "warning",
    Tier.SUPPRESS: "note",
}


def format_sarif(
    findings: list[ClassifiedFinding],
    scanner: str = "unknown",
    **kwargs: object,
) -> str:
    """SARIF 2.1.0 JSON output."""
    results = []
    rules = []
    rule_ids_seen: set[str] = set()

    for cf in findings:
        ef = cf.enriched
        f = ef.finding
        cve_id = f.cve_id

        if cve_id not in rule_ids_seen:
            rule_ids_seen.add(cve_id)
            rules.append({
                "id": cve_id,
                "shortDescription": {"text": f"{cve_id} in {f.package_name}"},
                "helpUri": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        results.append({
            "ruleId": cve_id,
            "level": _TIER_TO_SARIF_LEVEL[cf.tier],
            "message": {"text": cf.reason},
            "properties": {
                "severity": f.severity,
                "package": f.package_name,
                "version": f.installed_version,
                "fixed_version": f.fixed_version,
                "epss_score": ef.epss_score,
                "attack_vector": ef.attack_vector,
                "in_kev": ef.in_kev,
                "days_since_published": ef.days_since_published,
                "tier": cf.tier.value,
            },
        })

    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cvesieve",
                    "version": __version__,
                    "informationUri": "https://github.com/cvesieve/cvesieve",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
