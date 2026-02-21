"""
cvesieve CLI entrypoint.

Stdout: results (clean for piping).
Stderr: progress, warnings, cache status.
Exit 1 if any BLOCK findings, exit 0 otherwise.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from cvesieve import __version__
from cvesieve.engine import classify
from cvesieve.enrichment.cvss import extract_attack_vector
from cvesieve.enrichment.epss import load_epss, lookup_epss
from cvesieve.enrichment.kev import is_in_kev, load_kev
from cvesieve.enrichment.nvd import fetch_missing_data
from cvesieve.models import ClassifiedFinding, EnrichedFinding, Tier
from cvesieve.output import format_json, format_summary, format_table
from cvesieve.parser import parse_sarif

DEFAULT_CACHE_DIR = Path.home() / ".cvesieve" / "cache"

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.upper(), 0)


def _apply_severity_filter(
    classified: list[ClassifiedFinding], min_severity: str
) -> list[ClassifiedFinding]:
    """Remove findings below min_severity — but never remove BLOCK findings (KEV always wins)."""
    threshold = _severity_rank(min_severity)
    return [
        cf for cf in classified
        if cf.tier == Tier.BLOCK or _severity_rank(cf.enriched.finding.severity) >= threshold
    ]


def _apply_block_severity_cap(
    classified: list[ClassifiedFinding], min_block_severity: str
) -> list[ClassifiedFinding]:
    """
    Cap findings below min_block_severity at WARN — they can never be BLOCK
    unless they're in KEV (KEV always wins).
    """
    threshold = _severity_rank(min_block_severity)
    result = []
    for cf in classified:
        if (
            cf.tier == Tier.BLOCK
            and not cf.enriched.in_kev
            and _severity_rank(cf.enriched.finding.severity) < threshold
        ):
            from cvesieve.models import ClassifiedFinding as CF
            result.append(CF(
                enriched=cf.enriched,
                tier=Tier.WARN,
                reason=cf.reason + f" [capped at WARN — severity below {min_block_severity.upper()}]",
            ))
        else:
            result.append(cf)
    return result


def _days_since(date_str: str | None) -> int | None:
    if not date_str:
        return None
    try:
        published = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return (now - published).days
    except Exception:
        return None


@click.command()
@click.argument("input_file", required=False, type=click.Path(exists=True, path_type=Path))
@click.option("-f", "--format", "output_format", type=click.Choice(["table", "json", "summary"]), default="table", show_default=True)
@click.option("-o", "--output", "output_file", type=click.Path(path_type=Path), default=None)
@click.option("--epss-threshold", type=float, default=0.001, show_default=True, help="EPSS score threshold (0.0-1.0)")
@click.option("--age-threshold", type=int, default=14, show_default=True, help="Minimum days since publication for downgrade")
@click.option("--cache-dir", type=click.Path(path_type=Path), default=DEFAULT_CACHE_DIR, show_default=True)
@click.option("--no-cache", is_flag=True, default=False, help="Force re-download of EPSS and KEV data")
@click.option("--tier", type=click.Choice(["block", "warn", "suppress", "all"]), default="all", show_default=True)
@click.option("--min-severity", type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False), default="low", show_default=True, help="Ignore findings below this severity (BLOCK findings are always shown regardless)")
@click.option("--min-block-severity", type=click.Choice(["low", "medium", "high", "critical"], case_sensitive=False), default="low", show_default=True, help="Cap findings below this severity at WARN — they cannot be BLOCK unless in KEV")
@click.option("--nvd-api-key", envvar="NVD_API_KEY", default=None, help="NVD API key for CVSS vector lookup (or set NVD_API_KEY env var). Get one free at https://nvd.nist.gov/developers/request-an-api-key")
@click.version_option(version=__version__, prog_name="cvesieve")
def main(
    input_file: Path | None,
    output_format: str,
    output_file: Path | None,
    epss_threshold: float,
    age_threshold: int,
    cache_dir: Path,
    no_cache: bool,
    tier: str,
    min_severity: str,
    min_block_severity: str,
    nvd_api_key: str | None,
) -> None:
    """Filter CVE scanner noise using real-world exploitability signals.

    INPUT_FILE: Path to SARIF JSON from Docker Scout, Trivy, or Grype.
    If omitted, reads from stdin.
    """
    # 1. Read SARIF input
    try:
        if input_file:
            raw = input_file.read_text()
        else:
            if sys.stdin.isatty():
                click.echo("Error: no input file given and stdin is a terminal.", err=True)
                sys.exit(1)
            raw = sys.stdin.read()
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        click.echo(f"Error: invalid JSON — {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error reading input: {e}", err=True)
        sys.exit(1)

    # 2. Parse SARIF
    try:
        findings = parse_sarif(data)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    scanner = data.get("runs", [{}])[0].get("tool", {}).get("driver", {}).get("name", "unknown")

    if not findings:
        click.echo("No CVE findings in input.", err=True)
        sys.exit(0)

    # 3. Load enrichment data
    epss_scores = load_epss(cache_dir, no_cache=no_cache)
    kev_set = load_kev(cache_dir, no_cache=no_cache)

    # 3b. NVD lookup for findings missing vector or published date
    missing_nvd_ids = [f.cve_id for f in findings if not f.cvss_vector or not f.published_date]
    nvd_data = {}
    if missing_nvd_ids:
        nvd_data = fetch_missing_data(missing_nvd_ids, cache_dir, api_key=nvd_api_key, no_cache=no_cache)

    # 4. Enrich findings
    enriched = []
    for f in findings:
        epss_score, epss_pct = lookup_epss(epss_scores, f.cve_id)
        nvd = nvd_data.get(f.cve_id)
        cvss_vector = f.cvss_vector or (nvd.vector if nvd else None)
        attack_vector = extract_attack_vector(cvss_vector)
        in_kev = is_in_kev(kev_set, f.cve_id)
        published = f.published_date or (nvd.published if nvd else None)
        days = _days_since(published)

        enriched.append(EnrichedFinding(
            finding=f,
            epss_score=epss_score,
            epss_percentile=epss_pct,
            attack_vector=attack_vector,
            in_kev=in_kev,
            days_since_published=days,
        ))

    # 5. Classify
    classified = [classify(ef, epss_threshold=epss_threshold, age_threshold=age_threshold) for ef in enriched]

    # 5b. Cap low-severity findings at WARN (KEV always overrides)
    if min_block_severity.lower() != "low":
        classified = _apply_block_severity_cap(classified, min_block_severity)

    # 5c. Apply severity filter (BLOCK findings always pass through regardless)
    if min_severity.lower() != "low":
        before = len(classified)
        classified = _apply_severity_filter(classified, min_severity)
        filtered = before - len(classified)
        if filtered:
            click.echo(f"Filtered {filtered} finding(s) below {min_severity.upper()} severity.", err=True)

    # 6. Format output
    if output_format == "table":
        result = format_table(classified, scanner=scanner, tier_filter=tier)
    elif output_format == "json":
        result = format_json(classified, scanner=scanner, epss_threshold=epss_threshold, age_threshold=age_threshold)
    else:
        result = format_summary(classified, scanner=scanner)

    if output_file:
        output_file.write_text(result)
    else:
        click.echo(result)

    # 7. Exit code
    has_block = any(cf.tier == Tier.BLOCK for cf in classified)
    sys.exit(1 if has_block else 0)
