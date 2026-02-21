"""
SARIF parser — handles output from Docker Scout, Trivy, and Grype.

Returns a deduplicated list of Finding objects.
Never crashes on missing fields — sets them to None and continues.
"""
from urllib.parse import unquote
from cvesieve.models import Finding

# SARIF result level → severity fallback when no explicit severity in properties
_LEVEL_TO_SEVERITY = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "LOW",
}

# Ordered list of property keys to check for CVSS vector string
_VECTOR_KEYS = [
    "cvssV3_vectorString",
    "cvssV2_vectorString",
    "security-severity",  # Trivy sometimes embeds score here, not vector — we skip non-vector values
]


def _find_cvss_vector(properties: dict) -> str | None:
    for key in ("cvssV3_vectorString", "cvssV2_vectorString"):
        value = properties.get(key)
        if value and isinstance(value, str) and "AV:" in value:
            return value
    return None


def _find_severity(properties: dict, level: str) -> str:
    for key in ("cvssV3_severity", "cvssV2_severity", "severity"):
        value = properties.get(key)
        if value and isinstance(value, str):
            return value.upper()
    return _LEVEL_TO_SEVERITY.get(level, "UNKNOWN")


def _parse_purl(purl: str) -> tuple[str, str]:
    """Parse a Package URL (PURL) into (name, version).

    Format: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>
    Example: pkg:deb/debian/tar@1.35%2Bdfsg-3.1?os_distro=trixie
    """
    try:
        # Strip "pkg:" prefix and qualifiers
        body = purl[4:] if purl.startswith("pkg:") else purl
        body = body.split("?")[0].split("#")[0]
        # Split on @ for version
        if "@" in body:
            path, version = body.rsplit("@", 1)
            version = unquote(version)
        else:
            path, version = body, ""
        # Name is the last path component
        name = unquote(path.split("/")[-1])
        return name, version
    except Exception:
        return "unknown", ""


def _parse_package(locations: list, properties: dict) -> tuple[str, str]:
    # Try logicalLocations first (Trivy, Grype)
    for loc in locations:
        for logical in loc.get("logicalLocations", []):
            name = logical.get("name", "")
            fqn = logical.get("fullyQualifiedName", "")
            if "@" in fqn:
                pkg_name, version = fqn.rsplit("@", 1)
                return pkg_name.strip(), version.strip()
            if name:
                return name.strip(), ""

    # Fall back to PURLs (Docker Scout)
    purls = properties.get("purls", [])
    if purls:
        return _parse_purl(purls[0])

    return "unknown", ""


def parse_sarif(data: dict) -> list[Finding]:
    if "runs" not in data or "version" not in data:
        raise ValueError("Input is not valid SARIF — missing 'version' or 'runs'")

    runs = data.get("runs", [])
    if not runs:
        return []

    findings: dict[str, Finding] = {}

    for run in runs:
        driver = run.get("tool", {}).get("driver", {})
        scanner = driver.get("name", "unknown")

        # Build rules lookup: rule_id → rule properties
        rules = {}
        for rule in driver.get("rules", []):
            rule_id = rule.get("id")
            if rule_id:
                rules[rule_id] = rule

        for result in run.get("results", []):
            cve_id = result.get("ruleId", "")
            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            # Already seen this CVE — deduplicate (keep first occurrence)
            if cve_id in findings:
                continue

            rule = rules.get(cve_id, {})
            properties = rule.get("properties", {})
            level = result.get("level", "none")

            cvss_vector = _find_cvss_vector(properties)
            severity = _find_severity(properties, level)
            published_date = properties.get("published")
            description = rule.get("shortDescription", {}).get("text") or result.get("message", {}).get("text")

            try:
                package_name, installed_version = _parse_package(result.get("locations", []), properties)
            except Exception:
                package_name, installed_version = "unknown", ""

            # fixed_version: try rule properties, not always present
            fixed_version = None
            fix_versions = properties.get("fix-versions") or properties.get("fixedVersion") or properties.get("fixed_version")
            if fix_versions:
                if isinstance(fix_versions, list) and fix_versions:
                    fixed_version = fix_versions[0]
                elif isinstance(fix_versions, str):
                    fixed_version = fix_versions

            findings[cve_id] = Finding(
                cve_id=cve_id,
                severity=severity,
                package_name=package_name,
                installed_version=installed_version,
                fixed_version=fixed_version,
                cvss_vector=cvss_vector,
                published_date=published_date,
                scanner=scanner,
                description=description,
            )

    return list(findings.values())
