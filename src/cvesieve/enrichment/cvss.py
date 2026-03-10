"""
Extract fields from CVSS v3.x or v2 vector strings.

CVSS v3.x example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSS v2 example:   AV:N/AC:L/Au:N/C:P/I:P/A:P

Attack vector returns one of: "NETWORK", "ADJACENT", "LOCAL", "PHYSICAL", or None.
Scope returns one of: "CHANGED", "UNCHANGED", or None (v2 has no Scope field).
None means the vector was missing, unparseable, or the field doesn't exist in that version.
"""

_AV_MAP = {
    "N": "NETWORK",
    "A": "ADJACENT",
    "L": "LOCAL",
    "P": "PHYSICAL",
}

_SCOPE_MAP = {
    "C": "CHANGED",
    "U": "UNCHANGED",
}


def extract_attack_vector(cvss_vector: str | None) -> str | None:
    if not cvss_vector:
        return None

    for component in cvss_vector.split("/"):
        if component.startswith("AV:"):
            code = component[3:]
            return _AV_MAP.get(code)

    return None


def extract_scope(cvss_vector: str | None) -> str | None:
    """Extract Scope from a CVSS v3.x vector string.

    Returns "CHANGED", "UNCHANGED", or None.
    Always returns None for CVSS v2 vectors (no Scope field).
    """
    if not cvss_vector:
        return None
    # CVSS v2 vectors don't start with "CVSS:" prefix and have no S: component
    if not cvss_vector.startswith("CVSS:"):
        return None

    for component in cvss_vector.split("/"):
        if component.startswith("S:"):
            code = component[2:]
            return _SCOPE_MAP.get(code)

    return None
