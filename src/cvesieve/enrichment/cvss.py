"""
Extract attack vector from a CVSS v3.x or v2 vector string.

CVSS v3.x example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSS v2 example:   AV:N/AC:L/Au:N/C:P/I:P/A:P

Returns one of: "NETWORK", "ADJACENT", "LOCAL", "PHYSICAL", or None.
None means the vector was missing or unparseable — treat as unknown (fail open).
"""

_AV_MAP = {
    "N": "NETWORK",
    "A": "ADJACENT",
    "L": "LOCAL",
    "P": "PHYSICAL",
}


def extract_attack_vector(cvss_vector: str | None) -> str | None:
    if not cvss_vector:
        return None

    for component in cvss_vector.split("/"):
        if component.startswith("AV:"):
            code = component[3:]
            return _AV_MAP.get(code)

    return None
