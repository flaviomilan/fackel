"""IP infrastructure classifier — pure function, no I/O.

Classifies an IP address as ``cdn``, ``cloud``, ``direct_host``, or ``isp``
based on ASN and organisation metadata returned by ipinfo / RIPEstat.

The classifier uses a static lookup of well-known ASNs and organisation
name patterns.  No LLM call, no network request.
"""

from __future__ import annotations

from typing import Literal

IpClass = Literal["cdn", "cloud", "direct_host", "isp"]


_CDN_ASNS: frozenset[int] = frozenset(
    {
        13335,
        20940,
        16625,
        54113,
        16509,
        13249,
        209242,
        395747,
        14789,
        30148,
        19551,
        22207,
        15169,
    }
)


_CLOUD_ASNS: frozenset[int] = frozenset(
    {
        16509,
        14618,
        8075,
        15169,
        396982,
        63949,
        20473,
        24940,
        16276,
        14061,
        201011,
        13414,
        36351,
        19871,
        46606,
        22612,
        132203,
        45090,
        37963,
    }
)


_CDN_ORG_KEYWORDS: tuple[str, ...] = (
    "cloudflare",
    "akamai",
    "fastly",
    "cloudfront",
    "incapsula",
    "imperva",
    "limelight",
    "edgecast",
    "stackpath",
    "sucuri",
    "cdn77",
    "keycdn",
    "bunny",
    "maxcdn",
)


_CLOUD_ORG_KEYWORDS: tuple[str, ...] = (
    "amazon",
    "aws",
    "microsoft",
    "azure",
    "google cloud",
    "digitalocean",
    "linode",
    "vultr",
    "choopa",
    "hetzner",
    "ovh",
    "oracle cloud",
    "ibm cloud",
    "softlayer",
    "alibaba",
    "tencent",
    "rackspace",
    "scaleway",
    "upcloud",
    "contabo",
)


def _parse_asn(raw: str | int | None) -> int | None:
    """Extract an integer ASN from values like ``"AS13335"`` or ``13335``."""
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw
    s = str(raw).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    try:
        return int(s)
    except ValueError:
        return None


def classify_ip(
    *,
    org: str = "",
    asn: str | int | None = None,
    asn_name: str = "",
    hostname: str = "",
    anycast: bool = False,
    target_domain: str = "",
) -> IpClass:
    """Classify an IP's infrastructure role.

    Parameters
    ----------
    org:
        Organisation name (from ipinfo ``org`` field).
    asn:
        AS number — string like ``"AS13335"`` or integer.
    asn_name:
        ASN name/description (from RIPEstat ``asn_name``).
    hostname:
        PTR hostname or ipinfo ``hostname`` field.
    anycast:
        Whether ipinfo flagged this IP as anycast.
    target_domain:
        The scan target domain — if the PTR matches this, it's direct_host.

    Returns
    -------
    One of ``"cdn"``, ``"cloud"``, ``"direct_host"``, ``"isp"``.
    """
    asn_int = _parse_asn(asn)
    org_lower = (org or "").lower()
    asn_name_lower = (asn_name or "").lower()
    combined_text = f"{org_lower} {asn_name_lower}"

    if anycast:
        return "cdn"

    if asn_int and asn_int in _CDN_ASNS:
        return "cdn"

    for kw in _CDN_ORG_KEYWORDS:
        if kw in combined_text:
            return "cdn"

    if target_domain and hostname:
        target_lower = target_domain.lower().rstrip(".")
        hostname_lower = hostname.lower().rstrip(".")
        if hostname_lower == target_lower or hostname_lower.endswith(f".{target_lower}"):
            return "direct_host"

    if asn_int and asn_int in _CLOUD_ASNS:
        return "cloud"

    for kw in _CLOUD_ORG_KEYWORDS:
        if kw in combined_text:
            return "cloud"

    return "isp"
