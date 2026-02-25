"""IP infrastructure classifier — pure function, no I/O.

Classifies an IP address as ``cdn``, ``cloud``, ``direct_host``, or ``isp``
based on ASN and organisation metadata returned by ipinfo / RIPEstat.

The classifier uses a static lookup of well-known ASNs and organisation
name patterns.  No LLM call, no network request.
"""

from __future__ import annotations

from typing import Literal

IpClass = Literal["cdn", "cloud", "direct_host", "isp"]


# ── Known CDN providers by ASN number ──────────────────────────────────

_CDN_ASNS: frozenset[int] = frozenset(
    {
        13335,  # Cloudflare
        20940,  # Akamai
        16625,  # Akamai
        54113,  # Fastly
        16509,  # Amazon CloudFront (shared ASN with AWS)
        13249,  # Incapsula / Imperva
        209242,  # Cloudflare (secondary)
        395747,  # Cloudflare (additional)
        14789,  # Limelight Networks
        30148,  # Sucuri
        19551,  # Incapsula
        22207,  # EdgeCast / Verizon Digital Media
        15169,  # Google (also cloud, but fronts as CDN often)
    }
)

# ── Known cloud providers by ASN number ────────────────────────────────

_CLOUD_ASNS: frozenset[int] = frozenset(
    {
        16509,  # Amazon AWS
        14618,  # Amazon AWS
        8075,  # Microsoft Azure
        15169,  # Google Cloud
        396982,  # Google Cloud
        63949,  # Linode / Akamai Cloud
        20473,  # Vultr / Choopa
        24940,  # Hetzner
        16276,  # OVH
        14061,  # DigitalOcean
        201011,  # Oracle Cloud
        13414,  # Twitter / X data centres
        36351,  # SoftLayer / IBM Cloud
        19871,  # Network Solutions
        46606,  # Unified Layer
        22612,  # Namecheap
        132203,  # Tencent Cloud
        45090,  # Tencent Cloud
        37963,  # Alibaba Cloud
    }
)

# ── Org-name substrings for CDN detection (lowercased) ─────────────────

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

# ── Org-name substrings for cloud detection (lowercased) ───────────────

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

    # ── Anycast is almost always CDN ───────────────────────────────
    if anycast:
        return "cdn"

    # ── Check CDN by ASN ───────────────────────────────────────────
    if asn_int and asn_int in _CDN_ASNS:
        return "cdn"

    # ── Check CDN by org/ASN name keywords ─────────────────────────
    for kw in _CDN_ORG_KEYWORDS:
        if kw in combined_text:
            return "cdn"

    # ── Direct-host: PTR hostname contains the target domain ───────
    if target_domain and hostname:
        target_lower = target_domain.lower().rstrip(".")
        hostname_lower = hostname.lower().rstrip(".")
        if hostname_lower == target_lower or hostname_lower.endswith(f".{target_lower}"):
            return "direct_host"

    # ── Check cloud by ASN ─────────────────────────────────────────
    if asn_int and asn_int in _CLOUD_ASNS:
        return "cloud"

    # ── Check cloud by org/ASN name keywords ───────────────────────
    for kw in _CLOUD_ORG_KEYWORDS:
        if kw in combined_text:
            return "cloud"

    # ── Default: ISP / unknown ─────────────────────────────────────
    return "isp"
