"""CloudBrute — cloud infrastructure enumeration.

Enumerates cloud resources (storage buckets, apps, databases) across
AWS, Azure, GCP, and DigitalOcean for a given target keyword/domain.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    format_tool_output,
    get_tool_timeout,
    parse_jsonl,
    require_binary,
    run_command,
)

_TIMEOUT = 300


class CloudBruteInput(BaseModel):
    """Input for CloudBrute cloud enumeration."""

    keyword: str = Field(
        description=(
            "Target keyword or company name to enumerate cloud resources for "
            "(e.g. 'example', 'acme-corp'). CloudBrute generates permutations "
            "and checks for storage buckets, apps, and databases across AWS, "
            "Azure, GCP, and DigitalOcean."
        ),
    )
    cloud: str = Field(
        default="",
        description=(
            "Cloud provider to target: 'aws', 'azure', 'gcp', 'digitalocean', "
            "or empty string for all providers."
        ),
    )


_VALID_CLOUDS = frozenset({"aws", "azure", "gcp", "digitalocean", ""})


@tool(args_schema=CloudBruteInput)
def cloudbrute_enum(keyword: str, cloud: str = "") -> dict[str, Any]:
    """Enumerate cloud resources (buckets, apps, databases) for a keyword.

    Checks AWS S3, Azure Storage/Apps, GCP buckets/apps, and DigitalOcean
    Spaces for publicly accessible resources matching the keyword.
    Discovers misconfigured cloud assets that may expose sensitive data.
    """
    keyword = keyword.strip()
    if not keyword:
        raise ToolException("cloudbrute_enum: keyword must not be empty")

    cloud = cloud.strip().lower()
    if cloud not in _VALID_CLOUDS:
        raise ToolException(
            f"cloudbrute_enum: invalid cloud provider '{cloud}'. "
            f"Use one of: aws, azure, gcp, digitalocean, or empty for all."
        )

    require_binary("cloudbrute", "cloudbrute_enum")

    cmd = [
        "cloudbrute",
        "-d",
        keyword,
        "-t",
        "80",
        "-T",
        "10",
        "-w",
        "-",
    ]

    if cloud:
        cmd.extend(["-c", cloud])

    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("cloudbrute_enum", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"cloudbrute_enum: {exc}") from exc

    results: list[dict[str, str]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # CloudBrute outputs lines with format: [provider] resource_url
        for raw in parse_jsonl(line):
            results.append(
                {
                    "provider": raw.get("provider", ""),
                    "url": raw.get("url", raw.get("resource", "")),
                    "status": raw.get("status", ""),
                }
            )
            break
        else:
            # Plain text output — parse [provider] url pattern
            if line.startswith("["):
                bracket_end = line.find("]")
                if bracket_end > 0:
                    provider = line[1:bracket_end].strip()
                    url = line[bracket_end + 1 :].strip()
                    if url:
                        results.append({"provider": provider, "url": url, "status": "found"})

    if not results:
        if code:
            raise ToolException(f"cloudbrute_enum: {stderr.strip() or 'scan failed'}")
        return format_tool_output(
            "cloudbrute_enum",
            keyword,
            "ok",
            data={"results": [], "count": 0, "message": "no cloud resources found"},
        )

    return format_tool_output(
        "cloudbrute_enum",
        keyword,
        "ok",
        data={"results": results, "count": len(results)},
    )


cloudbrute_enum.handle_tool_error = True
