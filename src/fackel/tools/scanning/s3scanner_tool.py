"""S3Scanner — S3 bucket permission auditing.

Scans S3-compatible buckets for misconfigured permissions (public read,
public write, authenticated read) across AWS, GCP, and DigitalOcean Spaces.
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

_TIMEOUT = 120


class S3ScannerInput(BaseModel):
    """Input for S3Scanner bucket permission check."""

    bucket: str = Field(
        description=(
            "S3 bucket name to scan for permission misconfigurations "
            "(e.g. 'example-backup', 'acme-uploads'). Checks for public "
            "read, public write, and authenticated access across AWS S3, "
            "GCP Cloud Storage, and DigitalOcean Spaces."
        ),
    )
    provider: str = Field(
        default="aws",
        description=(
            "Cloud storage provider: 'aws' (Amazon S3), 'gcp' (Google "
            "Cloud Storage), or 'digitalocean' (Spaces). Defaults to 'aws'."
        ),
    )


_VALID_PROVIDERS = frozenset({"aws", "gcp", "digitalocean"})


@tool(args_schema=S3ScannerInput)
def s3scanner_scan(bucket: str, provider: str = "aws") -> dict[str, Any]:
    """Scan an S3 bucket for permission misconfigurations.

    Checks whether a bucket exists, is publicly listable, publicly
    writable, or allows authenticated access.  Covers AWS S3, GCP Cloud
    Storage, and DigitalOcean Spaces.
    """
    bucket = bucket.strip()
    if not bucket:
        raise ToolException("s3scanner_scan: bucket name must not be empty")

    provider = provider.strip().lower()
    if provider not in _VALID_PROVIDERS:
        raise ToolException(
            f"s3scanner_scan: invalid provider '{provider}'. Use one of: aws, gcp, digitalocean."
        )

    require_binary("s3scanner", "s3scanner_scan")

    cmd = [
        "s3scanner",
        "scan",
        "--bucket",
        bucket,
        "--provider",
        provider,
        "--json",
    ]

    try:
        code, out, stderr = run_command(cmd, timeout=get_tool_timeout("s3scanner_scan", _TIMEOUT))
    except Exception as exc:
        raise ToolException(f"s3scanner_scan: {exc}") from exc

    results: list[dict[str, Any]] = []
    for raw in parse_jsonl(out):
        result: dict[str, Any] = {
            "bucket": raw.get("bucket", raw.get("name", bucket)),
            "exists": raw.get("exists", raw.get("bucket_exists", None)),
            "public": raw.get("public", None),
            "permissions": {
                "read": raw.get("auth_users_read", raw.get("perm_read", None)),
                "write": raw.get("auth_users_write", raw.get("perm_write", None)),
                "read_acp": raw.get("auth_users_read_acp", None),
                "write_acp": raw.get("auth_users_write_acp", None),
                "full_control": raw.get("auth_users_full_control", None),
            },
            "num_objects": raw.get("num_objects", None),
            "size": raw.get("bucket_size", None),
            "region": raw.get("region", ""),
        }
        results.append(result)

    if not results:
        # Fallback: parse plain text output
        result_text = out.strip() or stderr.strip()
        if code and not result_text:
            raise ToolException(f"s3scanner_scan: {stderr.strip() or 'scan failed'}")
        return format_tool_output(
            "s3scanner_scan",
            bucket,
            "ok",
            data={
                "bucket": bucket,
                "provider": provider,
                "results": [],
                "message": result_text or "no findings",
            },
        )

    return format_tool_output(
        "s3scanner_scan",
        bucket,
        "ok",
        data={
            "bucket": bucket,
            "provider": provider,
            "results": results,
        },
    )


s3scanner_scan.handle_tool_error = True
