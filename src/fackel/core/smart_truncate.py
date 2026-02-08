"""Smart truncation strategies for different tool outputs."""

from __future__ import annotations

import json
import re
from typing import Any


def smart_truncate(
    tool_output: str,
    tool_name: str,
    max_chars: int = 32000,
    preserve_start: int = 5000,
    preserve_end: int = 2000
) -> str:
    """
    Apply tool-specific truncation strategy to preserve most relevant content.
    
    Args:
        tool_output: Raw tool output
        tool_name: Name of the tool (for strategy selection)
        max_chars: Maximum characters to keep
        preserve_start: Characters to keep from start (default strategy)
        preserve_end: Characters to keep from end (default strategy)
    
    Returns:
        Truncated output with most relevant content preserved
    """
    if len(tool_output) <= max_chars:
        return tool_output
    
    # Apply tool-specific strategy
    if tool_name in ("nuclei_scan", "nmap_port_scan", "httpx_scan"):
        return _truncate_structured_scan(tool_output, tool_name, max_chars)
    
    elif tool_name in ("katana_crawl", "feroxbuster_scan"):
        return _truncate_url_list(tool_output, max_chars)
    
    elif tool_name in ("dnsdumpster_lookup", "virustotal_subdomain_enum"):
        return _truncate_dns_records(tool_output, max_chars)
    
    # Default: preserve start + end
    return _truncate_default(tool_output, preserve_start, preserve_end)


def _truncate_structured_scan(output: str, tool_name: str, max_chars: int) -> str:
    """Prioritize high severity findings in structured scans."""
    
    # Try to parse as JSON first (nuclei often outputs JSON)
    try:
        data = json.loads(output)
        if isinstance(data, list):
            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(
                data,
                key=lambda x: severity_order.get(x.get("severity", "info"), 5)
            )
            
            # Take top findings until we hit max_chars
            truncated = []
            current_size = 0
            for finding in sorted_findings:
                finding_str = json.dumps(finding, indent=2)
                if current_size + len(finding_str) > max_chars:
                    break
                truncated.append(finding)
                current_size += len(finding_str)
            
            return json.dumps(truncated, indent=2) + f"\n\n... ({len(data) - len(truncated)} findings truncated)"
    except json.JSONDecodeError:
        pass
    
    # Text format: extract lines with severity keywords
    lines = output.split("\n")
    high_priority = []
    low_priority = []
    
    for line in lines:
        line_lower = line.lower()
        if any(keyword in line_lower for keyword in ["critical", "high", "severe", "alert"]):
            high_priority.append(line)
        elif any(keyword in line_lower for keyword in ["medium", "warning", "moderate"]):
            if len("\n".join(high_priority)) < max_chars * 0.7:
                high_priority.append(line)
            else:
                low_priority.append(line)
        else:
            low_priority.append(line)
    
    # Combine high priority first
    result = "\n".join(high_priority)
    
    # Add low priority until max
    remaining = max_chars - len(result)
    if remaining > 0 and low_priority:
        result += "\n\n[Lower priority findings:]\n"
        for line in low_priority:
            if len(result) + len(line) > max_chars:
                result += f"\n... ({len(low_priority) - low_priority.index(line)} lines truncated)"
                break
            result += line + "\n"
    
    return result


def _truncate_url_list(output: str, max_chars: int) -> str:
    """Deduplicate and truncate URL lists."""
    
    lines = output.split("\n")
    
    # Extract URLs
    urls = []
    for line in lines:
        # Match URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        matches = re.findall(url_pattern, line)
        if matches:
            urls.extend(matches)
        elif line.strip():
            urls.append(line.strip())
    
    # Deduplicate
    unique_urls = list(dict.fromkeys(urls))  # Preserve order
    
    # Prioritize interesting URLs (with parameters, paths, extensions)
    interesting = []
    basic = []
    
    for url in unique_urls:
        if any(indicator in url for indicator in ["?", "=", ".php", ".asp", "admin", "api", "auth", "login"]):
            interesting.append(url)
        else:
            basic.append(url)
    
    # Build result
    result_lines = ["[Interesting URLs]"]
    result_lines.extend(interesting[:500])  # Max 500 interesting URLs
    
    if basic and len("\n".join(result_lines)) < max_chars * 0.8:
        result_lines.append("\n[Other URLs]")
        result_lines.extend(basic[:200])  # Max 200 basic URLs
    
    result = "\n".join(result_lines)
    
    if len(result) > max_chars:
        return result[:max_chars] + f"\n... ({len(unique_urls)} total unique URLs)"
    
    return result + f"\n\nTotal unique URLs: {len(unique_urls)}"


def _truncate_dns_records(output: str, max_chars: int) -> str:
    """Aggregate DNS records by type."""
    
    lines = output.split("\n")
    
    # Group by record type
    records_by_type: dict[str, list[str]] = {}
    
    for line in lines:
        if not line.strip():
            continue
        
        # Detect record type
        record_type = "OTHER"
        if "A " in line or line.endswith(" A"):
            record_type = "A"
        elif "AAAA" in line:
            record_type = "AAAA"
        elif "MX" in line:
            record_type = "MX"
        elif "NS" in line:
            record_type = "NS"
        elif "TXT" in line:
            record_type = "TXT"
        elif "CNAME" in line:
            record_type = "CNAME"
        
        records_by_type.setdefault(record_type, []).append(line)
    
    # Build summary
    result_lines = []
    
    priority_types = ["MX", "NS", "TXT", "A", "AAAA", "CNAME", "OTHER"]
    
    for record_type in priority_types:
        if record_type not in records_by_type:
            continue
        
        records = records_by_type[record_type]
        result_lines.append(f"\n[{record_type} Records] ({len(records)} total)")
        
        # Show first 50 of each type
        for record in records[:50]:
            if len("\n".join(result_lines)) > max_chars:
                result_lines.append(f"... ({len(records) - 50} more {record_type} records truncated)")
                break
            result_lines.append(record)
    
    return "\n".join(result_lines)


def _truncate_default(output: str, preserve_start: int, preserve_end: int) -> str:
    """Default truncation: preserve start and end."""
    if len(output) <= preserve_start + preserve_end:
        return output
    
    return (
        output[:preserve_start]
        + f"\n\n... ({len(output) - preserve_start - preserve_end} chars truncated) ...\n\n"
        + output[-preserve_end:]
    )


def estimate_tokens(text: str) -> int:
    """
    Rough estimation of token count (1 token ≈ 4 characters for English).
    
    For accurate counting, use tiktoken library.
    """
    return len(text) // 4
