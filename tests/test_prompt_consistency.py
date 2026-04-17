"""Schema/prompt drift guard.

For each agent, every Pydantic ``args_schema`` field of every tool
must be mentioned somewhere in the composed system prompt — otherwise
the LLM has no documented way to populate that parameter.

The test does *not* assert the inverse (it's fine for prompts to talk
about contextual concepts that aren't direct fields), but it does
catch the most common drift: a tool gains/renames a field and the
prompt is left behind.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pytest

from fackel.agents.osint import agent as osint_agent
from fackel.agents.port_scan import agent as port_scan_agent
from fackel.agents.vuln_scan import agent as vuln_scan_agent
from fackel.prompts import compose_prompt

# Field names that are conventional/structural — the prompts often
# refer to them at a higher level rather than by literal token.
_GENERIC_FIELDS = frozenset(
    {
        "kwargs",
        "args",
    }
)


def _agent_specs() -> list[tuple[str, list[Any], tuple[str, ...], bool]]:
    """Return ``(agent_name, tools, compose_args, check_fields)`` per agent.

    ``check_fields`` is ``False`` for agents whose prompt deliberately defers
    per-tool parameter documentation to the tool schemas (the OSINT skill is
    self-contained and says so explicitly). For those agents we still assert
    every tool is *named* in the prompt, but not every individual field.
    """
    return [
        (
            "osint",
            osint_agent.TOOLS,
            # The OSINT agent composes only the self-contained skill; per-tool
            # parameter details live in each tool's schema (see agent.py).
            ("osint",),
            False,
        ),
        (
            "port_scan",
            port_scan_agent.TOOLS,
            (
                "port_scan",
                "tools/port_scanning",
                "contracts/nmap",
            ),
            True,
        ),
        (
            "vuln_scan",
            vuln_scan_agent.TOOLS,
            (
                "vuln_scan",
                "tools/vuln_scanning",
                "tools/security_headers",
                "tools/sqli_scanning",
                "tools/jwt_analysis",
                "tools/ssrf_scanning",
                "tools/api_fuzzing",
                "tools/xss_scanning",
                "tools/wordpress_scanning",
                "tools/graphql_scanning",
                "tools/web_crawling",
                "tools/http_probing",
                "contracts/nuclei",
                "contracts/httpx",
                "strategy/error_resilience",
            ),
            True,
        ),
    ]


def _schema_fields(tool: Any) -> Iterable[str]:
    schema = getattr(tool, "args_schema", None)
    if schema is None:
        return ()
    fields = getattr(schema, "model_fields", None)
    if not fields:
        return ()
    return [name for name in fields if name not in _GENERIC_FIELDS]


@pytest.mark.parametrize("agent_name,tools,compose_args,check_fields", _agent_specs())
def test_tool_fields_documented_in_prompt(
    agent_name: str, tools: list[Any], compose_args: tuple[str, ...], check_fields: bool
) -> None:
    prompt = compose_prompt(*compose_args)
    missing: list[str] = []
    for tool in tools:
        tool_name = getattr(tool, "name", "")
        if tool_name and tool_name not in prompt:
            missing.append(f"tool '{tool_name}' (no mention in prompt)")
            continue
        if not check_fields:
            continue
        for field in _schema_fields(tool):
            if field not in prompt:
                missing.append(f"{tool_name}.{field}")
    assert not missing, (
        f"Agent '{agent_name}' has tool fields/names not mentioned in any "
        f"prompt section — drift between schema and docs:\n  - " + "\n  - ".join(missing)
    )
