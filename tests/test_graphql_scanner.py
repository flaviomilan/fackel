"""Tests for the GraphQL security scanner tool."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from tools.scanning.graphql_scanner import (
    _probe_alias_batching,
    _probe_array_batching,
    _probe_field_suggestions,
    _probe_get_method,
    _probe_introspection,
    graphql_scan,
)


# ── Introspection probe ───────────────────────────────────────────────────


class TestProbeIntrospection:
    """Verify introspection detection logic."""

    @patch("tools.scanning.graphql_scanner.get_session")
    def test_detects_exposed_schema(self, mock_session):
        schema = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {"name": "Query", "kind": "OBJECT", "fields": [{"name": "users"}]},
                        {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "createUser"}]},
                        {"name": "User", "kind": "OBJECT", "fields": [{"name": "id"}]},
                    ],
                }
            }
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = schema
        mock_session.return_value.post.return_value = mock_resp

        enabled, issues, summary = _probe_introspection("https://example.com/graphql", {})
        assert enabled is True
        assert len(issues) == 1
        assert issues[0]["severity"] == "medium"
        assert summary["has_mutations"] is True

    @patch("tools.scanning.graphql_scanner.get_session")
    def test_disabled_introspection(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_session.return_value.post.return_value = mock_resp

        enabled, issues, summary = _probe_introspection("https://example.com/graphql", {})
        assert enabled is False
        assert issues == []

    @patch("tools.scanning.graphql_scanner.get_session")
    def test_handles_request_error(self, mock_session):
        import requests

        mock_session.return_value.post.side_effect = requests.RequestException("timeout")

        enabled, issues, summary = _probe_introspection("https://example.com/graphql", {})
        assert enabled is False
        assert issues == []


# ── Alias batching probe ──────────────────────────────────────────────────


class TestProbeAliasBatching:
    """Verify alias batching detection."""

    @patch("tools.scanning.graphql_scanner.get_session")
    def test_detects_alias_batching(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"a": "Query", "b": "Query", "c": "Query"}}
        mock_session.return_value.post.return_value = mock_resp

        issues = _probe_alias_batching("https://example.com/graphql", {})
        assert len(issues) == 1
        assert issues[0]["severity"] == "low"

    @patch("tools.scanning.graphql_scanner.get_session")
    def test_no_alias_batching(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"errors": [{"message": "not allowed"}]}
        mock_session.return_value.post.return_value = mock_resp

        issues = _probe_alias_batching("https://example.com/graphql", {})
        assert issues == []


# ── Array batching probe ──────────────────────────────────────────────────


class TestProbeArrayBatching:
    """Verify array batching detection."""

    @patch("tools.scanning.graphql_scanner.get_session")
    def test_detects_array_batching(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"data": {"__typename": "Query"}},
            {"data": {"__typename": "Query"}},
        ]
        mock_session.return_value.post.return_value = mock_resp

        issues = _probe_array_batching("https://example.com/graphql", {})
        assert len(issues) == 1

    @patch("tools.scanning.graphql_scanner.get_session")
    def test_no_array_batching(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_session.return_value.post.return_value = mock_resp

        issues = _probe_array_batching("https://example.com/graphql", {})
        assert issues == []


# ── GET method probe ──────────────────────────────────────────────────────


class TestProbeGetMethod:
    """Verify GET method query detection."""

    @patch("tools.scanning.graphql_scanner.get_session")
    def test_detects_get_method(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"__typename": "Query"}}
        mock_session.return_value.get.return_value = mock_resp

        issues = _probe_get_method(
            "https://example.com/graphql",
            {"User-Agent": "test"},
        )
        assert len(issues) == 1
        assert issues[0]["severity"] == "info"


# ── Field suggestions probe ──────────────────────────────────────────────


class TestProbeFieldSuggestions:
    """Verify field suggestion detection."""

    @patch("tools.scanning.graphql_scanner.get_session")
    def test_detects_field_suggestions(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = 'Did you mean "__typename"?'
        mock_session.return_value.post.return_value = mock_resp

        issues = _probe_field_suggestions("https://example.com/graphql", {})
        assert len(issues) == 1

    @patch("tools.scanning.graphql_scanner.get_session")
    def test_no_field_suggestions(self, mock_session):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"errors": [{"message": "unknown field"}]}'
        mock_session.return_value.post.return_value = mock_resp

        issues = _probe_field_suggestions("https://example.com/graphql", {})
        assert issues == []


# ── Full tool integration ─────────────────────────────────────────────────


class TestGraphqlScan:
    """Verify the full graphql_scan tool function."""

    @patch("tools.scanning.graphql_scanner._probe_field_suggestions", return_value=[])
    @patch("tools.scanning.graphql_scanner._probe_get_method", return_value=[])
    @patch("tools.scanning.graphql_scanner._probe_array_batching", return_value=[])
    @patch("tools.scanning.graphql_scanner._probe_alias_batching", return_value=[])
    @patch("tools.scanning.graphql_scanner._probe_introspection", return_value=(False, [], {}))
    def test_no_issues_detected(self, *_probes):
        result = graphql_scan.invoke({"url": "https://example.com/graphql"})
        assert result["status"] == "ok"
        assert result["data"]["issues"] == []

    @patch("tools.scanning.graphql_scanner._probe_field_suggestions", return_value=[])
    @patch("tools.scanning.graphql_scanner._probe_get_method", return_value=[])
    @patch("tools.scanning.graphql_scanner._probe_array_batching", return_value=[])
    @patch("tools.scanning.graphql_scanner._probe_alias_batching", return_value=[])
    @patch(
        "tools.scanning.graphql_scanner._probe_introspection",
        return_value=(
            True,
            [{"issue": "Introspection enabled", "severity": "medium", "detail": "exposed"}],
            {"total_types": 5},
        ),
    )
    def test_issues_detected(self, *_probes):
        result = graphql_scan.invoke({"url": "https://example.com/graphql"})
        assert result["status"] == "ok"
        assert result["data"]["total_issues"] == 1
        assert result["data"]["introspection_enabled"] is True
