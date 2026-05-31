"""Tests for github_repo_discovery — list an org/user's public repos."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from fackel.tools.osint.github_repos import github_repo_discovery


def _resp(json_data: object, status: int = 200) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


class TestGithubRepoDiscovery:
    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_circuits()
        yield
        reset_circuits()

    @patch("fackel.tools.osint.github_repos.get_session")
    def test_lists_repos(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp(
            [
                {
                    "full_name": "acme/site",
                    "html_url": "https://github.com/acme/site",
                    "language": "Go",
                    "pushed_at": "2024-01-01T00:00:00Z",
                    "fork": False,
                },
                {
                    "full_name": "acme/api",
                    "html_url": "https://github.com/acme/api",
                    "language": "Python",
                    "pushed_at": "2024-02-01T00:00:00Z",
                    "fork": True,
                },
            ]
        )
        result = github_repo_discovery.invoke({"org": "acme"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 2
        assert result["data"]["repositories"][0]["html_url"] == "https://github.com/acme/site"

    @patch("fackel.tools.osint.github_repos.get_session")
    def test_accepts_github_url_and_targets_users_endpoint(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp([])
        github_repo_discovery.invoke({"org": "https://github.com/acme"})
        called_url = mock_gs.return_value.get.call_args[0][0]
        assert called_url.endswith("/users/acme/repos")

    @patch("fackel.tools.osint.github_repos.get_session")
    def test_404_returns_ok_empty(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp({"message": "Not Found"}, status=404)
        result = github_repo_discovery.invoke({"org": "nonexistent-xyz"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 0

    @patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test"})
    @patch("fackel.tools.osint.github_repos.get_session")
    def test_token_sent_in_header(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp([])
        github_repo_discovery.invoke({"org": "acme"})
        headers = mock_gs.return_value.get.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer ghp_test"

    @patch("fackel.tools.osint.github_repos.get_session")
    def test_rate_limited_raises(self, mock_gs: MagicMock) -> None:
        mock_gs.return_value.get.return_value = _resp({"message": "rate limited"}, status=403)
        result = github_repo_discovery.invoke({"org": "acme"})
        assert "rate limited" in result or "GITHUB_TOKEN" in result
