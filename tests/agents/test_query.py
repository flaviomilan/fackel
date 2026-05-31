"""Tests for the natural-language graph query agent."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from fackel.agents.query import answer_query
from fackel.domain import InformationCandidate, InformationType
from fackel.persistence.store import InformationStore


def _store(tmp_path: Path) -> InformationStore:
    store = InformationStore("s", tmp_path)
    store.ingest(
        [
            InformationCandidate(
                type=InformationType.SUBDOMAIN,
                normalized_value="api.example.com",
                original_value="api.example.com",
                source_execution_id="e",
                source_tool="subfinder_enum",
                phase="osint",
            )
        ],
        phase="osint",
    )
    return store


class TestAnswerQuery:
    @patch("fackel.agents.query.build_llm")
    def test_returns_llm_answer_with_graph_context(
        self, mock_build: MagicMock, tmp_path: Path
    ) -> None:
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content="There is 1 subdomain: api.example.com")
        mock_build.return_value = mock_llm

        answer = answer_query(_store(tmp_path), "What subdomains were found?")

        assert answer == "There is 1 subdomain: api.example.com"
        # The graph context (with the discovered entity) was sent to the model.
        messages = mock_llm.invoke.call_args[0][0]
        human_content = messages[-1].content
        assert "api.example.com" in human_content
        assert "QUESTION: What subdomains were found?" in human_content

    @patch("fackel.agents.query.build_llm")
    def test_non_string_content_coerced(self, mock_build: MagicMock, tmp_path: Path) -> None:
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = MagicMock(content=["chunk-a", "chunk-b"])
        mock_build.return_value = mock_llm
        answer = answer_query(_store(tmp_path), "?")
        assert isinstance(answer, str)
