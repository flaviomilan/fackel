"""Test suite for token tracking functionality."""

import pytest
from fackel.core.token_tracker import TokenTracker, CostConfig, get_tracker, reset_tracker


def test_token_tracker_basic():
    """Test basic token tracking."""
    tracker = TokenTracker()
    
    # Track some usage
    tracker.track("planner", "gpt-4o-mini", input_tokens=1000, output_tokens=500)
    tracker.track("reporter", "gpt-4o-mini", input_tokens=5000, output_tokens=2000)
    
    # Check totals
    report = tracker.report()
    
    assert report["total_tokens"] == 8500
    assert "planner" in report["by_component"]
    assert report["by_component"]["planner"]["input_tokens"] == 1000
    assert report["by_component"]["planner"]["output_tokens"] == 500


def test_cost_calculation():
    """Test cost calculation for different models."""
    tracker = TokenTracker()
    
    # GPT-4o mini: $0.15 per 1M input, $0.60 per 1M output
    cost = tracker.calculate_cost("gpt-4o-mini", input_tokens=1_000_000, output_tokens=1_000_000)
    assert abs(cost - 0.75) < 0.01  # $0.15 + $0.60 = $0.75
    
    # Small amounts
    cost_small = tracker.calculate_cost("gpt-4o-mini", input_tokens=10_000, output_tokens=5_000)
    assert abs(cost_small - 0.0045) < 0.0001  # (10k * 0.15 + 5k * 0.60) / 1M


def test_global_tracker():
    """Test global tracker singleton."""
    reset_tracker()
    
    tracker1 = get_tracker()
    tracker2 = get_tracker()
    
    assert tracker1 is tracker2  # Same instance
    
    # Track in one, see in the other
    tracker1.track("test", "gpt-4o-mini", 100, 50)
    
    report = tracker2.report()
    assert report["total_tokens"] == 150


def test_multiple_models():
    """Test tracking multiple models."""
    tracker = TokenTracker()
    
    tracker.track("planner", "gpt-4o-mini", 1000, 500)
    tracker.track("embeddings", "text-embedding-3-small", 50000, 0)
    tracker.track("analyzer", "gpt-3.5-turbo", 2000, 1000)
    
    report = tracker.report()
    
    assert len(report["by_model"]) == 3
    assert "gpt-4o-mini" in report["by_model"]
    assert "text-embedding-3-small" in report["by_model"]
    assert "gpt-3.5-turbo" in report["by_model"]


def test_report_structure():
    """Test report JSON structure."""
    tracker = TokenTracker()
    tracker.track("test", "gpt-4o-mini", 100, 50)
    
    report = tracker.report()
    
    # Check structure
    assert "total_cost_usd" in report
    assert "total_tokens" in report
    assert "by_component" in report
    assert "by_model" in report
    
    assert "test" in report["by_component"]
    assert "input_tokens" in report["by_component"]["test"]
    assert "output_tokens" in report["by_component"]["test"]
    assert "total_tokens" in report["by_component"]["test"]
    assert "calls" in report["by_component"]["test"]


def test_zero_cost_unknown_model():
    """Test that unknown models don't error, just return 0 cost."""
    tracker = TokenTracker()
    
    cost = tracker.calculate_cost("unknown-model-xyz", 1000, 500)
    assert cost == 0.0


@pytest.mark.parametrize("input_tok,output_tok,expected_cost", [
    (0, 0, 0.0),
    (1000, 0, 0.00015),  # Input only
    (0, 1000, 0.0006),   # Output only
    (10000, 5000, 0.0045),  # Mixed
])
def test_cost_calculations_parametrized(input_tok, output_tok, expected_cost):
    """Parametrized cost calculation tests."""
    tracker = TokenTracker()
    cost = tracker.calculate_cost("gpt-4o-mini", input_tok, output_tok)
    assert abs(cost - expected_cost) < 0.00001
