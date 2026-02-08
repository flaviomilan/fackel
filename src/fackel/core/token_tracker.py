"""Token usage tracking and cost monitoring for LLM calls."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("fackel.token_tracker")


@dataclass
class TokenUsage:
    """Track token usage for a single model/component."""
    
    input_tokens: int = 0
    output_tokens: int = 0
    total_calls: int = 0
    
    def add(self, input_tok: int, output_tok: int):
        self.input_tokens += input_tok
        self.output_tokens += output_tok
        self.total_calls += 1
    
    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class CostConfig:
    """Cost per 1M tokens for different models."""
    
    # GPT-4o mini (as of Feb 2026)
    GPT4O_MINI_INPUT = 0.15  # $0.15 per 1M input tokens
    GPT4O_MINI_OUTPUT = 0.60  # $0.60 per 1M output tokens
    
    # Text embeddings
    TEXT_EMBEDDING_3_SMALL = 0.02  # $0.02 per 1M tokens
    TEXT_EMBEDDING_3_LARGE = 0.13  # $0.13 per 1M tokens
    
    # GPT-3.5 Turbo
    GPT35_TURBO_INPUT = 0.50  # $0.50 per 1M tokens
    GPT35_TURBO_OUTPUT = 1.50  # $1.50 per 1M tokens


class TokenTracker:
    """Track and report token usage and costs across all LLM calls."""
    
    def __init__(self, cost_config: CostConfig | None = None):
        self.cost_config = cost_config or CostConfig()
        self.usage_by_component: dict[str, TokenUsage] = defaultdict(TokenUsage)
        self.usage_by_model: dict[str, TokenUsage] = defaultdict(TokenUsage)
    
    def track(
        self,
        component: str,
        model: str,
        input_tokens: int,
        output_tokens: int = 0
    ):
        """Record token usage for a component and model."""
        self.usage_by_component[component].add(input_tokens, output_tokens)
        self.usage_by_model[model].add(input_tokens, output_tokens)
        
        logger.debug(
            f"[{component}] {model}: {input_tokens} in + {output_tokens} out tokens"
        )
    
    def calculate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost in USD for given token usage."""
        model_lower = model.lower()
        
        if "gpt-4o-mini" in model_lower:
            input_cost = (input_tokens / 1_000_000) * self.cost_config.GPT4O_MINI_INPUT
            output_cost = (output_tokens / 1_000_000) * self.cost_config.GPT4O_MINI_OUTPUT
            return input_cost + output_cost
        
        elif "gpt-3.5-turbo" in model_lower:
            input_cost = (input_tokens / 1_000_000) * self.cost_config.GPT35_TURBO_INPUT
            output_cost = (output_tokens / 1_000_000) * self.cost_config.GPT35_TURBO_OUTPUT
            return input_cost + output_cost
        
        elif "text-embedding-3-small" in model_lower:
            return (input_tokens / 1_000_000) * self.cost_config.TEXT_EMBEDDING_3_SMALL
        
        elif "text-embedding-3-large" in model_lower:
            return (input_tokens / 1_000_000) * self.cost_config.TEXT_EMBEDDING_3_LARGE
        
        else:
            logger.warning(f"Unknown model for cost calculation: {model}")
            return 0.0
    
    def get_total_cost(self) -> float:
        """Calculate total cost across all models."""
        total = 0.0
        for model, usage in self.usage_by_model.items():
            total += self.calculate_cost(model, usage.input_tokens, usage.output_tokens)
        return total
    
    def report(self) -> dict[str, Any]:
        """Generate comprehensive usage report."""
        total_cost = self.get_total_cost()
        total_tokens = sum(u.total_tokens for u in self.usage_by_component.values())
        
        return {
            "total_cost_usd": round(total_cost, 4),
            "total_tokens": total_tokens,
            "by_component": {
                name: {
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "total_tokens": usage.total_tokens,
                    "calls": usage.total_calls
                }
                for name, usage in self.usage_by_component.items()
            },
            "by_model": {
                model: {
                    "tokens": usage.total_tokens,
                    "cost_usd": round(
                        self.calculate_cost(model, usage.input_tokens, usage.output_tokens),
                        4
                    )
                }
                for model, usage in self.usage_by_model.items()
            }
        }
    
    def print_summary(self):
        """Print human-readable summary."""
        report = self.report()
        
        print("\n" + "="*60)
        print("💰 LLM TOKEN USAGE & COST SUMMARY")
        print("="*60)
        print(f"Total Cost: ${report['total_cost_usd']:.4f}")
        print(f"Total Tokens: {report['total_tokens']:,}")
        print()
        
        print("By Component:")
        for component, data in report['by_component'].items():
            print(f"  {component:20s} {data['total_tokens']:>10,} tokens  ({data['calls']} calls)")
        print()
        
        print("By Model:")
        for model, data in report['by_model'].items():
            print(f"  {model:30s} ${data['cost_usd']:>8.4f}  ({data['tokens']:,} tokens)")
        print("="*60)


# Global tracker instance
_global_tracker: TokenTracker | None = None


def get_tracker() -> TokenTracker:
    """Get or create global token tracker."""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = TokenTracker()
    return _global_tracker


def reset_tracker():
    """Reset global tracker (useful for testing)."""
    global _global_tracker
    _global_tracker = None
