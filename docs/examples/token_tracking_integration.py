"""Example integration of token tracker with LLM calls."""

from langchain_openai import ChatOpenAI
from fackel.core.token_tracker import get_tracker


# Example 1: Wrap LLM invocation
def analyze_with_tracking(prompt: str, model: str = "gpt-4o-mini"):
    """Analyze with automatic token tracking."""
    tracker = get_tracker()
    llm = ChatOpenAI(model=model, temperature=0.3)
    
    # Make LLM call
    response = llm.invoke(prompt)
    
    # Track usage (LangChain provides token counts in response metadata)
    if hasattr(response, 'response_metadata'):
        usage = response.response_metadata.get('token_usage', {})
        tracker.track(
            component="analyzer",
            model=model,
            input_tokens=usage.get('prompt_tokens', 0),
            output_tokens=usage.get('completion_tokens', 0)
        )
    
    return response.content


# Example 2: Integrate in existing reporter
def analyze_incremental_with_tracking(tool_name: str, tool_output: str, domain: str):
    """Modified analyze_incremental with token tracking."""
    from fackel.agents.reporter import LLMReporter
    from fackel.core.smart_truncate import smart_truncate
    
    reporter = LLMReporter()
    tracker = get_tracker()
    
    if not reporter.llm:
        return ""
    
    # Smart truncation
    truncated = smart_truncate(tool_output, tool_name, max_chars=32000)
    
    # Build prompt
    prompt = f"Análise de segurança para {tool_name} contra {domain}:\n{truncated}"
    
    # Invoke LLM
    response = reporter.llm.invoke(prompt)
    
    # Track tokens
    if hasattr(response, 'response_metadata'):
        usage = response.response_metadata.get('token_usage', {})
        tracker.track(
            component=f"incremental_analysis.{tool_name}",
            model="gpt-4o-mini",  # Get from config
            input_tokens=usage.get('prompt_tokens', 0),
            output_tokens=usage.get('completion_tokens', 0)
        )
    
    return response.content if hasattr(response, 'content') else str(response)


# Example 3: Print summary at end of scan
def print_final_report():
    """Print token usage summary after scan completes."""
    tracker = get_tracker()
    
    print("\n" + "="*70)
    print("📊 FACKEL SCAN COMPLETE")
    print("="*70)
    
    # ... print vulnerability summary ...
    
    # Token usage
    tracker.print_summary()
    
    # Add recommendations
    report = tracker.report()
    if report['total_cost_usd'] > 1.0:
        print("\n💡 Cost Optimization Tips:")
        print("   - Enable Redis cache for embeddings")
        print("   - Use smart truncation for large tool outputs")
        print("   - Consider batch processing for similar tools")


# Example 4: Track embeddings
def track_embedding_call(text: str, cache_hit: bool = False):
    """Track embedding generation (or cache hit)."""
    from fackel.core.smart_truncate import estimate_tokens
    
    if cache_hit:
        return  # No cost for cache hits
    
    tracker = get_tracker()
    input_tokens = estimate_tokens(text)
    
    tracker.track(
        component="embeddings",
        model="text-embedding-3-small",
        input_tokens=input_tokens,
        output_tokens=0  # Embeddings don't have output tokens
    )
