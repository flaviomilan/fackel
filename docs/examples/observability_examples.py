"""
Example: Advanced Langfuse Observability Usage

This example demonstrates all observability features:
- Custom traces with metadata
- Session grouping
- Custom scores
- Performance monitoring
- Cost analysis
"""

import time
from fackel.core.observability import get_observability, instrument
from fackel.agents.graph_agent import LangGraphAgent


def example_basic_scan():
    """Example 1: Basic scan with automatic observability."""
    print("=" * 60)
    print("Example 1: Basic Scan with Automatic Observability")
    print("=" * 60)
    
    agent = LangGraphAgent(
        active_scan=False,
        use_llm_planner=True,
    )
    
    # Observability is automatic - just run the scan
    result = agent.run("example.com")
    
    print("\n✅ Scan completed!")
    print("   View trace at: http://localhost:3000/traces")
    print(f"   Summary: {len(result['summary'])} chars")
    

def example_session_grouping():
    """Example 2: Group multiple scans in one session."""
    print("\n" + "=" * 60)
    print("Example 2: Session Grouping")
    print("=" * 60)
    
    obs = get_observability()
    
    # Set session ID to group related scans
    obs.set_session("project_alpha_recon")
    
    agent = LangGraphAgent(active_scan=False)
    
    domains = ["example.com", "api.example.com", "test.example.com"]
    
    for domain in domains:
        print(f"\n🔍 Scanning {domain}...")
        result = agent.run(domain)
        print(f"   ✓ Completed")
    
    print("\n✅ All scans in session 'project_alpha_recon'")
    print("   View at: http://localhost:3000/sessions/project_alpha_recon")


def example_custom_metadata():
    """Example 3: Add custom metadata to traces."""
    print("\n" + "=" * 60)
    print("Example 3: Custom Metadata")
    print("=" * 60)
    
    obs = get_observability()
    
    # Create trace with rich metadata
    with obs.trace_scan(
        domain="customer.example.com",
        active_scan=True,
        metadata={
            "client": "Acme Corp",
            "project": "Q1 2026 Security Assessment",
            "tester": "security@example.com",
            "scope": ["web", "api", "infrastructure"],
            "budget_usd": 5.00,
        },
    ):
        # Simulate scan operations
        print("🔍 Executing scan with custom metadata...")
        time.sleep(1)
        
        # Add custom scores
        obs.add_trace_score(
            name="budget_compliance",
            value=1.0,
            comment="Under budget",
        )
        
        obs.add_trace_score(
            name="scope_coverage",
            value=0.85,
            comment="85% of planned scope",
        )
        
        # Add custom tags
        obs.add_trace_tags([
            "client:acme_corp",
            "priority:high",
            "compliance:pci_dss",
        ])
        
        print("✅ Metadata and scores added")


def example_cost_monitoring():
    """Example 4: Monitor and alert on costs."""
    print("\n" + "=" * 60)
    print("Example 4: Cost Monitoring")
    print("=" * 60)
    
    agent = LangGraphAgent(
        active_scan=False,
        use_llm_planner=True,
    )
    
    obs = get_observability()
    cost_limit = 0.50  # $0.50 limit
    
    with obs.trace_scan(
        domain="example.com",
        active_scan=False,
        metadata={"cost_limit_usd": cost_limit},
    ):
        # Run scan
        print(f"🔍 Running scan with ${cost_limit} cost limit...")
        result = agent.run("example.com")
        
        # Note: In real implementation, you'd extract cost from trace
        # This is a simulation
        estimated_cost = 0.35
        
        if estimated_cost > cost_limit:
            print(f"⚠️  WARNING: Cost ${estimated_cost} exceeds limit ${cost_limit}")
            obs.add_trace_score(
                name="cost_alert",
                value=0.0,
                comment=f"Over budget: ${estimated_cost} > ${cost_limit}",
            )
        else:
            print(f"✅ Cost ${estimated_cost} within limit ${cost_limit}")
            obs.add_trace_score(
                name="cost_alert",
                value=1.0,
                comment=f"Under budget: ${estimated_cost} < ${cost_limit}",
            )


@instrument(name="custom_analysis", tags=["analysis", "custom"])
def analyze_findings(domain: str, findings: list) -> dict:
    """Example 5: Custom instrumented function."""
    print(f"\n🔬 Analyzing {len(findings)} findings for {domain}")
    
    # Simulate analysis
    time.sleep(0.5)
    
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    
    return {
        "total": len(findings),
        "critical": critical,
        "high": high,
        "risk_score": (critical * 10 + high * 5) / max(1, len(findings)),
    }


def example_custom_instrumentation():
    """Example 5: Instrument custom functions."""
    print("\n" + "=" * 60)
    print("Example 5: Custom Function Instrumentation")
    print("=" * 60)
    
    obs = get_observability()
    
    with obs.trace_scan(
        domain="example.com",
        active_scan=False,
    ):
        # Simulate findings
        findings = [
            {"severity": "critical", "type": "sqli"},
            {"severity": "high", "type": "xss"},
            {"severity": "medium", "type": "cors"},
        ]
        
        # This function is automatically instrumented
        analysis = analyze_findings("example.com", findings)
        
        print(f"✅ Analysis: {analysis}")
        
        # Add analysis results as scores
        obs.add_trace_score(
            name="risk_score",
            value=analysis["risk_score"] / 10,  # Normalize to 0-1
            comment=f"Risk: {analysis['risk_score']:.2f}/10",
        )


def example_performance_comparison():
    """Example 6: Compare performance across runs."""
    print("\n" + "=" * 60)
    print("Example 6: Performance Comparison")
    print("=" * 60)
    
    obs = get_observability()
    obs.set_session("performance_test")
    
    configurations = [
        {"use_llm_planner": False, "name": "deterministic"},
        {"use_llm_planner": True, "name": "llm_planner"},
    ]
    
    for config in configurations:
        print(f"\n🔬 Testing configuration: {config['name']}")
        
        agent = LangGraphAgent(
            active_scan=False,
            use_llm_planner=config["use_llm_planner"],
        )
        
        start = time.time()
        
        with obs.trace_scan(
            domain="test.example.com",
            active_scan=False,
            metadata={"configuration": config["name"]},
        ):
            result = agent.run("test.example.com")
        
        duration = time.time() - start
        print(f"   ✓ Completed in {duration:.2f}s")
    
    print("\n✅ Performance test completed")
    print("   Compare at: http://localhost:3000/sessions/performance_test")


def example_error_tracking():
    """Example 7: Error tracking and recovery."""
    print("\n" + "=" * 60)
    print("Example 7: Error Tracking")
    print("=" * 60)
    
    obs = get_observability()
    
    with obs.trace_scan(
        domain="invalid.example.com",
        active_scan=False,
        metadata={"expected_errors": True},
    ):
        try:
            # Simulate operation that might fail
            print("🔍 Attempting scan of invalid domain...")
            
            # This would normally raise an error
            # For demo, we'll simulate it
            raise ValueError("Domain not reachable")
            
        except Exception as e:
            print(f"❌ Error: {e}")
            
            # Track error in observability
            obs.add_trace_score(
                name="error_severity",
                value=0.5,
                comment=f"Recoverable error: {str(e)[:100]}",
            )
            
            obs.add_trace_tags(["has_error", "error:domain_unreachable"])
            
            print("✅ Error tracked in observability")


def main():
    """Run all examples."""
    print("\n" + "🚀 " * 20)
    print("Langfuse Observability Examples")
    print("🚀 " * 20)
    
    obs = get_observability()
    
    if not obs.enabled:
        print("\n⚠️  Langfuse is NOT enabled!")
        print("   Set LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY in .env")
        print("   See: docs/langfuse_observability.md")
        return
    
    print(f"\n✅ Langfuse enabled")
    print(f"   Dashboard: http://localhost:3000")
    print(f"   Environment: {obs._environment}")
    
    try:
        # Run examples
        # example_basic_scan()
        # example_session_grouping()
        example_custom_metadata()
        example_cost_monitoring()
        example_custom_instrumentation()
        example_performance_comparison()
        example_error_tracking()
        
        print("\n" + "=" * 60)
        print("✅ All examples completed!")
        print("=" * 60)
        print("\n📊 View results at: http://localhost:3000")
        print("   - Traces: See all scans")
        print("   - Sessions: Group related scans")
        print("   - Analytics: Cost and token usage")
        print("   - Scores: Quality metrics")
        
    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
