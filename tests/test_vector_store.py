#!/usr/bin/env python3
"""Utility to test vector store playbook matching."""

from fackel.agents.vector_store import VectorPlaybookStore


def test_matching():
    """Test vector store with sample signals."""
    store = VectorPlaybookStore()
    
    print(f"\n📚 Loaded {len(store.entries)} playbooks")
    print(f"🔬 Using embeddings: {store.use_embeddings}\n")
    
    # Test cases
    test_cases = [
        (["graphql endpoint detected", "apollo server"], "GraphQL"),
        (["wordpress site", "wp-json api"], "WordPress"),
        (["nginx server", "https port 443"], "Web Surface"),
        (["react application", "single page app"], "React SPA"),
        (["cloudfront distribution", "s3 bucket"], "AWS"),
        (["mongodb port 27017 open"], "Database Exposed"),
        (["jenkins dashboard", "/jenkins/login"], "Jenkins CI"),
    ]
    
    for signals, label in test_cases:
        print(f"🔍 Test: {label}")
        print(f"   Signals: {signals}")
        
        tools = store.match(signals, threshold=0.5, top_k=3)
        
        if tools:
            print(f"   ✅ Matched {len(tools)} tools:")
            for tool in tools:
                print(f"      → {tool.name}: {tool.reason}")
        else:
            print(f"   ❌ No matches")
        print()


if __name__ == "__main__":
    test_matching()
