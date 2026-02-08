"""
Example: Query Service for Q&A over scan results.

Demonstrates:
1. Saving scan results to MongoDB
2. Embedding scan content for semantic search
3. Asking natural language questions
4. Getting LLM-powered answers with sources
"""

import asyncio
import sys
from datetime import datetime

sys.path.insert(0, '/home/dasein/Work/projects/fackel/src')

from pymongo import MongoClient

from fackel.core.models import CVE, DomainReport, Finding, Host, Service
from fackel.core.scan_repository import MongoScanRepository
from fackel.query.embeddings import ScanEmbeddingService
from fackel.query.query_service import QueryService


def create_sample_scan(domain: str) -> DomainReport:
    """Create a sample scan report for demonstration."""
    report = DomainReport(domain=domain)
    
    # Add a host with services
    host = Host(hostname=domain, ip="93.184.216.34")
    
    # Add services with CVEs
    host.services.append(
        Service(
            port=443,
            protocol="tcp",
            state="open",
            name="https",
            product="nginx",
            version="1.18.0",
            cves=[
                CVE(cve_id="CVE-2021-23017", cvss=7.5, source="vulners"),
                CVE(cve_id="CVE-2020-36309", cvss=5.3, source="vulners")
            ]
        )
    )
    
    host.services.append(
        Service(
            port=22,
            protocol="tcp",
            state="open",
            name="ssh",
            product="OpenSSH",
            version="8.2p1",
            cves=[
                CVE(cve_id="CVE-2021-41617", cvss=7.0, source="vulners")
            ]
        )
    )
    
    report.hosts[domain] = host
    
    # Add findings
    report.findings.append(
        Finding(
            title="Outdated Nginx Version",
            severity="HIGH",
            description="Server is running an outdated version of Nginx (1.18.0) with known vulnerabilities.",
            cves=[
                CVE(cve_id="CVE-2021-23017", cvss=7.5, source="vulners")
            ]
        )
    )
    
    report.findings.append(
        Finding(
            title="SSH Weak Configuration",
            severity="MEDIUM",
            description="SSH server allows password authentication which is less secure than key-based auth."
        )
    )
    
    return report


async def example_save_and_query():
    """Main example: save scans and query them."""
    print("\n" + "=" * 60)
    print("Query Service Example")
    print("=" * 60)
    
    # Setup MongoDB connection
    mongo_uri = "mongodb://localhost:27017/"
    client = MongoClient(mongo_uri)
    db = client["fackel"]
    
    # Initialize services
    scan_repo = MongoScanRepository(db)
    embedding_service = ScanEmbeddingService(db)
    query_service = QueryService(scan_repo, embedding_service)
    
    # Step 1: Create and save some sample scans
    print("\n📝 Step 1: Saving sample scans...")
    
    domains = ["example.com", "test.com", "demo.com"]
    scan_ids = []
    
    for domain in domains:
        report = create_sample_scan(domain)
        scan_id = scan_repo.save_scan(
            domain=domain,
            report=report,
            metadata={
                "tool_versions": {"nmap": "7.92", "nuclei": "2.9.0"},
                "duration_seconds": 120
            }
        )
        scan_ids.append(scan_id)
        print(f"  ✓ Saved scan for {domain}: {scan_id}")
    
    # Step 2: Generate embeddings
    print("\n🔍 Step 2: Generating embeddings for semantic search...")
    
    for scan_id, domain in zip(scan_ids, domains):
        scan = scan_repo.get_scan(scan_id)
        if scan:
            report = DomainReport(**scan["report"])
            await embedding_service.embed_scan(scan_id, domain, report)
            print(f"  ✓ Embedded scan for {domain}")
    
    # Step 3: Query the scans
    print("\n💬 Step 3: Asking questions about the scans...")
    
    questions = [
        "Quais vulnerabilidades críticas foram encontradas?",
        "Qual é a versão do nginx rodando?",
        "Existem problemas de configuração SSH?",
        "Quantos hosts foram escaneados?",
        "Quais CVEs têm CVSS maior que 7?"
    ]
    
    for question in questions:
        print(f"\n❓ Pergunta: {question}")
        print("-" * 60)
        
        result = await query_service.query(question, max_scans=3)
        
        print(f"📊 Confidence: {result['confidence']:.2f}")
        print(f"\n✅ Resposta:\n{result['answer']}")
        
        if result['sources']:
            print(f"\n📚 Fontes ({len(result['sources'])}):")
            for source in result['sources']:
                print(f"  - {source['domain']} (Scan ID: {source['scan_id'][:8]}...)")
                print(f"    Timestamp: {source['timestamp']}")
                print(f"    Similarity: {source['similarity']:.2f}")
    
    # Step 4: Query with domain filter
    print("\n" + "=" * 60)
    print("🎯 Step 4: Query with domain filter")
    print("=" * 60)
    
    result = await query_service.query(
        "Liste todas as vulnerabilidades encontradas",
        domain="example.com",
        max_scans=1
    )
    
    print(f"\n✅ Resposta (example.com only):\n{result['answer']}")
    
    # Cleanup
    client.close()
    
    print("\n" + "=" * 60)
    print("✅ Example completed!")
    print("=" * 60)


async def example_list_scans():
    """Example: List all scans."""
    print("\n" + "=" * 60)
    print("List Scans Example")
    print("=" * 60)
    
    mongo_uri = "mongodb://localhost:27017/"
    client = MongoClient(mongo_uri)
    db = client["fackel"]
    
    scan_repo = MongoScanRepository(db)
    
    # List all scans
    scans = scan_repo.list_scans(limit=10)
    
    print(f"\n📋 Found {len(scans)} scans:")
    for scan in scans:
        print(f"\n  Domain: {scan['domain']}")
        print(f"  Scan ID: {scan['scan_id']}")
        print(f"  Timestamp: {scan['timestamp']}")
        print(f"  Hosts: {scan['host_count']}, Services: {scan['service_count']}, CVEs: {scan['cve_count']}")
    
    client.close()


def main():
    """Run examples."""
    print("\n🔍 Fackel Query Service Examples")
    print("=" * 60)
    print("\n⚠️  Requirements:")
    print("  1. MongoDB running on localhost:27017")
    print("  2. OPENAI_API_KEY set in environment")
    print("  3. Langfuse configured (optional)")
    
    try:
        # Run async example
        asyncio.run(example_save_and_query())
        
        # List scans
        asyncio.run(example_list_scans())
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
