#!/usr/bin/env python3
"""
Test script para validar cancelamento de requisições.

Simula cliente que cancela requisição no meio do processamento.
"""

import asyncio
import time
import requests
from threading import Thread


def test_query_cancellation():
    """Testa cancelamento de query."""
    
    print("🧪 Teste 1: Cancelar query no meio")
    print("-" * 60)
    
    def make_request():
        try:
            response = requests.post(
                "http://localhost:8000/query",
                json={
                    "question": "Liste todas as vulnerabilidades encontradas",
                    "max_scans": 10
                },
                timeout=1.0  # Cancela após 1 segundo
            )
            print(f"✓ Response: {response.status_code}")
        except requests.exceptions.Timeout:
            print("✓ Request timeout (esperado)")
        except Exception as e:
            print(f"✓ Request cancelado: {type(e).__name__}")
    
    thread = Thread(target=make_request)
    thread.start()
    
    # Espera um pouco e verifica logs do servidor
    time.sleep(2)
    thread.join(timeout=1)
    
    print("\nVerifique os logs do servidor:")
    print("- Deve mostrar 'Client disconnected before query processing' ou similar")
    print("- Processamento deve parar")
    print()


def test_scan_stream_cancellation():
    """Testa cancelamento de scan streaming."""
    
    print("🧪 Teste 2: Cancelar scan stream")
    print("-" * 60)
    
    def stream_request():
        try:
            response = requests.get(
                "http://localhost:8000/scan/stream",
                params={"domain": "example.com", "active": "false"},
                stream=True,
                timeout=2.0  # Cancela após 2 segundos
            )
            
            count = 0
            for line in response.iter_lines():
                if line:
                    print(f"Evento {count}: {line[:50]}...")
                    count += 1
                    if count >= 3:
                        print("Fechando conexão propositalmente...")
                        break
            
        except requests.exceptions.Timeout:
            print("✓ Stream timeout (esperado)")
        except Exception as e:
            print(f"✓ Stream cancelado: {type(e).__name__}")
    
    thread = Thread(target=stream_request)
    thread.start()
    
    time.sleep(3)
    thread.join(timeout=1)
    
    print("\nVerifique os logs do servidor:")
    print("- Deve mostrar 'Client disconnected during scan of example.com'")
    print("- Scan deve parar de processar")
    print()


def test_normal_completion():
    """Testa request normal sem cancelamento."""
    
    print("🧪 Teste 3: Request normal (sem cancelamento)")
    print("-" * 60)
    
    try:
        # Health check (rápido)
        response = requests.get("http://localhost:8000/health")
        print(f"✓ Health check: {response.status_code}")
        print(f"  Features: {response.json()['features']}")
        
        # List scans (deveria ser rápido)
        response = requests.get("http://localhost:8000/scans?limit=5")
        print(f"✓ List scans: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"  Total scans: {data['total']}")
        
    except Exception as e:
        print(f"✗ Erro: {e}")
    
    print()


def main():
    print("=" * 60)
    print("TESTE DE CANCELAMENTO DE REQUISIÇÕES")
    print("=" * 60)
    print()
    print("Pré-requisitos:")
    print("1. Servidor deve estar rodando: uv run fackel serve")
    print("2. MongoDB e Redis devem estar ativos")
    print("3. Pelo menos 1 scan deve existir no banco")
    print()
    input("Pressione Enter para começar os testes...")
    print()
    
    # Teste 3 primeiro (mais simples)
    test_normal_completion()
    
    # Teste 1: Query cancellation
    test_query_cancellation()
    
    # Teste 2: Stream cancellation
    test_scan_stream_cancellation()
    
    print("=" * 60)
    print("TESTES CONCLUÍDOS")
    print("=" * 60)
    print()
    print("📝 Resumo:")
    print("- Requests podem ser canceladas pelo cliente")
    print("- Servidor detecta desconexão e para processamento")
    print("- Recursos são liberados apropriadamente")
    print()
    print("💡 Comportamento esperado:")
    print("- Query longa: Para antes/durante/depois de embedding/LLM")
    print("- Scan stream: Para quando cliente desconecta")
    print("- Logs: Mostram 'Client disconnected' ou 'cancelled'")
    print()


if __name__ == "__main__":
    main()
