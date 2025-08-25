import asyncio
import os
from typing import Dict, List

import aiohttp
import requests
from langchain.tools import tool


class EmailAnalyzer:
    def __init__(self):
        self.hibp_api_key = os.getenv("HIBP_API_KEY")
        self.emailrep_api_key = os.getenv("EMAILREP_API_KEY")

    async def check_email_services(self, email: str) -> Dict[str, bool]:
        """Verifica em quais serviços o e-mail está registrado."""
        results = {}

        async with aiohttp.ClientSession() as session:

            services = [
                (
                    "Twitter",
                    "https://api.twitter.com/i/users/email_available.json",
                    {"email": email},
                ),
                (
                    "Instagram",
                    "https://www.instagram.com/accounts/check_email/",
                    {"email": email},
                ),
                ("LinkedIn", "https://www.linkedin.com/login-submit", {"email": email}),
                (
                    "Spotify",
                    "https://spclient.wg.spotify.com/signup/public/v1/account",
                    {"email": email},
                ),
                (
                    "Discord",
                    "https://discord.com/api/v9/auth/register",
                    {"email": email},
                ),
            ]

            for service_name, url, data in services:
                try:
                    async with session.post(url, json=data, timeout=10) as response:

                        exists = response.status in [400, 409]
                        results[service_name] = exists
                except Exception as e:
                    print(f"[Debug] Erro ao verificar {service_name}: {e}")
                    results[service_name] = False

        return results


@tool
def analyze_email(email: str) -> str:
    """Analisa um e-mail usando múltiplas fontes."""
    results = []
    analyzer = EmailAnalyzer()

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        services = loop.run_until_complete(analyzer.check_email_services(email))
    except Exception as e:
        print(f"[Debug] Erro ao executar verificações assíncronas: {e}")
        services = {}
    finally:
        try:
            loop.close()
        except:
            pass

    if services:
        results.append("\n=== Serviços Verificados ===")
        for service, exists in services.items():
            results.append(
                f"- {service}: {'Encontrado' if exists else 'Não encontrado'}"
            )

    if analyzer.hibp_api_key:
        try:
            headers = {
                "hibp-api-key": analyzer.hibp_api_key,
                "user-agent": "OSINT-Tool",
            }

            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers=headers,
                timeout=10,
            )

            if response.status_code == 200:
                results.append("\n=== Vazamentos de Dados ===")
                breaches = response.json()
                for breach in breaches:
                    name = breach.get("Name", "Desconhecido")
                    domain = breach.get("Domain", "Desconhecido")
                    date = breach.get("BreachDate", "Data desconhecida")
                    results.append(f"- {name} ({domain}) - {date}")
            elif response.status_code == 404:
                results.append("\n=== Vazamentos de Dados ===")
                results.append("Nenhum vazamento encontrado")
        except Exception as e:
            print(f"[Debug] Erro ao verificar vazamentos: {e}")

    if analyzer.emailrep_api_key:
        try:
            headers = {"Key": analyzer.emailrep_api_key}
            response = requests.get(
                f"https://emailrep.io/{email}", headers=headers, timeout=10
            )

            if response.status_code == 200:
                reputation = response.json()
                results.append("\n=== Reputação do E-mail ===")
                suspicious = reputation.get("suspicious", False)
                results.append(f"- Suspeito: {'Sim' if suspicious else 'Não'}")
                results.append(f"- Reputação: {reputation.get('reputation', 'N/A')}")
                if "details" in reputation:
                    results.append("- Detalhes:")
                    for key, value in reputation["details"].items():
                        results.append(f"  * {key}: {value}")
        except Exception as e:
            print(f"[Debug] Erro ao verificar reputação: {e}")

    return "\n".join(results) if results else "Nenhuma informação encontrada"
