import asyncio
import os

import aiohttp
import requests
from langchain.tools import tool


class EmailAnalyzer:
    def __init__(self):
        self.hibp_api_key = os.getenv("HIBP_API_KEY")
        self.emailrep_api_key = os.getenv("EMAILREP_API_KEY")

    async def check_email_services(self, email: str) -> dict[str, bool]:
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
def analyze_email(email: str):
    """Analisa um e-mail usando múltiplas fontes (serviços, vazamentos, reputação)."""
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
        except Exception:
            pass

    breaches: list[dict] = []
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
                breaches = response.json()
        except Exception as e:
            print(f"[Debug] Erro ao verificar vazamentos: {e}")

    reputation = None
    if analyzer.emailrep_api_key:
        try:
            headers = {"Key": analyzer.emailrep_api_key}
            response = requests.get(
                f"https://emailrep.io/{email}", headers=headers, timeout=10
            )
            if response.status_code == 200:
                reputation = response.json()
        except Exception as e:
            print(f"[Debug] Erro ao verificar reputação: {e}")

    return {
        "tool": "analyze_email",
        "status": "ok",
        "email": email,
        "services": services,
        "breaches": breaches,
        "reputation": reputation,
    }
