import asyncio
import re
import traceback

from langchain.tools import tool
from playwright.async_api import TimeoutError as PlaywrightTimeout
from playwright.async_api import async_playwright


class CensysWebScraper:
    def __init__(self):
        self.base_url = "https://search.censys.io"

    def _normalize_domain(self, domain: str) -> str:
        """Remove schema/trailing slash so Censys query is clean."""
        cleaned = re.sub(r"^https?://", "", domain.strip())
        cleaned = cleaned.rstrip("/")
        return cleaned

    async def setup_browser(self):
        """Configura o browser com configurações anti-detecção."""
        print("[Debug] Iniciando setup do browser...")
        playwright = await async_playwright().start()
        browser = await playwright.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"]
        )
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        )

        return context, playwright, browser

    async def extract_host_info(self, page) -> dict:
        """Extrai informações do host da página."""
        info = {}

        try:
            print("[Debug] Aguardando carregamento da página...")

            await page.wait_for_load_state("networkidle")

            no_results = await page.query_selector(".no-results")
            if no_results:
                print("[Debug] Nenhum resultado encontrado")
                return {"message": "Nenhum resultado encontrado"}

            print("[Debug] Extraindo informações...")

            ips = await page.query_selector_all('text="IP Address:"')
            if ips:
                info["ips"] = []
                for ip_elem in ips:
                    try:
                        parent = await ip_elem.evaluate("node => node.parentElement")
                        if parent:
                            ip_text = await parent.evaluate("node => node.textContent")
                            if ip_text:
                                info["ips"].append(
                                    ip_text.replace("IP Address:", "").strip()
                                )
                    except Exception as e:
                        print(f"[Debug] Erro ao extrair IP: {e}")

            services = await page.query_selector_all(".service-info")
            if services:
                info["services"] = []
                for service in services:
                    try:
                        service_text = await service.inner_text()
                        info["services"].append(service_text.strip())
                    except Exception as e:
                        print(f"[Debug] Erro ao extrair serviço: {e}")

            ssl_info = await page.query_selector_all(".ssl-info")
            if ssl_info:
                info["ssl"] = []
                for ssl in ssl_info:
                    try:
                        ssl_text = await ssl.inner_text()
                        info["ssl"].append(ssl_text.strip())
                    except Exception as e:
                        print(f"[Debug] Erro ao extrair SSL: {e}")

            print("[Debug] Extração concluída")
            return info

        except PlaywrightTimeout:
            print("[Debug] Timeout ao extrair informações")
            return {"error": "Timeout ao carregar a página"}
        except Exception as e:
            print(f"[Debug] Erro ao extrair informações: {e}")
            return {"error": str(e)}

    async def search_domain(self, domain: str) -> list[dict]:
        """Realiza a busca por um domínio no Censys."""
        results = []
        context = None
        browser = None
        playwright = None

        try:
            print(f"[Debug] Iniciando busca para domínio: {domain}")
            context, playwright, browser = await self.setup_browser()

            page = await context.new_page()
            page.set_default_timeout(45000)
            clean_domain = self._normalize_domain(domain)
            target_url = f"{self.base_url}/search?q={clean_domain}"
            print(f"[Debug] Navegando para {target_url}")

            await page.goto(target_url, wait_until="domcontentloaded", timeout=60000)

            info = await self.extract_host_info(page)
            if info:
                results.append(info)

            return results

        except Exception as e:
            print(f"[Debug] Erro durante a busca: {e}")
            print(f"[Debug] Traceback:\n{traceback.format_exc()}")
            return [{"error": f"Erro durante a busca: {e!s}"}]

        finally:
            print("[Debug] Finalizando recursos...")
            if context:
                await context.close()
            if browser:
                await browser.close()
            if playwright:
                await playwright.stop()



scraper = CensysWebScraper()

from .utils import format_tool_output


@tool
def censys_web_lookup(domain: str):
    """Web scraping do Censys (fallback). Retorna hosts/serviços estruturados."""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            results = loop.run_until_complete(scraper.search_domain(domain))
        finally:
            loop.close()

        hosts = []
        errors = []
        for result in results:
            if "error" in result:
                errors.append(result["error"])
                continue
            hosts.append(
                {
                    "ip": result.get("ips", [None])[0] if result.get("ips") else None,
                    "services": [{"raw": s} for s in result.get("services", [])],
                }
            )

        return format_tool_output(
            "censys_web_lookup",
            domain,
            "ok" if hosts else "error",
            data={"hosts": hosts, "errors": errors},
            error=str(errors) if not hosts else None,
        )

    except Exception as e:
        return format_tool_output(
            "censys_web_lookup",
            domain,
            "error",
            error=f"Erro ao realizar busca no Censys: {e!s}",
        )
