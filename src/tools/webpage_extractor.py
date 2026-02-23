from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from langchain_core.tools import tool


class WebpageExtractor:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
        )

    def extract_text_from_html(self, html_content):
        """Extrai texto relevante do conteúdo HTML."""
        soup = BeautifulSoup(html_content, "html.parser")

        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()

        text_elements = []
        for tag in soup.find_all(["p", "h1", "h2", "h3", "h4", "h5", "h6"]):
            text = tag.get_text(strip=True)
            if text and len(text) > 20:
                text_elements.append(text)

        return "\n".join(text_elements)

    def is_valid_url(self, url):
        """Verifica se a URL é válida e segura para acessar."""
        try:
            parsed = urlparse(url)
            return all([parsed.scheme in ["http", "https"], parsed.netloc])
        except:
            return False

    def extract_content(self, url):
        """Extrai conteúdo de uma URL."""
        if not self.is_valid_url(url):
            return f"URL inválida: {url}"

        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            content_type = response.headers.get("content-type", "").lower()
            if "text/html" not in content_type:
                return f"Conteúdo não é HTML: {content_type}"

            return self.extract_text_from_html(response.text)
        except requests.exceptions.RequestException as e:
            return f"Erro ao acessar {url}: {e!s}"



extractor = WebpageExtractor()

from pydantic import BaseModel, Field

from .utils import format_tool_output


class WebpageExtractorInput(BaseModel):
    """Input schema for webpage content extraction."""

    url: str = Field(
        description="Full URL to extract content from (must include http:// or https://).",
    )


@tool(args_schema=WebpageExtractorInput)
def extract_webpage_content(url: str) -> dict:
    """Extract relevant text content from a web page, stripping HTML boilerplate.

    Useful for reading page content to identify technologies, organisation info,
    or intel from discovered web endpoints.
    """
    try:
        content = extractor.extract_content(url)

        max_length = 2000
        if "Erro ao acessar" in content or "URL inválida" in content:
            return format_tool_output(
                "extract_webpage_content",
                url,
                "error",
                error=content,
            )

        if len(content) > max_length:
            content = content[:max_length] + "... (conteúdo truncado)"
        
        return format_tool_output(
            "extract_webpage_content",
            url,
            "ok",
            data={"content": content},
        )
    except Exception as e:
        return format_tool_output(
            "extract_webpage_content",
            url,
            "error",
            error=str(e),
        )
