from langchain_core.tools import tool

try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS

    except ImportError:
        DDGS = None

from .utils import format_tool_output


@tool
def job_search(company_name: str) -> dict:
    """Busca vagas de emprego da empresa para identificar tecnologias e sistemas utilizados."""
    if DDGS is None:
        return format_tool_output(
            "job_search",
            company_name,
            "error",
            error="ddgs não está instalado. pip install ddgs",
        )
    try:
        with DDGS() as ddgs:

            query = f'"{company_name}" (vagas OR trabalhe-conosco OR carreiras) (site:linkedin.com/jobs OR site:gupy.io OR site:vagas.com.br OR site:indeed.com.br)'
            results = ddgs.text(query, max_results=5)

            job_posts = []
            for r in results:
                title = r.get("title", "")
                body = r.get("body", "")
                url = r.get("href", "")
                # job_posts.append(f"Vaga: {title}\nDescrição: {body}\nURL: {url}\n---")
                job_posts.append({"title": title, "body": body, "url": url, "type": "job"})

            careers_query = f'"{company_name}" (trabalhe-conosco OR carreiras OR opportunities OR careers)'
            career_results = ddgs.text(careers_query, max_results=2)
            for r in career_results:
                title = r.get("title", "")
                body = r.get("body", "")
                url = r.get("href", "")
                if any(
                    keyword in title.lower()
                    for keyword in [
                        "trabalhe",
                        "carreira",
                        "vaga",
                        "opportunit",
                        "career",
                    ]
                ):
                    # job_posts.append(
                    #     f"Página de Carreiras: {title}\nConteúdo: {body}\nURL: {url}\n---"
                    # )
                    job_posts.append({"title": title, "body": body, "url": url, "type": "career_page"})

            return format_tool_output(
                "job_search",
                company_name,
                "ok",
                data={"results": job_posts},
            )
    except Exception as e:
        return format_tool_output(
            "job_search",
            company_name,
            "error",
            error=f"Erro ao buscar vagas: {e}",
        )
