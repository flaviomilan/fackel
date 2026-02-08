
from langchain.tools import tool

try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        DDGS = None


@tool
def job_search(company_name: str) -> str:
    """Busca vagas de emprego da empresa para identificar tecnologias e sistemas utilizados."""
    if DDGS is None:
        return "Erro: ddgs não está instalado. pip install ddgs"
    try:
        with DDGS() as ddgs:

            query = f'"{company_name}" (vagas OR trabalhe-conosco OR carreiras) (site:linkedin.com/jobs OR site:gupy.io OR site:vagas.com.br OR site:indeed.com.br)'
            results = ddgs.text(query, max_results=5)

            job_posts = []
            for r in results:
                title = r.get("title", "")
                body = r.get("body", "")
                url = r.get("href", "")
                job_posts.append(f"Vaga: {title}\nDescrição: {body}\nURL: {url}\n---")

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
                    job_posts.append(
                        f"Página de Carreiras: {title}\nConteúdo: {body}\nURL: {url}\n---"
                    )

            return (
                "\n".join(job_posts)
                if job_posts
                else "Nenhuma vaga ou página de carreiras encontrada."
            )
    except Exception as e:
        return f"Erro ao buscar vagas: {e}"
