from langchain.tools import tool
from typing import Dict, List
import re
from bs4 import BeautifulSoup
import requests
from duckduckgo_search import DDGS

class ProfileAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def extract_skills_from_text(self, text: str) -> List[str]:
        """Extrai possíveis habilidades técnicas do texto."""

        tech_keywords = [

            r'\b(Python|Java|JavaScript|C\+\+|PHP|Ruby|Go|Rust|Swift|Kotlin)\b',

            r'\b(React|Angular|Vue|Django|Flask|Spring|Laravel|Node\.js|Express)\b',

            r'\b(SQL|MySQL|PostgreSQL|MongoDB|Oracle|Redis|Cassandra)\b',

            r'\b(AWS|Azure|GCP|Docker|Kubernetes|Jenkins|Git|Linux|Windows Server)\b',

            r'\b(Cybersecurity|Pentest|SIEM|Firewall|IDS|IPS|SOC|ISO 27001)\b',

            r'\b(Agile|Scrum|Kanban|DevOps|CI/CD)\b',

            r'\b(SAP|Oracle|Totvs|Protheus|Microsoft Dynamics|Salesforce)\b',

            r'\b(PLC|SCADA|Industrial Automation|IoT|Sensors|Modbus|OPC)\b'
        ]

        skills = set()
        for pattern in tech_keywords:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            skills.update(match.group(0) for match in matches)

        return sorted(list(skills))

    def search_professional_info(self, name: str, company: str) -> Dict:
        """Busca informações profissionais detalhadas."""
        results = {
            'profile_summary': [],
            'skills': set(),
            'roles': set(),
            'education': set()
        }

        queries = [
            f'"{name}" "{company}" site:linkedin.com',
            f'"{name}" curriculum vitae OR resume',
            f'"{name}" "{company}" conference OR speaker OR article'
        ]

        with DDGS() as ddgs:
            for query in queries:
                search_results = ddgs.text(query, max_results=3)
                for r in search_results:
                    title = r.get('title', '')
                    body = r.get('body', '')
                    url = r.get('href', '')


                    skills = self.extract_skills_from_text(f"{title} {body}")
                    results['skills'].update(skills)


                    roles_pattern = r'(Engineer|Developer|Manager|Director|Coordinator|Analyst|Architect|Lead|Head of|CTO|CIO|CEO|VP|Supervisor)\s+(?:of|at|in)?\s+[\w\s]+'
                    roles = re.finditer(roles_pattern, f"{title} {body}", re.IGNORECASE)
                    results['roles'].update(role.group(0) for role in roles)


                    edu_pattern = r'(Bachelor|Master|PhD|MBA|Graduation|Degree|Certified)\s+(?:in|of)?\s+[\w\s]+'
                    education = re.finditer(edu_pattern, body, re.IGNORECASE)
                    results['education'].update(edu.group(0) for edu in education)

                    results['profile_summary'].append({
                        'title': title,
                        'summary': body[:300] + "..." if len(body) > 300 else body,
                        'url': url
                    })


        results['skills'] = sorted(list(results['skills']))
        results['roles'] = sorted(list(results['roles']))
        results['education'] = sorted(list(results['education']))

        return results

analyzer = ProfileAnalyzer()

@tool
def analyze_professional_profile(name: str, company: str = "") -> str:
    """Analisa o perfil profissional de uma pessoa, buscando informações sobre carreira, habilidades e educação."""
    results = analyzer.search_professional_info(name, company)

    output = [f"=== Análise Profissional: {name} ===\n"]

    if results['profile_summary']:
        output.append("Resumo Profissional:")
        for profile in results['profile_summary']:
            output.append(f"- {profile['title']}")
            output.append(f"  {profile['summary']}")
            output.append(f"  URL: {profile['url']}\n")

    if results['roles']:
        output.append("Cargos Identificados:")
        for role in results['roles']:
            output.append(f"- {role}")
        output.append("")

    if results['skills']:
        output.append("Habilidades Técnicas:")
        for skill in results['skills']:
            output.append(f"- {skill}")
        output.append("")

    if results['education']:
        output.append("Formação Acadêmica:")
        for edu in results['education']:
            output.append(f"- {edu}")
        output.append("")

    return '\n'.join(output)
