import os

from dotenv import load_dotenv
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain.globals import set_llm_cache
from langchain_community.cache import SQLiteCache
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from src.collectors.collectors import get_all_tools

set_llm_cache(SQLiteCache(database_path=".langchain.db"))


class OsintProcessor:
    """
    Processes an OSINT request using a LangChain agent.
    """

    def __init__(self, active_scan: bool = False):
        """
        Initializes the processor, loading environment variables.

        Args:
            active_scan: Whether to enable active scanning tools
        """
        load_dotenv()
        if not os.getenv("OPENAI_API_KEY"):
            raise ValueError("OPENAI_API_KEY not found in environment variables.")

        self.llm = ChatOpenAI(
            temperature=0, model="gpt-4-turbo-preview", streaming=True
        )
        self.active_scan = active_scan
        self.tools = get_all_tools(active_scan=active_scan)

    def _build_prompt(self, active_scan: bool = False):
        """
        Builds the system prompt for the agent based on the scanning mode.
        """
        system_prompt = """You are Fackel, a world-class cybersecurity analyst and OSINT specialist.
Your mission is to conduct a comprehensive OSINT investigation of a given domain.

METHODOLOGY:
1.  **Initial Reconnaissance**: Start by gathering basic domain information with `whois_lookup`.
2.  **Subdomain and Host Enumeration**: Use `dnsdumpster_lookup` and `virustotal_subdomain_enum` as your primary tools to get a comprehensive list of subdomains and their IP addresses. If you don't have access to Shodan or Censys API keys, `dnsdumpster_lookup` is your best alternative for mapping infrastructure.
"""

        if active_scan:
            system_prompt += """3.  **Active Host Probing and Scanning**: This is a two-stage process.
- **Stage 1: Probing**: After finding subdomains, you MUST validate them with the `probe_host` tool. This quickly identifies which hosts are live and have web servers.
- **Stage 2: Deep Scan**: Based on the results from the probing, select the most interesting live hosts for a full Nmap scan. You MUST use `nmap_port_scan` on these selected hosts. This tool will provide detailed service, version, and **vulnerability (CVE)** information.
"""
            system_prompt += """4.  **Company and Technology Profiling**: Investigate the company associated with the domain. Use search tools (`duckduckgo_lookup`, `serp_search`) to find company details. Use `job_search` to discover technologies and software used by the company.
5.  **People Discovery and Profiling**: Your primary tool for finding people is `search_linkedin_for_employees`. Use it to get a list of potential employees. For the most relevant individuals found (e.g., technical roles, leadership), use `analyze_professional_profile` to get more detailed career and skills information.
6.  **Email Discovery and Analysis**: While investigating, look for email addresses in the content of web pages (`extract_webpage_content`) and other search results. For every email address you find, you MUST use the `analyze_email` tool to check its exposure in data breaches and its digital footprint.
7.  **Synthesize and Report**: Once you have exhausted all available tools, synthesize all findings into a single, coherent, and well-structured final report in Portuguese. The report should be detailed and include a **dedicated section for Vulnerability Analysis**, highlighting any CVEs found and their potential impact.
"""
        else:
            system_prompt += """3.  **Company and Technology Profiling**: Investigate the company associated with the domain. Use search tools (`duckduckgo_lookup`, `serp_search`) to find company details. Use `job_search` to discover technologies and software used by the company.
4.  **People Discovery and Profiling**: Your primary tool for finding people is `search_linkedin_for_employees`. Use it to get a list of potential employees. For the most relevant individuals found (e.g., technical roles, leadership), use `analyze_professional_profile` to get more detailed career and skills information.
5.  **Email Discovery and Analysis**: While investigating, look for email addresses in the content of web pages (`extract_webpage_content`) and other search results. For every email address you find, you MUST use the `analyze_email` tool to check its exposure in data breaches and its digital footprint.
6.  **Synthesize and Report**: Once you have exhausted all available tools and gathered sufficient information, synthesize all findings into a single, coherent, and well-structured final report in Portuguese. The report should be detailed and provide a clear picture of the domain's OSINT profile.
"""

        system_prompt += "\nIMPORTANT:\n- Execute tools logically and sequentially. Use the output of one tool to inform the input of the next.\n- If a tool fails or returns no information, note it down and move to the next logical step.\n- Structure your final report using Markdown for clear formatting (e.g., use headings, lists, and bold text).\n- Your final output MUST be the comprehensive report in Portuguese."

        return ChatPromptTemplate.from_messages(
            [
                ("system", system_prompt),
                ("user", "{input}"),
                ("placeholder", "{agent_scratchpad}"),
            ]
        )

    def process_domain(self, domain: str) -> str:
        """
        Process a domain using the OSINT tools and return a comprehensive report.

        Args:
            domain: The domain to investigate

        Returns:
            str: The investigation report in Portuguese
        """
        prompt = self._build_prompt(self.active_scan)
        agent = create_openai_tools_agent(self.llm, self.tools, prompt)
        agent_executor = AgentExecutor(
            agent=agent, tools=self.tools, verbose=True, handle_parsing_errors=True
        )

        result = agent_executor.invoke({"input": f"Investigue o domínio: {domain}"})

        return result["output"]
