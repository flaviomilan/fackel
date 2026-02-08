from __future__ import annotations

import json
import logging
from typing import Any

from fackel.core.observability import get_observability, observe, get_langfuse_handler
from fackel.schemas.state import AgentState


class LLMReporter:
    """Generates a final security report using an LLM based on collected data."""

    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.3):
        try:
            from langchain_openai import ChatOpenAI
            # Initialize with Langfuse callback handler
            callbacks = get_langfuse_handler()
            self.llm = ChatOpenAI(
                model=model,
                temperature=temperature,
                callbacks=callbacks if callbacks else None,
            )
        except ImportError:
            # Fallback or error if not installed, but consistent with Planner
            self.llm = None

        self.model = model
        self.logger = logging.getLogger("fackel.reporter")
        self.observability = get_observability()

    @observe(name="incremental_analysis")
    def analyze_incremental(self, tool_name: str, tool_output: str, domain: str) -> str:
        """Analyzes the output of a single tool execution to generate an incremental insight."""
        if not self.llm:
            self.logger.debug(f"Skipping analysis for {tool_name}: LLM not available")
            return ""
        
        # Ensure tool_output is a string
        if not isinstance(tool_output, str):
            tool_output = str(tool_output)
        
        # Strip whitespace for accurate length check
        tool_output_stripped = tool_output.strip()
        
        # Skip truly empty outputs
        if not tool_output_stripped or len(tool_output_stripped) < 10:
            self.logger.debug(f"Skipping analysis for {tool_name}: Output too short ({len(tool_output_stripped)} chars)")
            return ""
        
        # Skip explicit error messages (not just presence of word "error")
        error_indicators = [
            "error:",
            "failed to",
            "could not",
            "unable to",
            "no results found",
            "api key required",
            "authentication failed",
            "tool not found",
        ]
        output_lower = tool_output_stripped.lower()
        if any(indicator in output_lower for indicator in error_indicators):
            self.logger.debug(f"Skipping analysis for {tool_name}: Error message detected")
            return ""
        
        self.logger.info(f"Analyzing output for {tool_name} ({len(tool_output)} chars)...")

        # Truncate extremely large outputs for the incremental step too, 
        # but keep enough to be useful (e.g. 15k chars ~ 3-4k tokens).
        # Nuclei scans can be huge, but usually findings are repetitive.
        truncated_output = tool_output[:32000] 
        if len(tool_output) > 32000:
            truncated_output += "\n...(output truncated)..."

        prompt = f"""
Você é um Analista de Segurança especializado em Reconhecimento e Testes de Penetração.
Analise a saída bruta da ferramenta '{tool_name}' executada contra o domínio '{domain}'.

SAÍDA DA FERRAMENTA:
```
{truncated_output}
```

OBJETIVO DA ANÁLISE:
Extrair informações acionáveis e relevantes para segurança ofensiva desta execução específica.

TAREFAS:
1. **Identificar Descobertas Críticas/Altas/Médias:**
   - Vulnerabilidades confirmadas (com CVEs quando disponível)
   - Exposições de serviços sensíveis
   - Configurações incorretas de segurança
   - Credenciais ou dados sensíveis vazados
   - Vetores de ataque potenciais

2. **Filtrar Ruído:**
   - Ignore informações genéricas ou irrelevantes
   - Descarte falsos positivos óbvios
   - Foque em dados exploráveis

3. **Contexto Técnico:**
   - Para portas abertas: especifique serviço, versão e protocolo
   - Para vulnerabilidades: inclua severity, impacto e exploitabilidade
   - Para tecnologias: versões específicas e componentes identificados
   - Para subdomínios/hosts: IPs associados e propósito inferido

4. **Preservação de Evidências (IMPORTANTE):**
   - Inclua trechos exatos da saída bruta (URLs, IPs, CVE IDs, headers, textos de match) que comprovam as descobertas.
   - Não apenas resuma; mostre os dados brutos relevantes para que não se percam.

5. **Formato de Saída:**
   - Se houver descobertas: liste em bullet points técnicos e objetivos, seguidos dos trechos de evidência.
   - Se não houver descobertas significativas: retorne "No significant findings."
   - Seja conciso mas tecnicamente preciso
   - Use terminologia de segurança apropriada
   - NÃO mencione o nome da ferramenta na análise (já está no contexto)

EXEMPLO DE SAÍDA ESPERADA (apenas formato):
- **[SEVERITY]** Descrição técnica da descoberta
  - Detalhe: (ex: Nginx 1.14.2)
  - Evidência: `Server: nginx/1.14.2`

  - Impacto ou implicação de segurança
  - Indicador de exploitabilidade quando relevante

IMPORTANTE:
- Baseie-se APENAS no output fornecido
- NÃO especule ou invente vulnerabilidades
- Mantenha objetividade técnica
- Priorize qualidade sobre quantidade
"""
        try:
            self.logger.info(f"Analyzing output for tool: {tool_name}")
            response = self.llm.invoke(prompt)
            
            # Track LLM call with Langfuse
            self.observability.track_llm_call(
                component=f"incremental_analysis.{tool_name}",
                model=self.model,
                prompt=prompt,
                response=response,
                metadata={
                    "tool": tool_name,
                    "domain": domain,
                    "output_length": len(tool_output),
                    "truncated": len(tool_output) > 32000,
                },
            )
            
            return response.content
        except Exception as e:
            self.logger.error(f"Failed to analyze tool output: {e}")
            return f"Error analyzing {tool_name}: {e}"

    @observe(name="final_report_generation")
    def generate(self, state: AgentState) -> str:
        if not self.llm:
            return "LLM Reporter not available (langchain-openai not installed)."

        # Prepare context from store
        report_data = state.store.report.model_dump()
        
        # Optimize context size to avoid 429/Context Limit errors
        pruned_data = self._prune_report_data(report_data)
        
        context_json = json.dumps(pruned_data, default=str, indent=2)

        # Include incremental analysis logs to enrich the final report
        analysis_context = ""
        if state.analysis_log:
            analysis_context = "ANÁLISE INCREMENTAL (Logs por ferramenta):\n"
            for log in state.analysis_log:
                analysis_context += f"\n--- Análise da ferramenta {log['tool']} ---\n{log['analysis']}\n"

        prompt = f"""
Você é um Analista de Segurança Sênior especializado em OSINT e Reconhecimento. Sua tarefa é elaborar um relatório técnico profissional de reconhecimento de segurança baseado nos dados coletados e nos logs de análise incremental.

Domínio Alvo: {state.domain}
Modo de Varredura: {"Ativa" if state.active_scan else "Passiva"}

Dados Coletados (JSON):
```json
{context_json}
```

{analysis_context}

ESTRUTURA DO RELATÓRIO:

1. SUMÁRIO EXECUTIVO
   - Visão geral objetiva da postura de segurança do alvo
   - Principais descobertas (máximo 3-5 pontos críticos)
   - Nível de exposição geral (Baixo/Médio/Alto/Crítico)

2. ANÁLISE DA SUPERFÍCIE DE ATAQUE
   
   2.1 Infraestrutura Exposta
   - Hosts e endereços IP identificados
   - Subdomínios e serviços acessíveis
   - Análise de DNS e registros relevantes
   
   2.2 Portas e Serviços
   - Portas abertas por host/IP
   - Serviços em execução e versões identificadas
   - Protocolos e configurações detectadas
   
   2.3 Stack Tecnológica
   - Servidores web e aplicações
   - Frameworks e bibliotecas
   - Sistemas operacionais e componentes de infraestrutura
   - Serviços de terceiros integrados

3. DESCOBERTAS E VULNERABILIDADES

   3.1 Descobertas Críticas e de Alta Severidade
   - CVEs confirmados com código de identificação
   - Configurações incorretas verificadas
   - Exposições de dados sensíveis
   
   3.2 Descobertas de Média Severidade
   - Problemas de configuração
   - Versões desatualizadas de software
   - Headers de segurança ausentes
   
   3.3 Observações Relevantes
   - Padrões de comportamento da infraestrutura
   - Possíveis vetores de ataque
   - Informações vazadas publicamente

4. ANÁLISE DE RISCO
   - Impacto potencial das descobertas
   - Probabilidade de exploração
   - Classificação de risco (Crítico/Alto/Médio/Baixo/Informativo)

5. RECOMENDAÇÕES PRIORITIZADAS
   - Ações imediatas (0-7 dias)
   - Ações de curto prazo (1-4 semanas)
   - Ações de médio/longo prazo (1-3 meses)
   - Melhorias de hardening e monitoramento

DIRETRIZES IMPORTANTES:
- Baseie-se EXCLUSIVAMENTE nos dados fornecidos no JSON
- NÃO invente ou especule sobre vulnerabilidades não presentes nos dados
- Se nenhuma vulnerabilidade foi encontrada, declare isso explicitamente e foque na exposição da superfície de ataque
- Priorize descobertas confirmadas sobre indicativos ou possibilidades
- Use linguagem técnica precisa, mas compreensível
- Mantenha tom profissional e objetivo
- NÃO mencione nomes de ferramentas de varredura (exemplo: substitua "detectado pelo Nuclei" por "identificado durante a análise")
- Cite CVEs com formato correto (CVE-YYYY-XXXXX) quando aplicável
- Inclua severity scores (CVSS) quando disponíveis nos dados
- Se não houver dados em alguma seção, indique "Nenhuma informação coletada" ou "Não aplicável ao escopo da varredura"

FORMATO DE SAÍDA:
- Use markdown para formatação clara
- Inclua tabelas quando apropriado para organizar dados
- Use listas numeradas para priorização
- Destaque informações críticas com **negrito**
- Mantenha parágrafos concisos e objetivos
"""

        try:
            self.logger.info("Invoking LLM for final report generation...")
            response = self.llm.invoke(prompt)
            
            # Track final report generation with Langfuse
            self.observability.track_llm_call(
                component="final_report",
                model=self.model,
                prompt=prompt,
                response=response,
                metadata={
                    "domain": state.domain,
                    "active_scan": state.active_scan,
                    "findings_count": len(state.store.report.findings) if state.store else 0,
                    "tools_executed": len(state.completed) if state.completed else 0,
                },
            )
            
            return response.content
        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}")
            return f"Error generating report: {e}"

    def _prune_report_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Reduces data size by removing heavy raw evidence key."""
        import copy
        pruned = copy.deepcopy(data)
        
        # 'evidence' contains full raw JSON outputs from tools (megabytes of text).
        # We rely on 'hosts', 'findings', and 'services' which are normalized.
        if "evidence" in pruned:
            tool_counts = {}
            for e in pruned.get("evidence", []):
                t = e.get("source_tool", "unknown")
                tool_counts[t] = tool_counts.get(t, 0) + 1
            
            # Replace full evidence list with a summary count to save tokens
            pruned["evidence_summary"] = tool_counts
            del pruned["evidence"]

        # Truncate large findings evidence if present
        if "findings" in pruned:
            for f in pruned["findings"]:
                if f.get("evidence") and len(str(f["evidence"])) > 200:
                    f["evidence"] = str(f["evidence"])[:200] + "... (truncated)"
        
        return pruned

