"""
Lightweight tool selector using Haiku to classify queries
and select relevant tools before the main agent runs.
"""
from langchain_anthropic import ChatAnthropic
from typing import List, Dict, Any
import structlog
import json

logger = structlog.get_logger()


# Pivot map: tool -> additional tools likely needed if the agent needs to adapt
PIVOT_MAP: Dict[str, List[str]] = {
    "analyze_alerts": ["investigate_entity", "find_anomalies"],
    "investigate_entity": ["map_relationships", "analyze_alerts"],
    "map_relationships": ["investigate_entity", "analyze_alerts", "detect_threats"],
    "detect_threats": ["investigate_entity", "trace_timeline", "map_relationships"],
    "find_anomalies": ["analyze_alerts", "investigate_entity"],
    "trace_timeline": ["investigate_entity", "detect_threats"],
    "check_vulnerabilities": ["monitor_agents", "investigate_entity"],
    "monitor_agents": ["check_vulnerabilities", "investigate_entity"],
}

# All valid tool names for validation
ALL_TOOL_NAMES = list(PIVOT_MAP.keys())

SELECTOR_PROMPT = """You are a tool routing classifier for a security SIEM agent. Given a user query, select the PRIMARY tools needed (1-3 max).

Available tools:
- analyze_alerts: Aggregate/filter/rank/distribute alerts across multiple entities
- investigate_entity: Get alerts/details/status for a SINGLE entity (host, user, process, file, IP)
- map_relationships: Map connections BETWEEN entities (who spawned/created/accessed what)
- detect_threats: MITRE ATT&CK techniques, tactics, threat actors, IoCs, attack chains
- find_anomalies: Threshold breaches, behavioral deviations, trend anomalies (RCF baselines)
- trace_timeline: Chronological event timelines (when did things happen)
- check_vulnerabilities: CVEs, patches, vulnerability scanning
- monitor_agents: Wazuh agent status, versions, health

Rules:
- Select ONLY the tools directly needed for this query (1-3 tools)
- If query mentions a specific entity AND wants relationships/connections -> map_relationships
- If query mentions a specific entity AND wants its alerts/status/details -> investigate_entity
- If query wants aggregate statistics across many entities -> analyze_alerts
- If query mentions anomalies, thresholds, baselines, deviations -> find_anomalies
- If query mentions timeline, sequence, "when did" -> trace_timeline
- If query mentions MITRE, techniques, T1xxx, tactics, attack chains -> detect_threats
- If query mentions CVE, vulnerabilities, patches -> check_vulnerabilities
- If query mentions agent status, agent health, agent version -> monitor_agents

Respond with ONLY a JSON array of tool names. Example: ["analyze_alerts", "investigate_entity"]"""


class ToolSelector:
    """Selects relevant tools for a query using a fast Haiku classifier."""

    def __init__(self, anthropic_api_key: str):
        self.llm = ChatAnthropic(
            model="claude-haiku-4-5-20251001",
            temperature=0.0,
            anthropic_api_key=anthropic_api_key,
            max_tokens=100,
            timeout=10
        )

    async def select_tools(self, user_input: str, context_result: Dict[str, Any] = None) -> List[str]:
        """
        Select relevant tools for the given query.

        Args:
            user_input: User's natural language query
            context_result: Context from ConversationContextProcessor (optional)

        Returns:
            List of tool names (primary + pivot tools), deduplicated
        """
        try:
            messages = [
                ("system", SELECTOR_PROMPT),
                ("human", user_input)
            ]

            response = await self.llm.ainvoke(messages)
            content = response.content.strip()

            # Handle cases where model wraps in markdown code block
            if content.startswith("```"):
                content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()

            primary_tools = json.loads(content)

            # Validate tool names
            primary_tools = [t for t in primary_tools if t in ALL_TOOL_NAMES]

            if not primary_tools:
                logger.warning("Tool selector returned no valid tools, falling back to all tools")
                return ALL_TOOL_NAMES

            # Expand with pivot tools
            selected = set(primary_tools)
            for tool in primary_tools:
                pivots = PIVOT_MAP.get(tool, [])
                selected.update(pivots)

            selected_list = list(selected)

            logger.info("Tool selector completed",
                       query_preview=user_input[:80],
                       primary_tools=primary_tools,
                       with_pivots=selected_list,
                       total_selected=len(selected_list))

            return selected_list

        except Exception as e:
            logger.error("Tool selector failed, falling back to all tools",
                        error=str(e),
                        query_preview=user_input[:80])
            # Graceful fallback: use all tools (same as current behavior)
            return ALL_TOOL_NAMES
