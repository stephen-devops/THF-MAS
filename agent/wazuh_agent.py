"""
Wazuh Security Agent using LangChain v1 create_agent
"""
from langchain.agents import create_agent
from langgraph.checkpoint.memory import MemorySaver
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage
from typing import Dict, Any, List
import structlog
import asyncio

from functions._shared.opensearch_client import WazuhOpenSearchClient
from tools.wazuh_tools import get_all_tools
from .state import THFState, ContextMiddleware

logger = structlog.get_logger()


class WazuhSecurityAgent:
    """
    LangGraph-based security agent for Wazuh SIEM
    """

    def __init__(self, anthropic_api_key: str, opensearch_config: Dict[str, Any]):
        """
        Initialize the Wazuh security agent

        Args:
            anthropic_api_key: Anthropic API key
            opensearch_config: OpenSearch connection configuration
        """
        self.anthropic_api_key = anthropic_api_key
        self.opensearch_config = opensearch_config

        # Initialize OpenSearch client
        self.opensearch_client = WazuhOpenSearchClient(**opensearch_config)

        # Initialize LLM
        self.llm = ChatAnthropic(
            model="claude-sonnet-4-20250514",
            temperature=0.1,
            anthropic_api_key=anthropic_api_key,
            max_tokens=3000,
            timeout=300,
        )

        # Initialize tools (no agent reference needed)
        self.tools = get_all_tools(self.opensearch_client)

        # System prompt
        self.system_prompt = """You are a Wazuh SIEM security analyst assistant. You help users investigate security incidents, analyze alerts, and understand their security posture.

Key guidelines:
- Always use the appropriate tools for data retrieval
- Provide actionable security insights
- Highlight critical findings and potential threats
- Explain technical concepts in clear terms
- Suggest follow-up investigations when relevant
- Maintain security context in all responses
- Focus on the most important security information
- If a tool returns placeholder data, acknowledge it's not yet implemented

Available tools cover:
- Entity investigation for specific hosts, users, processes, files, IPs (investigate_entity)
- Alert analysis and statistics across multiple alerts (analyze_alerts)
- Threat detection and MITRE ATT&CK mapping (detect_threats)
- Relationship mapping between entities (map_relationships)
- Anomaly detection (find_anomalies)
- Timeline reconstruction (trace_timeline)
- Vulnerability checking (check_vulnerabilities)
- Agent monitoring (monitor_agents)

Always provide context about what the data means from a security perspective.

When context hints appear (e.g. references to "these alerts", "this host", "same host"), use the context information provided to maintain query continuity with previous investigations."""

        # Checkpointer — persists full state (including messages) per thread_id
        self.checkpointer = MemorySaver()

        # Build the LangChain agent (v1 API)
        self.graph = create_agent(
            model=self.llm,
            tools=self.tools,
            state_schema=THFState,
            checkpointer=self.checkpointer,
            system_prompt=self.system_prompt,
            middleware=[ContextMiddleware()],
        )

        logger.info("Wazuh Security Agent initialized (LangGraph)",
                     tools_count=len(self.tools),
                     model="claude-sonnet-4-20250514")

    async def query(self, user_input: str, session_id: str = "default") -> str:
        """
        Process user query and return response with session-based context.

        Args:
            user_input: User's natural language query
            session_id: Unique session identifier for conversation context

        Returns:
            Agent's response string
        """
        config = {"configurable": {"thread_id": session_id}}

        try:
            response = await self._invoke_with_retry(
                {"messages": [HumanMessage(content=user_input)]},
                config,
            )
            return response["messages"][-1].content

        except Exception as e:
            logger.error("Agent query failed",
                         error=str(e),
                         query_preview=user_input[:100],
                         session_id=session_id)
            return f"I encountered an error processing your request: {str(e)}"

    async def _invoke_with_retry(self, inputs: dict, config: dict, max_retries: int = 2) -> dict:
        """Invoke the graph with retry logic for API overload (529)."""
        for attempt in range(max_retries + 1):
            try:
                return await self.graph.ainvoke(inputs, config=config)
            except Exception as e:
                error_str = str(e)
                if ("overloaded" in error_str.lower() or "529" in error_str) and attempt < max_retries:
                    wait_time = (2 ** attempt) * 2  # 2s, 4s
                    logger.warning(f"API overloaded, retrying in {wait_time}s "
                                   f"(attempt {attempt + 1}/{max_retries + 1})")
                    await asyncio.sleep(wait_time)
                    continue
                raise

    async def reset_memory(self, session_id: str = None):
        """Reset conversation memory for a session.

        With MemorySaver there is no direct delete API, so we record a
        timestamp that the query() method can use to start fresh threads.
        In practice, callers should simply start using a new session_id.
        """
        # MemorySaver is an in-memory dict — we can clear the thread directly
        if session_id:
            # Remove the thread's storage entry if it exists
            if hasattr(self.checkpointer, 'storage'):
                keys_to_remove = [k for k in self.checkpointer.storage if k[0] == session_id]
                for k in keys_to_remove:
                    del self.checkpointer.storage[k]
            logger.info("Session memory reset", session_id=session_id)
        else:
            # Reset all sessions
            if hasattr(self.checkpointer, 'storage'):
                self.checkpointer.storage.clear()
            logger.info("All session memories reset")

    def get_session_info(self, session_id: str = None) -> dict:
        """Get information about active sessions."""
        if session_id:
            # Check if there are checkpoints for this thread
            has_data = False
            msg_count = 0
            if hasattr(self.checkpointer, 'storage'):
                thread_keys = [k for k in self.checkpointer.storage if k[0] == session_id]
                has_data = len(thread_keys) > 0
                if has_data:
                    # Try to get message count from latest checkpoint
                    try:
                        config = {"configurable": {"thread_id": session_id}}
                        checkpoint = self.checkpointer.get(config)
                        if checkpoint and "channel_values" in checkpoint:
                            messages = checkpoint["channel_values"].get("messages", [])
                            msg_count = len(messages)
                    except Exception:
                        pass
            return {
                "session_id": session_id,
                "message_count": msg_count,
                "exists": has_data,
            }
        else:
            # List all sessions
            active_sessions = set()
            if hasattr(self.checkpointer, 'storage'):
                for key in self.checkpointer.storage:
                    active_sessions.add(key[0])
            return {
                "total_sessions": len(active_sessions),
                "active_sessions": list(active_sessions),
            }

    async def test_connection(self) -> bool:
        """Test connection to OpenSearch."""
        try:
            return await self.opensearch_client.test_connection()
        except Exception as e:
            logger.error("Connection test failed", error=str(e))
            return False

    async def get_available_indices(self) -> List[str]:
        """Get list of available Wazuh indices."""
        try:
            return await self.opensearch_client.get_indices()
        except Exception as e:
            logger.error("Failed to get indices", error=str(e))
            return []

    async def close(self):
        """Close connections and cleanup."""
        try:
            await self.opensearch_client.close()
            logger.info("Agent connections closed")
        except Exception as e:
            logger.error("Error closing agent connections", error=str(e))

    def get_tool_descriptions(self) -> Dict[str, str]:
        """Get descriptions of available tools."""
        return {tool.name: tool.description for tool in self.tools}

    def get_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        session_count = 0
        if hasattr(self.checkpointer, 'storage'):
            session_count = len(set(k[0] for k in self.checkpointer.storage))
        return {
            "model": "claude-sonnet-4-20250514",
            "tools_available": len(self.tools),
            "tool_names": [tool.name for tool in self.tools],
            "opensearch_host": self.opensearch_config.get("host"),
            "opensearch_port": self.opensearch_config.get("port"),
            "memory_type": "LangGraph MemorySaver (checkpointed)",
            "active_sessions": session_count,
            "agent_type": "LangGraph ReAct Agent",
        }
