"""
Wazuh Security Agent using LangChain
"""
from langchain.agents import AgentExecutor
from langchain.agents.structured_chat.base import create_structured_chat_agent
from langchain.memory import ConversationSummaryBufferMemory
from langchain.callbacks import LangChainTracer
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from typing import Dict, Any, List
import structlog
import os
import asyncio
from collections import defaultdict

from functions._shared.opensearch_client import WazuhOpenSearchClient
from tools.wazuh_tools import get_all_tools
from .context_processor import ConversationContextProcessor

logger = structlog.get_logger()

class WazuhSecurityAgent:
    """
    LangChain-based security agent for Wazuh SIEM
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
            max_tokens=3000,  # Reduced to help prevent API overload
            timeout=300  # Add timeout for overload handling
        )
        
        # Initialize tools
        self.tools = get_all_tools(self.opensearch_client, self)
        
        # Initialize session-based memory storage
        self.session_memories = defaultdict(lambda: self._create_session_memory())
        self.current_session_id = None

        # Initialize default memory for backwards compatibility
        self.memory = self._create_session_memory()

        # Initialize context processor
        self.context_processor = ConversationContextProcessor()
        
        # Enhanced system prompt with context preservation instructions
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

**CRITICAL: Anomaly Detection Response Requirements**
When presenting anomaly detection results, you MUST explicitly state threshold sources and RCF baseline information:

**1. Threshold Source Identification (REQUIRED IN EVERY RESPONSE):**
- If using RCF-learned thresholds: State "Using RCF-learned thresholds from [X-day] baseline (confidence: [Y]%)"
- If using fallback thresholds: State "Using static fallback threshold of [value] (no RCF baseline data available)"
- ALWAYS specify the baseline period (e.g., "7-day RCF baseline", "30-day behavioral baseline")

**2. Three Threshold Types - Define When Mentioned:**
- **User-Provided Threshold**: Numeric value from query (e.g., "threshold: 150") - fallback only when RCF unavailable
- **RCF Feature Thresholds**: Internal OpenSearch plugin thresholds for each RCF feature (alert_count_threshold: 65.7, severity_sum_threshold: 297.4, etc.)
- **RCF-Learned Thresholds**: Dynamic thresholds from baseline analysis - OVERRIDE user-provided values when available

**3. Format Requirements for Anomaly Responses:**
- Start with: "Based on [RCF-learned/static fallback] baseline analysis over the last [X] days..."
- Include: Baseline confidence score (if RCF: "96.44% confidence")
- Specify: Which thresholds were exceeded (e.g., "Alert count: 6,669 (exceeds RCF threshold 65.7 by 6,603)")
- For each anomaly: Clearly state "X exceeds RCF-learned threshold Y" or "X exceeds static threshold Y"

**4. Detection Type-Specific Terminology:**
- **Threshold Detection**: "RCF-learned threshold breach" / "sudden burst exceeding baseline"
- **Trend Detection**: "Progressive escalation above RCF trend baseline" / "directional shift from baseline pattern"
- **Behavioral Detection**: "Behavioral deviation from RCF entity baseline" / "anomalous pattern compared to normal behavior"

**5. Example Good Response Opening:**
"Based on RCF-learned baseline analysis over the last 3 days with 96.44% confidence, I've identified 25 critical threshold breaches. The RCF-learned alert count threshold is 65.7 (baseline mean: 21.25), which was exceeded by the following hosts..."

**6. Example Bad Response (AVOID):**
"I found anomalies exceeding thresholds..." (Missing: which threshold type? What baseline? What confidence?)

Technical note: When context hints from previous input query like "these alerts", "this host", "this command, these processes", etc appear, consider using previous input parameters to maintain query continuity."""

        # Initialize callbacks
        callbacks = []
        # Only enable LangSmith tracing if properly configured
        try:
            if os.getenv("LANGCHAIN_TRACING_V2") == "true" and os.getenv("LANGCHAIN_API_KEY"):
                callbacks.append(LangChainTracer())
                logger.info("LangSmith tracing enabled")
        except Exception as e:
            logger.warning("Failed to initialize LangSmith tracing", error=str(e))

        # Create prompt template for structured chat agent
        # The system prompt needs to include tool information
        system_message = f"""{self.system_prompt}

You have access to the following tools:

{{tools}}

Use a json blob to specify a tool by providing an action key (tool name) and an action_input key (tool input).

Valid "action" values: "Final Answer" or {{tool_names}}

Provide only ONE action per $JSON_BLOB, as shown:

```
{{{{
  "action": $TOOL_NAME,
  "action_input": $INPUT
}}}}
```

Follow this format:

Question: input question to answer
Thought: consider previous and subsequent steps
Action:
```
$JSON_BLOB
```
Observation: action result
... (repeat Thought/Action/Observation N times)
Thought: I know what to respond
Action:
```
{{{{
  "action": "Final Answer",
  "action_input": "Final response to human"
}}}}
```"""

        prompt = ChatPromptTemplate.from_messages([
            ("system", system_message),
            MessagesPlaceholder(variable_name="chat_history", optional=True),
            ("human", "{input}\n\n{agent_scratchpad}"),
        ])

        # Create the structured chat agent
        agent = create_structured_chat_agent(
            llm=self.llm,
            tools=self.tools,
            prompt=prompt
        )

        # Create agent executor
        self.agent = AgentExecutor(
            agent=agent,
            tools=self.tools,
            memory=self.memory,
            verbose=True,
            callbacks=callbacks,
            handle_parsing_errors=True,
            max_iterations=15  # Allow more iterations for complex threat hunting queries
        )
        
        logger.info("Wazuh Security Agent initialized",
                   tools_count=len(self.tools),
                   model="claude-4-sonnet")

    def _create_session_memory(self):
        """Create a new memory instance for a session"""
        # Use ConversationSummaryBufferMemory for better context management
        return ConversationSummaryBufferMemory(
            llm=self.llm,
            max_token_limit=1500,  # Reduced to prevent API overload
            memory_key="chat_history",
            return_messages=True,
            output_key="output"
        )

    def _get_session_memory(self, session_id: str):
        """Get or create memory for a specific session"""
        if session_id not in self.session_memories:
            logger.info("Creating new session memory", session_id=session_id)
        return self.session_memories[session_id]

    def _update_agent_memory(self, session_id: str):
        """Update the agent's memory to use the session-specific memory"""
        if self.current_session_id != session_id:
            self.current_session_id = session_id
            session_memory = self._get_session_memory(session_id)

            # Re-initialize agent with session-specific memory
            callbacks = []
            try:
                if os.getenv("LANGCHAIN_TRACING_V2") == "true" and os.getenv("LANGCHAIN_API_KEY"):
                    callbacks.append(LangChainTracer())
            except Exception as e:
                logger.warning("Failed to initialize LangSmith tracing", error=str(e))

            # Create prompt template for structured chat agent
            # The system prompt needs to include tool information
            system_message = f"""{self.system_prompt}

You have access to the following tools:

{{tools}}

Use a json blob to specify a tool by providing an action key (tool name) and an action_input key (tool input).

Valid "action" values: "Final Answer" or {{tool_names}}

Provide only ONE action per $JSON_BLOB, as shown:

```
{{{{
  "action": $TOOL_NAME,
  "action_input": $INPUT
}}}}
```

Follow this format:

Question: input question to answer
Thought: consider previous and subsequent steps
Action:
```
$JSON_BLOB
```
Observation: action result
... (repeat Thought/Action/Observation N times)
Thought: I know what to respond
Action:
```
{{{{
  "action": "Final Answer",
  "action_input": "Final response to human"
}}}}
```"""

            prompt = ChatPromptTemplate.from_messages([
                ("system", system_message),
                MessagesPlaceholder(variable_name="chat_history", optional=True),
                ("human", "{input}\n\n{agent_scratchpad}"),
            ])

            # Create the structured chat agent
            agent = create_structured_chat_agent(
                llm=self.llm,
                tools=self.tools,
                prompt=prompt
            )

            # Create agent executor with session-specific memory
            self.agent = AgentExecutor(
                agent=agent,
                tools=self.tools,
                memory=session_memory,
                verbose=True,
                callbacks=callbacks,
                handle_parsing_errors=True,
                max_iterations=15  # Allow more iterations for complex threat hunting queries
            )

            logger.info("Agent memory updated for session", session_id=session_id)

    async def query(self, user_input: str, session_id: str = "default") -> str:
        """
        Process user query and return response with session-based context

        Args:
            user_input: User's natural language query
            session_id: Unique session identifier for conversation context

        Returns:
            Agent's response
        """
        try:
            # Update agent memory for this session
            self._update_agent_memory(session_id)

            # Get conversation history for context analysis
            session_memory = self._get_session_memory(session_id)
            chat_history = []
            try:
                # Safely access chat history - memory operations can fail
                if hasattr(session_memory, 'chat_memory'):
                    chat_history = session_memory.chat_memory.messages
            except Exception as mem_error:
                logger.warning("Failed to load chat history, using empty history",
                             error=str(mem_error),
                             session_id=session_id)
                # Reset corrupted memory
                session_memory.clear()
                chat_history = []

            # Process context separately from LLM prompt
            context_result = self.context_processor.process_query_with_context(user_input, chat_history)

            logger.info("Processing agent query with session context",
                       query_preview=user_input[:100],
                       session_id=session_id,
                       history_length=len(chat_history),
                       context_applied=context_result["context_applied"],
                       reasoning=context_result["reasoning"])

            # Create enriched input with context for LLM when context is applied
            enriched_input = user_input
            if context_result["context_applied"]:
                enriched_input = self._create_context_enriched_input(user_input, context_result)

            # Validate input is not empty
            if not enriched_input or not enriched_input.strip():
                logger.error("Empty input detected, using original user_input",
                           enriched_input=enriched_input,
                           user_input=user_input)
                enriched_input = user_input or "Please provide a query."

            # Execute agent with context-aware input
            response = await self._execute_with_retry(enriched_input, context_result)

            logger.info("Agent query completed with context",
                       query_preview=user_input[:100],
                       session_id=session_id,
                       response_length=len(response))

            return response

        except Exception as e:
            logger.error("Agent query failed",
                        error=str(e),
                        query_preview=user_input[:100],
                        session_id=session_id)
            return f"I encountered an error processing your request: {str(e)}"

    async def _execute_with_retry(self, user_input: str, context_result: Dict[str, Any], max_retries: int = 2) -> str:
        """Execute agent with retry logic for API overload"""
        # Store context result for tool execution
        self._current_context_result = context_result

        for attempt in range(max_retries + 1):
            try:
                # Validate user_input is not empty
                if not user_input or not user_input.strip():
                    logger.error("Empty user_input in _execute_with_retry",
                               user_input=user_input,
                               attempt=attempt + 1)
                    raise ValueError("Empty user input provided to agent")

                # Agent expects input as dict with "input" key for STRUCTURED_CHAT type
                agent_input = {"input": user_input.strip()}
                response = await self.agent.ainvoke(agent_input)
                # Extract the output from the response dict
                return response.get("output", str(response))
            except Exception as e:
                error_str = str(e)
                error_type = type(e).__name__

                # Log detailed error information for debugging
                logger.error("Agent execution error",
                           error_type=error_type,
                           error_message=error_str,
                           user_input_preview=user_input[:200],
                           context_filters=context_result.get("suggested_filters", {}),
                           attempt=attempt + 1)

                if "overloaded" in error_str.lower() or "529" in error_str:
                    if attempt < max_retries:
                        wait_time = (2 ** attempt) * 2  # Exponential backoff: 2s, 4s
                        logger.warning(f"API overloaded, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries + 1})")
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        return "I apologize, but the system is currently experiencing high load. Please try your query again in a few moments, or try a more specific question to reduce processing requirements."
                elif "at least one message is required" in error_str.lower() or ("400" in error_str and "messages" in error_str.lower()):
                    # Memory/message construction failure - reset and retry
                    logger.error("Empty messages error detected - memory corruption",
                               error=error_str,
                               user_input=user_input[:200])
                    if attempt < max_retries:
                        # Try to recover by resetting the agent memory
                        try:
                            if hasattr(self, 'agent') and hasattr(self.agent, 'memory'):
                                self.agent.memory.clear()
                            logger.info("Memory cleared, retrying query")
                            await asyncio.sleep(1)
                            continue
                        except Exception as reset_error:
                            logger.error("Failed to reset memory", error=str(reset_error))
                    return "I encountered a memory state error. Please try rephrasing your query with explicit parameters (e.g., specify host, timeframe, and entity names directly) rather than referencing previous context."
                elif "500" in error_str or "api_error" in error_str.lower():
                    # API 500 errors - provide helpful context
                    return f"The AI service encountered an error processing your query. This may be due to: (1) ambiguous entity references - try being more specific (e.g., use full process path instead of just name), (2) complex contextual queries - try rephrasing with explicit parameters, or (3) temporary API issues. Original error: {error_str}"
                else:
                    # Non-overload error, don't retry
                    raise e

        return "Unable to process request due to system overload."

    def _create_context_enriched_input(self, user_input: str, context_result: Dict[str, Any]) -> str:
        """
        Create enriched input that includes context information for the LLM

        Args:
            user_input: Original user input
            context_result: Result from context processor

        Returns:
            Enriched input with context guidance
        """
        suggested_filters = context_result.get("suggested_filters", {})
        suggested_time_range = context_result.get("suggested_time_range")

        # Build context hints
        context_parts = []

        if "host" in suggested_filters:
            context_parts.append(f'host {suggested_filters["host"]} (use "host": "{suggested_filters["host"]}")')

        if suggested_time_range:
            context_parts.append(f"timeframe {suggested_time_range}")

        if "rule.level" in suggested_filters:
            level_filter = suggested_filters["rule.level"]
            if isinstance(level_filter, dict) and "gte" in level_filter:
                if level_filter["gte"] == 12:
                    context_parts.append('critical alerts (use "rule.level": {"gte": 12})')
                elif level_filter["gte"] == 8:
                    context_parts.append('high severity alerts (use "rule.level": {"gte": 8})')

        if "rule.groups" in suggested_filters:
            groups = suggested_filters["rule.groups"]
            if isinstance(groups, list):
                context_parts.append(f"rule groups {', '.join(groups)}")

        # Create enriched input
        if context_parts:
            context_hint = f"[Context from previous query: {', '.join(context_parts)}] "
            enriched_input = context_hint + user_input

            logger.info("Created context-enriched input",
                       original=user_input,
                       context_parts=context_parts,
                       enriched_preview=enriched_input[:150])

            return enriched_input

        return user_input

    async def reset_memory(self, session_id: str = None):
        """Reset conversation memory for a session or all sessions"""
        try:
            if session_id:
                # Reset specific session
                if session_id in self.session_memories:
                    self.session_memories[session_id].clear()
                    logger.info("Session memory reset", session_id=session_id)
                else:
                    logger.info("Session not found for reset", session_id=session_id)
            else:
                # Reset all sessions
                self.session_memories.clear()
                self.current_session_id = None
                self.memory.clear()
                logger.info("All session memories reset")
        except Exception as e:
            logger.error("Failed to reset memory", error=str(e), session_id=session_id)
            raise

    def get_session_info(self, session_id: str = None) -> dict:
        """Get information about active sessions"""
        if session_id:
            session_memory = self.session_memories.get(session_id)
            if session_memory and hasattr(session_memory, 'chat_memory'):
                return {
                    "session_id": session_id,
                    "message_count": len(session_memory.chat_memory.messages),
                    "exists": True
                }
            return {"session_id": session_id, "exists": False}
        else:
            return {
                "total_sessions": len(self.session_memories),
                "active_sessions": list(self.session_memories.keys()),
                "current_session": self.current_session_id
            }

    async def test_connection(self) -> bool:
        """
        Test connection to OpenSearch
        
        Returns:
            True if connection successful
        """
        try:
            return await self.opensearch_client.test_connection()
        except Exception as e:
            logger.error("Connection test failed", error=str(e))
            return False
    
    async def get_available_indices(self) -> List[str]:
        """
        Get list of available Wazuh indices
        
        Returns:
            List of index names
        """
        try:
            return await self.opensearch_client.get_indices()
        except Exception as e:
            logger.error("Failed to get indices", error=str(e))
            return []
    
    async def close(self):
        """Close connections and cleanup"""
        try:
            await self.opensearch_client.close()
            logger.info("Agent connections closed")
        except Exception as e:
            logger.error("Error closing agent connections", error=str(e))
    
    def get_tool_descriptions(self) -> Dict[str, str]:
        """
        Get descriptions of available tools
        
        Returns:
            Dictionary mapping tool names to descriptions
        """
        return {tool.name: tool.description for tool in self.tools}
    
    def get_system_info(self) -> Dict[str, Any]:
        """
        Get system information
        
        Returns:
            Dictionary with system information
        """
        return {
            "model": "claude-4-sonnet",
            "tools_available": len(self.tools),
            "tool_names": [tool.name for tool in self.tools],
            "opensearch_host": self.opensearch_config.get("host"),
            "opensearch_port": self.opensearch_config.get("port"),
            "memory_type": "ConversationSummaryBufferMemory (Session-based)",
            "active_sessions": len(self.session_memories),
            "agent_type": "Structured Chat Zero Shot React Description"
        }