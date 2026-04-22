"""
Typed state and context middleware for the THF LangGraph agent.

Replaces:
- ConversationSummaryBufferMemory (session_memories, _create_session_memory, etc.)
- ConversationContextProcessor (agent/context_processor.py — 602 lines)
- _current_context_result instance variable
- _create_context_enriched_input() in wazuh_agent.py
"""
import json
import structlog
from typing import Any
from typing_extensions import NotRequired
from langchain.agents.middleware import AgentMiddleware, AgentState
from langchain_core.messages import AIMessage, ToolMessage, HumanMessage

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Contextual keyword list (ported from context_processor.py ~30 lines)
# ---------------------------------------------------------------------------
CONTEXTUAL_KEYWORDS = [
    # Demonstrative pronouns and determiners
    "those", "these", "that host", "this host", "the ones", "such",
    # Threat hunting references
    "the critical ones", "the high priority", "critical alerts", "high severity",
    "those alerts", "these alerts", "these events", "said alerts", "said events",
    "those processes", "these processes", "mentioned", "above", "earlier",
    # Contextual location/time references
    "from there", "on that host", "for that user", "same host", "same user",
    "same timeframe", "same period", "from before", "previously mentioned",
    # Request for additional details
    "more details", "more information", "further analysis", "dig deeper",
    "expand on", "tell me more", "additional context", "deeper dive",
]


# ---------------------------------------------------------------------------
# THFState — typed state extending AgentState (TypedDict)
# ---------------------------------------------------------------------------
class THFState(AgentState):
    """Typed state for the THF security agent graph.

    Inherits `messages` (with add_messages reducer) from AgentState.
    Custom fields carry structured context between turns.
    """
    previous_host: NotRequired[str]
    previous_time_range: NotRequired[str]
    previous_entity: NotRequired[str]
    previous_rule_ids: NotRequired[list[str]]
    suggested_filters: NotRequired[dict]


# ---------------------------------------------------------------------------
# Context extraction helpers
# ---------------------------------------------------------------------------
def _extract_context_from_tool_messages(messages: list) -> dict:
    """Parse structured JSON from ToolMessage objects to extract context.

    Returns a dict with keys: host, time_range, entity, rule_ids, filters.
    Only returns values that were actually found.
    """
    context: dict[str, Any] = {}

    # Walk messages in reverse so the most recent tool result wins
    for msg in reversed(messages):
        if not isinstance(msg, ToolMessage):
            continue

        try:
            # ToolMessage.content is the string returned by the tool
            content = msg.content
            if isinstance(content, str):
                # Strip anomaly formatting instructions if present
                if content.startswith("[ANOMALY"):
                    newline_idx = content.find("\n{")
                    if newline_idx != -1:
                        content = content[newline_idx + 1:]

                data = json.loads(content)
            elif isinstance(content, dict):
                data = content
            else:
                continue
        except (json.JSONDecodeError, TypeError):
            continue

        # Extract host from search_parameters or query_info
        for params_key in ("search_parameters", "query_info", "parameters"):
            params = data.get(params_key, {})
            if isinstance(params, dict):
                # Host
                host = params.get("host") or params.get("entity_id") or params.get("agent_name")
                if host and "host" not in context:
                    context["host"] = host

                # Time range
                tr = params.get("time_range") or params.get("timeframe")
                if tr and "time_range" not in context:
                    context["time_range"] = tr

                # Entity
                entity = params.get("entity") or params.get("entity_id")
                if entity and "entity" not in context:
                    context["entity"] = entity

        # Extract from filters dict inside search_parameters
        search_params = data.get("search_parameters")
        filters = search_params.get("filters", {}) if isinstance(search_params, dict) else {}
        if isinstance(filters, dict):
            if filters.get("host") and "host" not in context:
                context["host"] = filters["host"]

        # Rule IDs from results
        rule_ids = set()
        for alert in (data.get("alerts") or data.get("events") or []):
            if isinstance(alert, dict):
                rid = alert.get("rule_id") or alert.get("rule", {}).get("id")
                if rid:
                    rule_ids.add(str(rid))
        if rule_ids and "rule_ids" not in context:
            context["rule_ids"] = list(rule_ids)

        # Accumulated filters
        if filters and "filters" not in context:
            context["filters"] = filters

    return context


def _has_contextual_reference(user_text: str) -> bool:
    """Check if the user's message references previous context."""
    lower = user_text.lower()
    return any(kw in lower for kw in CONTEXTUAL_KEYWORDS)


def _build_context_hint(context: dict) -> str:
    """Build a concise context hint string for the LLM."""
    parts = []
    if context.get("host"):
        parts.append(f'previous host: "{context["host"]}"')
    if context.get("time_range"):
        parts.append(f'previous time range: {context["time_range"]}')
    if context.get("entity"):
        parts.append(f'previous entity: "{context["entity"]}"')
    if context.get("rule_ids"):
        ids = context["rule_ids"][:5]  # cap at 5 for brevity
        parts.append(f'rule IDs from last query: {", ".join(ids)}')
    if context.get("filters"):
        parts.append(f'previous filters: {json.dumps(context["filters"])}')

    return "[Context from previous queries: " + "; ".join(parts) + "]"


# ---------------------------------------------------------------------------
# ContextMiddleware — replaces pre_model_hook for create_agent v1 API
# ---------------------------------------------------------------------------
class ContextMiddleware(AgentMiddleware):
    """Middleware that extracts context from tool results and injects hints.

    This replaces the 600-line ConversationContextProcessor. It:
    1. Scans ToolMessage objects for structured JSON context
    2. Updates THFState context fields
    3. Injects a context hint into the HumanMessage when the user references prior results
    """

    state_schema = THFState

    def before_model(self, state: THFState, runtime) -> dict[str, Any] | None:
        """Extract structured context from previous tool results and inject hints."""
        messages = state.get("messages", [])
        if not messages:
            return None

        # Find the latest HumanMessage to check for contextual references
        latest_human = None
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage):
                latest_human = msg
                break

        # Extract context from tool messages
        context = _extract_context_from_tool_messages(messages)

        # Build state updates for context fields
        updates: dict[str, Any] = {}
        if context.get("host"):
            updates["previous_host"] = context["host"]
        if context.get("time_range"):
            updates["previous_time_range"] = context["time_range"]
        if context.get("entity"):
            updates["previous_entity"] = context["entity"]
        if context.get("rule_ids"):
            updates["previous_rule_ids"] = context["rule_ids"]
        if context.get("filters"):
            updates["suggested_filters"] = context["filters"]

        # Only inject context hint if user references previous context
        if latest_human and context and _has_contextual_reference(latest_human.content):
            hint = _build_context_hint(context)
            # Prepend hint to the HumanMessage content instead of adding a
            # separate SystemMessage — Anthropic rejects non-consecutive system messages
            enriched_content = f"{hint}\n{latest_human.content}"
            enriched_human = HumanMessage(content=enriched_content)
            updates["messages"] = [
                enriched_human if msg is latest_human else msg
                for msg in messages
            ]

            logger.info("ContextMiddleware injected context hint",
                         hint_preview=hint[:120],
                         context_keys=list(context.keys()))

        return updates if updates else None

    def after_model(self, state: THFState, runtime) -> dict[str, Any] | None:
        """Log the LLM's tool call decisions for terminal visibility."""
        messages = state.get("messages", [])
        if not messages:
            return None

        last_msg = messages[-1]
        if not isinstance(last_msg, AIMessage):
            return None

        # Log tool calls (equivalent to old verbose=True Action: blocks)
        tool_calls = getattr(last_msg, "tool_calls", None)
        if tool_calls:
            for tc in tool_calls:
                logger.info("Agent tool call",
                            tool=tc.get("name"),
                            args=tc.get("args"))
        elif last_msg.content:
            # Final answer — log a preview
            logger.info("Agent response",
                        response_preview=last_msg.content[:200])

        return None
