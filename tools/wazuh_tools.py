"""
LangChain tools for Wazuh SIEM functions
"""
from langchain.tools import BaseTool
from langchain.callbacks.manager import AsyncCallbackManagerForToolRun
from typing import ClassVar, Type
import structlog
import json
from schemas.wazuh_schemas import *

logger = structlog.get_logger()


class WazuhBaseTool(BaseTool):
    """Base class for all Wazuh tools"""

    def __init__(self, opensearch_client, agent=None):
        super().__init__()
        # Store opensearch_client as a private attribute to avoid Pydantic validation
        self._opensearch_client = opensearch_client
        self._agent = agent

    @property
    def opensearch_client(self):
        """Get the OpenSearch client"""
        return self._opensearch_client

    @property
    def agent(self):
        """Get the agent reference"""
        return self._agent

    def _merge_context_filters(self, filters, time_range, default_time_range="7d"):
        """
        Merge context processor suggestions with tool parameters

        Handles three scenarios:
        1. Default temporal setting - LLM using tool default → Apply context
        2. Preserved temporal context - Contextual query → Apply context
        3. Submitted temporal value - User explicitly requests new time → Use user's value

        Args:
            filters: Explicit filters from LLM
            time_range: Time range from LLM
            default_time_range: The default time range for this tool (e.g., "7d", "24h")

        Returns:
            Tuple of (merged_filters, final_time_range)
        """
        if not self.agent or not hasattr(self.agent, '_current_context_result'):
            return filters, time_range

        context_result = self.agent._current_context_result

        # SCENARIO 3: If context processor detected explicit new params, don't apply context
        # This handles cases like "Now show me alerts from the past 1 day" (new explicit request)
        if not context_result or not context_result.get("context_applied"):
            logger.info("No context applied - using LLM time_range as-is",
                       time_range=time_range,
                       reason=context_result.get("reasoning") if context_result else "No context available")
            return filters, time_range

        suggested_filters = context_result.get("suggested_filters", {})
        suggested_time_range = context_result.get("suggested_time_range")

        # Merge suggested filters with explicit ones (explicit takes precedence)
        merged_filters = suggested_filters.copy() if suggested_filters else {}
        if filters:
            merged_filters.update(filters)

        # SCENARIO 1 & 2: Determine if we should apply context to time_range
        # Common defaults that LLM uses when not explicitly specified by user
        common_defaults = ["7d", "24h", "1h", "30d", "1d", "12h", "6h", "3d", "14d"]

        # Check if time_range differs from suggested context (possible explicit user request)
        # If user said "past 3 days" (context), then "past 12 hours" (new request),
        # LLM will pass "12h" which differs from context "3d"
        time_differs_from_context = (suggested_time_range and
                                     time_range != suggested_time_range)

        # Apply context if:
        # 1. LLM is using a common default (likely not user-specified), OR
        # 2. LLM's time matches the context (reinforcing existing context)
        if suggested_time_range:
            if time_range in common_defaults:
                # SCENARIO 1: LLM using default → Override with context
                final_time_range = suggested_time_range
                logger.info("Overriding default time_range with context",
                           llm_default=time_range,
                           context_suggested=suggested_time_range,
                           reason="LLM using common default")
            elif time_range == suggested_time_range:
                # SCENARIO 2: LLM matches context → Preserve context
                final_time_range = suggested_time_range
                logger.info("Preserving time_range from context",
                           time_range=time_range,
                           reason="LLM matches context")
            elif time_differs_from_context:
                # SCENARIO 3 (edge case): LLM provides different value that's not in defaults
                # This might be an explicit user request that context processor missed
                # Be conservative: use LLM's value
                final_time_range = time_range
                logger.info("Using LLM time_range despite context",
                           llm_value=time_range,
                           context_value=suggested_time_range,
                           reason="LLM provides non-default value different from context")
            else:
                final_time_range = time_range
        else:
            final_time_range = time_range

        logger.info("Applied context filters",
                   original_filters=filters,
                   suggested_filters=suggested_filters,
                   merged_filters=merged_filters,
                   original_time_range=time_range,
                   final_time_range=final_time_range,
                   context_reasoning=context_result.get("reasoning"))

        return merged_filters, final_time_range


class AnalyzeAlertsTool(WazuhBaseTool):
    """Tool for analyzing Wazuh alerts"""
    name: str = "analyze_alerts"
    description: str = "Aggregate and analyze multiple alerts. Actions: 'ranking' (rank by frequency), 'counting' (count with breakdowns), 'filtering' (filter by criteria), 'distribution' (statistical patterns, supports multi-dimensional like ['severity', 'host'] and temporal histograms). Use for aggregate views: 'top hosts by alert volume', 'alert distribution by severity', 'hourly alert counts'. NOT for single entity investigation (use investigate_entity) or entity relationships (use map_relationships)."
    args_schema: Type[AnalyzeAlertsSchema] = AnalyzeAlertsSchema
    
    def _run(
        self,
        action: str,
        group_by: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        time_range: str = "7d",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for alert analysis"""
        import asyncio
        return asyncio.run(self._arun(action, group_by, filters, limit, time_range, run_manager))

    async def _arun(
        self,
        action: str,
        group_by: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        time_range: str = "7d",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute alert analysis"""
        try:
            # Merge context filters with explicit parameters
            merged_filters, final_time_range = self._merge_context_filters(filters, time_range)

            # Route to specific sub-function
            if action == "ranking":
                from functions.analyze_alerts.rank_alerts import execute
            elif action == "counting":
                from functions.analyze_alerts.count_alerts import execute
            elif action == "filtering":
                from functions.analyze_alerts.filter_alerts import execute
            elif action == "distribution":
                from functions.analyze_alerts.distribution_alerts import execute
            else:
                raise ValueError(f"Unknown action: {action}")

            params = {
                "group_by": group_by,
                "filters": merged_filters,
                "limit": limit,
                "time_range": final_time_range
            }

            result = await execute(self.opensearch_client, params)
            
            logger.info("Alert analysis completed",
                       action=action,
                       results_count=result.get("total_alerts", 0))

            return json.dumps(result, default=str)
            
        except Exception as e:
            logger.error("Alert analysis failed", action=action, error=str(e))

            # Return structured error response instead of raising exception
            return json.dumps({
                "error": True,
                "error_message": f"Alert analysis failed: {str(e)}",
                "action": action,
                "total_alerts": 0,
                "returned_alerts": 0,
                "filters_applied": merged_filters if 'merged_filters' in locals() else {},
                "time_range": final_time_range if 'final_time_range' in locals() else time_range,
                "query_info": {
                    "action": action,
                    "limit": limit,
                    "success": False
                }
            }, default=str)


class InvestigateEntityTool(WazuhBaseTool):
    """Tool for investigating specific entities"""
    name: str = "investigate_entity"
    description: str = "Get alerts, activity, status, or details for a single entity (host, user, process, file, IP). Query types: 'alerts', 'details', 'activity', 'status'. Use for 'what alerts does X have?', 'show details of X'. NOT for relationships between entities (use map_relationships) or aggregate analysis across multiple entities (use analyze_alerts)."
    args_schema: Type[InvestigateEntitySchema] = InvestigateEntitySchema
    
    def _run(
        self,
        entity_type: str,
        entity_id: str,
        query_type: str,
        time_range: str = "24h",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for entity investigation"""
        import asyncio
        return asyncio.run(self._arun(entity_type, entity_id, query_type, time_range, run_manager))

    async def _arun(
        self,
        entity_type: str,
        entity_id: str,
        query_type: str,
        time_range: str = "24h",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute entity investigation"""
        try:
            # FIXED: Merge context filters with explicit parameters
            # Note: entity investigations don't have filters param, but do have time_range
            _, final_time_range = self._merge_context_filters(None, time_range, default_time_range="24h")

            # Route to specific sub-function based on query_type
            # Handle both string and enum values
            query_value = query_type.value if hasattr(query_type, 'value') else query_type

            if query_value == "alerts":
                from functions.investigate_entity.get_alerts_for_entity import execute
            elif query_value == "details":
                from functions.investigate_entity.get_entity_details import execute
            elif query_value == "activity":
                from functions.investigate_entity.get_entity_activity import execute
            elif query_value == "status":
                from functions.investigate_entity.get_entity_status import execute
            else:
                raise ValueError(f"Unknown query_type: {query_value}. Supported types: alerts, details, activity, status")

            params = {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "time_range": final_time_range
            }
            
            result = await execute(self.opensearch_client, params)
            
            logger.info("Entity investigation completed",
                        entity_type=entity_type,
                        entity_id=entity_id,
                        query_type=query_type,
                        total_alerts=result.get("total_alerts", 0))

            return json.dumps(result, default=str)
            
        except Exception as e:
            logger.error("Entity investigation failed",
                         entity_type=entity_type,
                         entity_id=entity_id,
                         error=str(e))

            # Return structured error response instead of raising exception
            return json.dumps({
                "error": True,
                "error_message": f"Entity investigation failed: {str(e)}",
                "entity_type": entity_type,
                "entity_id": entity_id,
                "query_type": query_type,
                "total_alerts": 0,
                "alerts": [],
                "time_range": time_range,
                "query_info": {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "success": False
                }
            }, default=str)


class MapRelationshipsTool(WazuhBaseTool):
    """Tool for mapping relationships between entities"""
    name: str = "map_relationships"
    description: str = """Map directional relationships between entities (users, hosts, files, processes). Identifies who/what spawned, created, modified, accessed, deleted, injected into, or logged into what.

DIRECTION: Subject performing action = source; object receiving action = target. 'What did X do to Y?' → source=X, target=Y.

Omit source_id for bulk queries across all entities of a type. Omit target_type to get all relationship types for an entity. Relationship types: entity_to_entity (direct connections, strength, frequency) or behavioral_correlation (access patterns, temporal clustering, coordinated activities).

NOT for: timelines/temporal ordering (use trace_timeline), entity properties or alerts (use investigate_entity)."""
    args_schema: Type[MapRelationshipsSchema] = MapRelationshipsSchema
    
    def _run(
        self,
        source_type: str,
        source_id: Optional[str] = None,
        relationship_type: str = "entity_to_entity",
        target_type: Optional[str] = None,
        host: Optional[str] = None,
        user: Optional[str] = None,
        timeframe: str = "24h",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for relationship mapping"""
        import asyncio
        return asyncio.run(self._arun(source_type, source_id, relationship_type, target_type, host, user, timeframe, run_manager))

    async def _arun(
        self,
        source_type: str,
        source_id: Optional[str] = None,
        relationship_type: str = "entity_to_entity",
        target_type: Optional[str] = None,
        host: Optional[str] = None,
        user: Optional[str] = None,
        timeframe: str = "24h",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute relationship mapping"""
        try:
            # FIXED: Merge context to preserve timeframe
            _, final_timeframe = self._merge_context_filters(None, timeframe, default_time_range="24h")

            # Build filters dict from individual parameters
            filters = {}
            if host:
                filters["host"] = host
            if user:
                filters["user"] = user

            # Build parameters for the relationship mapping functions
            params = {
                "source_type": source_type,
                "source_id": source_id,
                "target_type": target_type,
                "filters": filters if filters else None,
                "timeframe": final_timeframe
            }
            
            # Remove None values
            params = {k: v for k, v in params.items() if v is not None}
            
            logger.info("Executing relationship mapping", 
                       relationship_type=relationship_type,
                       params=params)
            
            # Handle both string and enum values
            rel_value = relationship_type.value if hasattr(relationship_type, 'value') else relationship_type
            rel_lower = rel_value.lower()
            
            # Route to appropriate relationship mapping function based on relationship_type
            if rel_lower in ["entity_to_entity", "entity", "direct"]:
                from functions.map_relationships.entity_to_entity import execute
                result = await execute(self.opensearch_client, params)

            elif rel_lower in ["behavioral_correlation", "behavioural_correlation", "access_patterns", "access", "patterns", "behavior", "behaviour", "activity_correlation", "correlation", "activity", "activities"]:
                from functions.map_relationships.behavioural_correlation import execute
                result = await execute(self.opensearch_client, params)
                
            else:
                # Default to entity_to_entity for unknown types
                logger.warning("Unknown relationship type, defaulting to entity_to_entity", 
                             relationship_type=relationship_type)
                from functions.map_relationships.entity_to_entity import execute
                result = await execute(self.opensearch_client, params)
            
            logger.info("Relationship mapping completed",
                        source_type=source_type,
                        source_id=source_id,
                        relationship_type=relationship_type,
                        total_results=result.get("relationship_summary", result.get("pattern_summary", result.get("correlation_summary", {}))).get("total_connections",
                                      result.get("relationship_summary", result.get("pattern_summary", result.get("correlation_summary", {}))).get("total_access_events",
                                      result.get("relationship_summary", result.get("pattern_summary", result.get("correlation_summary", {}))).get("total_correlated_activities", 0))))

            return json.dumps(result, default=str)
            
        except Exception as e:
            logger.error("Relationship mapping failed",
                         source_type=source_type,
                         source_id=source_id,
                         error=str(e))
            raise Exception(f"Relationship mapping failed: {str(e)}")


class DetectThreatsTool(WazuhBaseTool):
    """Tool for detecting threats and MITRE ATT&CK techniques"""
    name: str = "detect_threats"
    description: str = "Detect MITRE ATT&CK techniques, tactics, threat actors, IoCs, and attack chains. Use threat_type: 'technique' (with technique_id e.g. T1055), 'tactic' (with tactic_name), 'threat_actor' (with actor_name), 'indicators' (for IoCs), 'chains' (for attack sequences and technique progressions). NOT for single entity alerts (use investigate_entity) or alert statistics (use analyze_alerts)."
    args_schema: Type[DetectThreatsSchema] = DetectThreatsSchema
    
    def _run(
        self,
        threat_type: str,
        technique_id: Optional[str] = None,
        tactic_name: Optional[str] = None,
        actor_name: Optional[str] = None,
        timeframe: str = "7d",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for threat detection"""
        import asyncio
        return asyncio.run(self._arun(threat_type, technique_id, tactic_name, actor_name, timeframe, run_manager))

    async def _arun(
        self,
        threat_type: str,
        technique_id: Optional[str] = None,
        tactic_name: Optional[str] = None,
        actor_name: Optional[str] = None,
        timeframe: str = "7d",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute threat detection"""
        try:
            # FIXED: Merge context to preserve timeframe
            _, final_timeframe = self._merge_context_filters(None, timeframe, default_time_range="7d")

            # Handle both string and enum values
            threat_value = threat_type.value if hasattr(threat_type, 'value') else threat_type

            # Normalize to lowercase for case-insensitive matching
            threat_value_lower = threat_value.lower()

            # Route to specific sub-function based on threat_type
            if threat_value_lower == "technique":
                from functions.detect_threats.find_technique import execute
            elif threat_value_lower == "tactic":
                from functions.detect_threats.find_tactic import execute
            elif threat_value_lower in ["threat_actor", "actor"]:
                from functions.detect_threats.find_threat_actor import execute
            elif threat_value_lower in ["indicators", "iocs", "indicators of compromise"]:
                from functions.detect_threats.find_indicators import execute
            elif threat_value_lower == "chains":
                from functions.detect_threats.find_chains import execute
            else:
                raise ValueError(f"Unknown threat_type: {threat_value}. Supported types: technique, tactic, threat_actor/actor, indicators/ioc, chains")

            # Build parameters
            params = {
                "technique_id": technique_id,
                "tactic_name": tactic_name,
                "actor_name": actor_name,
                "timeframe": final_timeframe
            }
            
            # Execute the detection
            result = await execute(self.opensearch_client, params)
            
            logger.info("Threat detection completed",
                        threat_type=threat_value,
                        total_results=result.get("total_alerts", 0))

            return json.dumps(result, default=str)
            
        except Exception as e:
            logger.error("Threat detection failed",
                         threat_type=threat_type,
                         error=str(e))
            raise Exception(f"Threat detection failed: {str(e)}")


class FindAnomaliesTool(WazuhBaseTool):
    """Tool for finding anomalies in security data using various detection methods"""

    ANOMALY_RESPONSE_INSTRUCTIONS: ClassVar[str] = """[ANOMALY RESPONSE FORMATTING INSTRUCTIONS]
When presenting these anomaly results, you MUST:
1. State threshold source: "Using RCF-learned thresholds from [X-day] baseline (confidence: [Y]%)" or "Using static fallback threshold of [value]"
2. Start with: "Based on [RCF-learned/static fallback] baseline analysis over the last [X] days..."
3. Include baseline confidence score if RCF available
4. For each anomaly: State "X exceeds [RCF-learned/static] threshold Y"
5. Use detection-type terminology:
   - Threshold: "RCF-learned threshold breach" / "sudden burst exceeding baseline"
   - Trend: "Progressive escalation above RCF trend baseline"
   - Behavioral: "Behavioral deviation from RCF entity baseline"
[END FORMATTING INSTRUCTIONS]
"""

    name: str = "find_anomalies"
    description: str = "Detect security anomalies. Types: 'threshold' (numeric limit breaches, violations), 'behavioral' (entity behavior pattern deviations), 'trend' (time-series escalations, directional shifts). All types support RCF baselines. Use 'threshold' whenever query mentions specific numbers, limits, or breach counts, even alongside 'RCF' or 'baseline' keywords."
    args_schema: Type[FindAnomaliesSchema] = FindAnomaliesSchema
    
    def _run(
        self,
        anomaly_type: str,
        metric: Optional[str] = None,
        timeframe: str = "24h",
        threshold: Optional[float] = None,
        baseline: Optional[str] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for anomaly detection"""
        import asyncio
        return asyncio.run(self._arun(anomaly_type, metric, timeframe, threshold, baseline, run_manager))

    async def _arun(
        self,
        anomaly_type: str,
        metric: Optional[str] = None,
        timeframe: str = "24h",
        threshold: Optional[float] = None,
        baseline: Optional[str] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute anomaly detection"""
        try:
            # FIXED: Merge context to preserve timeframe
            _, final_timeframe = self._merge_context_filters(None, timeframe, default_time_range="24h")

            # Build parameters for the anomaly detection function
            params = {
                "metric": metric,
                "timeframe": final_timeframe,
                "baseline": baseline
            }

            # Only include threshold parameter for threshold-based detection
            anomaly_type_lower = anomaly_type.lower()
            if anomaly_type_lower in ["threshold", "thresholds"]:
                params["threshold"] = threshold
            
            # Remove None values
            params = {k: v for k, v in params.items() if v is not None}
            
            logger.info("Executing anomaly detection", 
                       anomaly_type=anomaly_type,
                       params=params)
            
            # Route to appropriate anomaly detection function based on type
            anomaly_type_lower = anomaly_type.lower()
            
            # Handle common variations and map them to correct types
            if anomaly_type_lower in ["threshold", "thresholds"]:
                from functions.find_anomalies.detect_threshold import execute
                result = await execute(self.opensearch_client, params)
                
                
            elif anomaly_type_lower in ["behavioral", "behaviour", "behavior", "user_behavior", "host_behavior", "behavioral_baseline", "baseline_comparison"]:
                from functions.find_anomalies.detect_behavioral import execute
                result = await execute(self.opensearch_client, params)
                
            elif anomaly_type_lower in ["trend", "trend_analysis", "trends", "trending", "time_trend", "temporal_trend"]:
                from functions.find_anomalies.detect_trend import execute
                result = await execute(self.opensearch_client, params)
                
            elif anomaly_type_lower in ["all", "comprehensive"]:
                # For comprehensive analysis, default to behavioral as it provides the most comprehensive view
                logger.info("Comprehensive anomaly request, using behavioral detection", 
                           anomaly_type=anomaly_type)
                from functions.find_anomalies.detect_behavioral import execute
                result = await execute(self.opensearch_client, params)
                
            else:
                # Check for threshold-related keywords first (prioritize explicit threshold mentions)
                if any(keyword in anomaly_type_lower for keyword in
                       ["threshold", "thresholds", "exceeding", "above", "limit", "limits", "over"]):
                    logger.info("Mapping threshold-related query to threshold detection",
                                anomaly_type=anomaly_type)
                    from functions.find_anomalies.detect_threshold import execute
                    result = await execute(self.opensearch_client, params)
                # Then default to behavioral detection for user-focused queries
                elif any(keyword in anomaly_type_lower for keyword in ["user", "host", "entity", "activity"]):
                    logger.info("Mapping user/host/activity query to behavioral detection",
                               anomaly_type=anomaly_type)
                    from functions.find_anomalies.detect_behavioral import execute
                    result = await execute(self.opensearch_client, params)
                else:
                    logger.warning("Unknown anomaly type, defaulting to threshold", 
                                 anomaly_type=anomaly_type)
                    from functions.find_anomalies.detect_threshold import execute
                    result = await execute(self.opensearch_client, params)
            
            logger.info("Anomaly detection completed",
                       anomaly_type=anomaly_type,
                       total_anomalies=result.get("summary", {}).get("total_anomalies", result.get("summary", {}).get("total_threshold_anomalies", result.get("summary", {}).get("total_pattern_anomalies", result.get("summary", {}).get("total_behavioral_anomalies", result.get("summary", {}).get("total_trend_anomalies", 0))))))

            result_json = json.dumps(result, default=str)
            return f"{self.ANOMALY_RESPONSE_INSTRUCTIONS}\n{result_json}"
            
        except Exception as e:
            logger.error("Anomaly detection failed", 
                        anomaly_type=anomaly_type, 
                        error=str(e))
            raise Exception(f"Anomaly detection failed: {str(e)}")


class TraceTimelineTool(WazuhBaseTool):
    """Tool for reconstructing event timelines"""
    name: str = "trace_timeline"
    description: str = "Reconstruct chronological timelines of when security events occurred. View types: 'sequence' (chronological), 'progression' (attack evolution), 'temporal' (simultaneous events). Use for 'what happened when?', 'trace event sequence', 'attack timeline'. NOT for who/what relationships between entities (use map_relationships) or entity details (use investigate_entity)."
    args_schema: Type[TraceTimelineSchema] = TraceTimelineSchema
    
    def _run(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        view_type: str = "progression",
        entity: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for timeline reconstruction"""
        import asyncio
        return asyncio.run(self._arun(start_time, end_time, view_type, entity, event_types, run_manager))

    async def _arun(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        view_type: str = "progression",
        entity: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute timeline reconstruction"""
        try:
            # FIXED: Apply context to timeline queries
            # Convert suggested_time_range to start_time/end_time if available
            if self.agent and hasattr(self.agent, '_current_context_result'):
                context_result = self.agent._current_context_result
                if context_result and context_result.get("context_applied"):
                    suggested_time_range = context_result.get("suggested_time_range")

                    # If context has time range and LLM is using defaults, override
                    if suggested_time_range and (start_time is None or start_time == "now-7d"):
                        start_time = f"now-{suggested_time_range}"
                        end_time = "now"
                        logger.info("Overriding timeline with context time range",
                                   suggested=suggested_time_range,
                                   start_time=start_time)

            # Set default time range if not provided
            if start_time is None:
                start_time = "now-7d"  # Default to 7 days ago
            if end_time is None:
                end_time = "now"  # Default to current time
            
            # Build parameters for the timeline function
            params = {
                "start_time": start_time,
                "end_time": end_time,
                "entity": entity,
                "event_types": event_types
            }
            
            # Remove None values
            params = {k: v for k, v in params.items() if v is not None}
            
            logger.info("Executing timeline reconstruction", 
                       view_type=view_type,
                       params=params)
            
            # Handle both string and enum values
            view_value = view_type.value if hasattr(view_type, 'value') else view_type
            view_lower = view_value.lower()
            
            # Route to appropriate timeline function based on view_type
            if view_lower in ["sequence", "show_sequence", "detailed", "chronological"]:
                from functions.trace_timeline.show_sequence import execute
                result = await execute(self.opensearch_client, params)
                
            elif view_lower in ["progression", "trace_progression", "evolution", "develop"]:
                from functions.trace_timeline.trace_progression import execute
                result = await execute(self.opensearch_client, params)
                
            elif view_lower in ["temporal", "correlate_temporal", "correlation", "related"]:
                from functions.trace_timeline.correlate_temporal import execute
                result = await execute(self.opensearch_client, params)
                
            else:
                # Default to sequence view for unknown types
                logger.warning("Unknown view type, defaulting to sequence", 
                             view_type=view_type)
                from functions.trace_timeline.show_sequence import execute
                result = await execute(self.opensearch_client, params)
            
            logger.info("Timeline reconstruction completed",
                       view_type=view_type,
                       start_time=start_time,
                       end_time=end_time,
                       total_events=result.get("timeline_summary", result.get("progression_summary", result.get("correlation_summary", {}))).get("total_events", 0))

            return json.dumps(result, default=str)
            
        except Exception as e:
            logger.error("Timeline reconstruction failed", 
                        start_time=start_time, 
                        end_time=end_time, 
                        view_type=view_type,
                        error=str(e))
            raise Exception(f"Timeline reconstruction failed: {str(e)}")


class CheckVulnerabilitiesTool(WazuhBaseTool):
    """Tool for checking vulnerabilities using various analysis methods"""
    name: str = "check_vulnerabilities"
    description: str = "Check vulnerabilities using different actions: 'list_by_entity' (list vulnerabilities by host/entity), 'check_cve' (analyze specific CVE references), 'check_patches' (check patch status and Windows updates)"
    args_schema: Type[CheckVulnerabilitiesSchema] = CheckVulnerabilitiesSchema
    
    def _run(
        self,
        action: str,
        entity_filter: Optional[str] = None,
        cve_id: Optional[str] = None,
        severity: Optional[str] = None,
        patch_status: Optional[str] = None,
        timeframe: str = "30d",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for vulnerability checking"""
        import asyncio
        return asyncio.run(self._arun(action, entity_filter, cve_id, severity, patch_status, timeframe, run_manager))

    async def _arun(
        self,
        action: str,
        entity_filter: Optional[str] = None,
        cve_id: Optional[str] = None,
        severity: Optional[str] = None,
        patch_status: Optional[str] = None,
        timeframe: str = "30d",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute vulnerability checking"""
        try:
            # FIXED: Merge context to preserve timeframe
            _, final_timeframe = self._merge_context_filters(None, timeframe, default_time_range="30d")

            # Build parameters for the vulnerability checking function
            params = {
                "entity_filter": entity_filter,
                "cve_id": cve_id,
                "severity": severity,
                "patch_status": patch_status,
                "timeframe": final_timeframe
            }
            
            # Remove None values
            params = {k: v for k, v in params.items() if v is not None}
            
            logger.info("Executing vulnerability checking", 
                       action=action,
                       params=params)
            
            # Handle both string and enum values
            action_value = action.value if hasattr(action, 'value') else action
            action_lower = action_value.lower()
            
            # Route to appropriate vulnerability checking function based on action
            if action_lower == "list_by_entity":
                from functions.check_vulnerabilities.list_by_entity import execute
                result = await execute(self.opensearch_client, params)
                
            elif action_lower == "check_cve":
                from functions.check_vulnerabilities.check_cve import execute
                result = await execute(self.opensearch_client, params)
                
            elif action_lower == "check_patches":
                from functions.check_vulnerabilities.check_patches import execute
                result = await execute(self.opensearch_client, params)
                
            else:
                # Default to list_by_entity for unknown actions
                logger.warning("Unknown vulnerability action, defaulting to list_by_entity", 
                             action=action)
                from functions.check_vulnerabilities.list_by_entity import execute
                result = await execute(self.opensearch_client, params)
            
            logger.info("Vulnerability checking completed",
                       action=action,
                       total_results=result.get("total_vulnerability_alerts", result.get("total_cve_alerts", result.get("total_patch_events", 0))))

            return json.dumps(result, default=str)
            
        except Exception as e:
            logger.error("Vulnerability checking failed", 
                        action=action,
                        error=str(e))
            raise Exception(f"Vulnerability checking failed: {str(e)}")


class MonitorAgentsTool(WazuhBaseTool):
    """Tool for monitoring Wazuh agents using various analysis methods"""
    name: str = "monitor_agents"
    description: str = "Monitor Wazuh agents and retrieve agent information including OS version, agent version, connectivity status, and health metrics. Use this for queries about specific agents by ID, name, or IP address. Actions: 'status_check' (connectivity and operational status), 'version_check' (agent and OS version information), 'health_check' (comprehensive health analysis)"
    args_schema: Type[MonitorAgentsSchema] = MonitorAgentsSchema
    
    def _run(
        self,
        action: str,
        agent_id: Optional[str] = None,
        status_filter: Optional[str] = None,
        version_requirements: Optional[str] = None,
        timeframe: str = "24h",
        health_threshold: float = 70.0,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for agent monitoring"""
        import asyncio
        return asyncio.run(self._arun(action, agent_id, status_filter, version_requirements, timeframe, health_threshold, run_manager))

    async def _arun(
        self,
        action: str,
        agent_id: Optional[str] = None,
        status_filter: Optional[str] = None,
        version_requirements: Optional[str] = None,
        timeframe: str = "24h",
        health_threshold: float = 70.0,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute agent monitoring"""
        try:
            # FIXED: Merge context to preserve timeframe
            _, final_timeframe = self._merge_context_filters(None, timeframe, default_time_range="24h")

            # Build parameters for the monitoring function
            params = {
                "agent_id": agent_id,
                "status_filter": status_filter,
                "version_requirements": version_requirements,
                "timeframe": final_timeframe,
                "health_threshold": health_threshold
            }
            
            # Remove None values
            params = {k: v for k, v in params.items() if v is not None}
            
            logger.info("Executing agent monitoring", 
                       action=action,
                       params=params)
            
            # Handle both string and enum values
            action_value = action.value if hasattr(action, 'value') else action
            action_lower = action_value.lower()
            
            # Route to appropriate monitoring function based on action
            if action_lower == "status_check":
                from functions.monitor_agents.status_check import execute
                result = await execute(self.opensearch_client, params)
                
            elif action_lower == "version_check":
                from functions.monitor_agents.version_check import execute
                result = await execute(self.opensearch_client, params)
                
            elif action_lower == "health_check":
                from functions.monitor_agents.health_check import execute
                result = await execute(self.opensearch_client, params)
                
            else:
                # Default to status_check for unknown actions
                logger.warning("Unknown monitoring action, defaulting to status_check", 
                             action=action)
                from functions.monitor_agents.status_check import execute
                result = await execute(self.opensearch_client, params)
            
            logger.info("Agent monitoring completed",
                       action=action,
                       total_agents=result.get("agent_summary", result.get("version_summary", result.get("health_summary", {}))).get("total_agents", 0))

            return json.dumps(result, default=str)
            
        except Exception as e:
            logger.error("Agent monitoring failed", 
                        action=action,
                        error=str(e))
            raise Exception(f"Agent monitoring failed: {str(e)}")


def get_all_tools(opensearch_client, agent=None):
    """
    Get all available Wazuh tools

    Args:
        opensearch_client: OpenSearch client instance
        agent: Optional agent reference for context merging

    Returns:
        List of all tool instances
    """
    return [
        AnalyzeAlertsTool(opensearch_client, agent),
        InvestigateEntityTool(opensearch_client, agent),
        MapRelationshipsTool(opensearch_client, agent),
        DetectThreatsTool(opensearch_client, agent),
        FindAnomaliesTool(opensearch_client, agent),
        TraceTimelineTool(opensearch_client, agent),
        CheckVulnerabilitiesTool(opensearch_client, agent),
        MonitorAgentsTool(opensearch_client, agent)
    ]
