"""
Rank alerts by specified criteria
"""
from typing import Dict, Any
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient, normalize_wazuh_array_fields

logger = structlog.get_logger()

def get_field_mapping() -> Dict[str, str]:
    """Get field mapping for user-friendly field names"""
    return {
        "severity": "rule.level",
        "host": "agent.name",
        "hosts": "agent.name",
        "rule": "rule.id",
        "rules": "rule.id",
        "rule_id": "rule.id",
        "rule_description": "rule.description",
        "description": "rule.description",
        "user": "data.win.eventdata.user",
        "users": "data.win.eventdata.user",
        "target_user": "data.win.eventdata.targetUserName",
        "time": "@timestamp",
        "temporal": "@timestamp",
        "rule_groups": "rule.groups",
        "groups": "rule.groups",
        "rule_group": "rule.groups",
        "geographic": "agent.ip",
        "geo": "agent.ip",
        "location": "agent.ip",
        "locations": "agent.ip",
        "ip": "agent.ip",
        "process": "data.win.eventdata.originalFileName",
        "processes": "data.win.eventdata.originalFileName",
        "process_name": "data.win.eventdata.originalFileName",
        "command": "data.win.eventdata.commandLine",
        "command_line": "data.win.eventdata.commandLine",
        "parent_command": "data.win.eventdata.parentCommandLine",
        "parent_command_line": "data.win.eventdata.parentCommandLine",
        "image": "data.win.eventdata.image",
        "process_image": "data.win.eventdata.image",
        "executable": "data.win.eventdata.image",
        "process_id": "data.win.eventdata.processId",
        "pid": "data.win.eventdata.processId",
        "parent_process_id": "data.win.eventdata.parentProcessId",
        "parent_pid": "data.win.eventdata.parentProcessId",
        "integrity_level": "data.win.eventdata.integrityLevel",
        "logon_id": "data.win.eventdata.logonId"
    }

async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Rank alerts by specified criteria (e.g., top alerting hosts, users, rules)
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including group_by, filters, limit, time_range
        
    Returns:
        Ranked results with counts and latest alert details
    """
    try:
        # Extraction and Normalization of Parameters ---
        raw_group_by = params.get("group_by") or "agent.name"
        field_mapping = get_field_mapping()
        group_by = field_mapping.get(raw_group_by.lower(), raw_group_by) if isinstance(raw_group_by, str) else raw_group_by
        limit = params.get("limit", 10)
        time_range = params.get("time_range", "7d")
        filters = params.get("filters", {}) or {}

        # Apply field mapping to filters
        mapped_filters = {}
        for key, value in filters.items():
            mapped_key = field_mapping.get(key, key)
            mapped_filters[mapped_key] = value
        filters = mapped_filters

        # Handle intelligent process and rule filtering
        process_fields = ["data.win.eventdata.originalFileName", "data.win.eventdata.image"]
        for field in process_fields:
            if field in filters and isinstance(filters[field], str):
                val = filters[field]
                if not val.endswith('.exe') and '\\' not in val and '/' not in val:
                    filters[field] = val + '.exe'

        if "rule.id" in filters and isinstance(filters["rule.id"], str):
            if not filters["rule.id"].isdigit():
                filters["rule.description"] = filters.pop("rule.id")

        filters = normalize_wazuh_array_fields(filters)
        
        # Handle time parameters from LLM
        time_start = filters.pop("time_start", None)
        time_end = filters.pop("time_end", None)
        if time_start and time_end:
            time_range = f"{time_start} until {time_end}"
        
        filter_time_range = filters.pop("time_range", None)
        if filter_time_range:
            time_range = filter_time_range

        logger.info("Ranking alerts", group_by=group_by, limit=limit, time_range=time_range)
        
        # ---  Build OpenSearch Query ---
        query = {
            "query": {
                "bool": {
                    "must": [
                        opensearch_client.build_single_time_filter(time_range)
                    ]
                }
            },
            "aggs": {
                "total_count": {
                    "value_count": {
                        "field": "_id"
                    }
                },
                "ranked_entities": {
                    "terms": {
                        "field": group_by,
                        "size": limit,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "latest_alert": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"@timestamp": {"order": "desc"}}],
                                "_source": [
                                    "rule.description", "rule.level", "rule.id", 
                                    "rule.groups", "@timestamp", "data.srcip", "data.srcuser",
                                    "data.win.eventdata" # Added to ensure win data is retrieved
                                ]
                            }
                        },
                        "severity_breakdown": {
                            "terms": {
                                "field": "rule.level",
                                "size": 10
                            }
                        }
                    }
                }
            }
        }
        
        if filters:
            query["query"]["bool"]["must"].extend(opensearch_client.build_filters_query(filters))
        
        # ---  Execute Query and Handle Response Safely ---
        response = await opensearch_client.search(
            opensearch_client.alerts_index, 
            query, 
            size=0
        )
        
        # Check if 'aggregations' exists (Prevent KeyError)
        if "aggregations" not in response:
            logger.error("OpenSearch response missing aggregations", response=response)
            return {
                "total_alerts": 0,
                "time_range": time_range,
                "grouped_by": group_by,
                "ranked_entities": [],
                "error": response.get("error", "No aggregations returned from OpenSearch")
            }

        # --- Format Results with Protective Access ---
        aggs = response["aggregations"]
        total_alerts = aggs.get("total_count", {}).get("value", 0)
        
        ranked_results = []
        buckets = aggs.get("ranked_entities", {}).get("buckets", [])
        
        for bucket in buckets:
            entity_data = {
                "entity": bucket["key"],
                "alert_count": bucket["doc_count"],
                "latest_alert": None,
                "severity_breakdown": {}
            }
            
            # Safe extraction of Top Hits
            latest_hits = bucket.get("latest_alert", {}).get("hits", {}).get("hits", [])
            if latest_hits:
                latest = latest_hits[0].get("_source", {})
                win_eventdata = latest.get("data", {}).get("win", {}).get("eventdata", {})

                entity_data["latest_alert"] = {
                    "rule_description": latest.get("rule", {}).get("description", ""),
                    "rule_level": latest.get("rule", {}).get("level", 0),
                    "rule_id": latest.get("rule", {}).get("id", ""),
                    "rule_groups": latest.get("rule", {}).get("groups", []),
                    "timestamp": latest.get("@timestamp", ""),
                    "source_ip": latest.get("data", {}).get("srcip", ""),
                    "source_user": latest.get("data", {}).get("srcuser", ""),
                    "process_name": win_eventdata.get("originalFileName", win_eventdata.get("processName", "")),
                    "process_image": win_eventdata.get("image", ""),
                    "command_line": win_eventdata.get("commandLine", ""),
                    "target_user": win_eventdata.get("targetUserName", ""),
                    "target_filename": win_eventdata.get("targetFilename", "")
                }
            
            # Safe extraction of Severity Breakdown
            sev_buckets = bucket.get("severity_breakdown", {}).get("buckets", [])
            for sev_bucket in sev_buckets:
                entity_data["severity_breakdown"][str(sev_bucket["key"])] = sev_bucket["doc_count"]
            
            ranked_results.append(entity_data)
        
        result = {
            "total_alerts": total_alerts,
            "time_range": time_range,
            "grouped_by": group_by,
            "ranked_entities": ranked_results,
            "query_info": {
                "filters_applied": bool(filters),
                "result_count": len(ranked_results)
            }
        }
        
        logger.info("Alert ranking completed", total_alerts=total_alerts, entities_found=len(ranked_results))
        return result
        
    except Exception as e:
        logger.error("Alert ranking failed", error=str(e), params=params)
        # We still raise or return a structured error
        return {
            "error": True,
            "error_message": f"Critical failure in ranking alerts: {str(e)}",
            "total_alerts": 0,
            "ranked_entities": []
        }

def get_severity_name(level: int) -> str:
    """
    Convert Wazuh alert level to severity name
    
    Args:
        level: Alert level number
        
    Returns:
        Severity name string
    """
    if level >= 12:
        return "Critical"
    elif level >= 8:
        return "High"
    elif level >= 5:
        return "Medium"
    elif level >= 3:
        return "Low"
    else:
        return "Informational"