"""
Count alerts with optional filters
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
        "description": "rule.description",  # Add missing mapping
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
    Count alerts matching specified criteria
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including filters, time_range
        
    Returns:
        Count results with breakdown by severity, rules, etc.
    """
    try:
        # Extract parameters
        time_range = params.get("time_range", "7d")
        filters = params.get("filters", {})

        # Handle case where filters is None
        if filters is None:
            filters = {}

        # Apply field mapping to convert user-friendly names to Wazuh field names
        field_mapping = get_field_mapping()
        mapped_filters = {}
        for key, value in filters.items():
            mapped_key = field_mapping.get(key, key)  # Use mapping if available, otherwise keep original
            mapped_filters[mapped_key] = value
        filters = mapped_filters

        # Convert string values to arrays for known Wazuh array fields
        filters = normalize_wazuh_array_fields(filters)
        
        # Handle separate time_start and time_end parameters from LLM
        time_start = filters.pop("time_start", None)
        time_end = filters.pop("time_end", None)
        
        # If we have separate start/end times, construct a time range
        if time_start and time_end:
            from datetime import date
            today = date.today().strftime("%Y-%m-%d")
            time_range = f"{time_start} until {time_end}"
            logger.info("Converting separate time parameters to range", 
                       time_start=time_start, time_end=time_end, time_range=time_range)
        
        # Handle time_range in filters (LLM sometimes puts it there instead of main params)
        filter_time_range = filters.pop("time_range", None)
        if filter_time_range:
            time_range = filter_time_range
            logger.info("Using time_range from filters", time_range=time_range)
        
        logger.info("Counting alerts", 
                   time_range=time_range, 
                   filters=filters)
        
        # Build base query
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
                "severity_counts": {
                    "terms": {
                        "field": "rule.level",
                        "size": 20,
                        "order": {"_key": "desc"}
                    }
                },
                "rule_counts": {
                    "terms": {
                        "field": "rule.id",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                },
                "hourly_distribution": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "format": "yyyy-MM-dd HH:mm"
                    }
                },
                "agent_counts": {
                    "terms": {
                        "field": "agent.name",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                },
                "process_counts": {
                    "terms": {
                        "field": "data.win.eventdata.originalFileName",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                },
                "user_counts": {
                    "terms": {
                        "field": "data.win.eventdata.user",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                },
                "integrity_level_counts": {
                    "terms": {
                        "field": "data.win.eventdata.integrityLevel",
                        "size": 5,
                        "order": {"_count": "desc"}
                    }
                },
                "mitre_technique_counts": {
                    "terms": {
                        "field": "rule.mitre.id",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                }
            }
        }
        
        # Add filters if provided
        if filters:
            filter_queries = opensearch_client.build_filters_query(filters)
            query["query"]["bool"]["must"].extend(filter_queries)
            logger.info("Applied filters to query", 
                       filters=filters, 
                       filter_queries=filter_queries)
        
        # Log the complete query for debugging
        logger.info("Executing OpenSearch query", 
                   index=opensearch_client.alerts_index,
                   query=query)
        
        # Execute query
        response = await opensearch_client.search(
            opensearch_client.alerts_index, 
            query, 
            size=0  # We only want aggregations
        )
        
        # Log the response for debugging
        logger.info("OpenSearch query response", 
                   total_hits=response.get("hits", {}).get("total", 0),
                   aggregations_keys=list(response.get("aggregations", {}).keys()) if response.get("aggregations") else [])
        
        # Format results
        total_alerts = response["aggregations"]["total_count"]["value"]
        
        # Process severity breakdown
        severity_breakdown = {}
        for bucket in response["aggregations"]["severity_counts"]["buckets"]:
            level = bucket["key"]
            count = bucket["doc_count"]
            severity_breakdown[str(level)] = {
                "count": count,
                "severity_name": get_severity_name(level)
            }
        
        # Process top rules
        top_rules = []
        for bucket in response["aggregations"]["rule_counts"]["buckets"]:
            rule_data = {
                "rule_id": bucket["key"],
                "count": bucket["doc_count"]
            }
            top_rules.append(rule_data)
        
        # Process hourly distribution
        hourly_distribution = []
        for bucket in response["aggregations"]["hourly_distribution"]["buckets"]:
            hourly_distribution.append({
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })
        
        # Process top agents
        top_agents = []
        for bucket in response["aggregations"]["agent_counts"]["buckets"]:
            top_agents.append({
                "agent_name": bucket["key"],
                "count": bucket["doc_count"]
            })

        # Process top processes
        top_processes = []
        for bucket in response["aggregations"]["process_counts"]["buckets"]:
            if bucket["key"]:  # Skip empty process names
                top_processes.append({
                    "process_name": bucket["key"],
                    "count": bucket["doc_count"]
                })

        # Process top users
        top_users = []
        for bucket in response["aggregations"]["user_counts"]["buckets"]:
            if bucket["key"]:  # Skip empty usernames
                top_users.append({
                    "username": bucket["key"],
                    "count": bucket["doc_count"]
                })

        # Process integrity level breakdown
        integrity_level_breakdown = {}
        for bucket in response["aggregations"]["integrity_level_counts"]["buckets"]:
            if bucket["key"]:  # Skip empty integrity levels
                integrity_level_breakdown[bucket["key"]] = bucket["doc_count"]

        # Process MITRE technique breakdown
        mitre_techniques = []
        for bucket in response["aggregations"]["mitre_technique_counts"]["buckets"]:
            if bucket["key"]:  # Skip empty techniques
                mitre_techniques.append({
                    "technique_id": bucket["key"],
                    "count": bucket["doc_count"]
                })

        result = {
            "total_count": total_alerts,
            "time_range": time_range,
            "severity_breakdown": severity_breakdown,
            "top_rules": top_rules,
            "hourly_distribution": hourly_distribution,
            "top_agents": top_agents,
            "top_processes": top_processes,
            "top_users": top_users,
            "integrity_level_breakdown": integrity_level_breakdown,
            "mitre_techniques": mitre_techniques,
            "query_info": {
                "filters_applied": bool(filters),
                "filters": filters
            }
        }
        
        logger.info("Alert counting completed", 
                   total_count=total_alerts,
                   time_range=time_range)
        
        return result
        
    except Exception as e:
        logger.error("Alert counting failed", 
                    error=str(e), 
                    params=params)
        raise Exception(f"Failed to count alerts: {str(e)}")

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