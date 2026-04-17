"""
Get alerts for a specific entity (host, user, process, file)
"""
from typing import Dict, Any
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient

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
        "user": "data.win.eventdata.user",
        "users": "data.win.eventdata.user",
        "target_user": "data.win.eventdata.targetUserName",
        "time": "@timestamp",
        "temporal": "@timestamp",
        "rule_groups": "rule.groups",
        "groups": "rule.groups",
        "rule_group": "rule.groups",
        "process": "data.win.eventdata.originalFileName",
        "processes": "data.win.eventdata.originalFileName",
        "process_name": "data.win.eventdata.originalFileName",
        "command": "data.win.eventdata.commandLine",
        "command_line": "data.win.eventdata.commandLine"
    }

async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get alerts associated with a specific entity with optional filtering

    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including entity_type, entity_id, time_range, filters

    Returns:
        Alerts for the specified entity with details and statistics
    """
    try:
        # Extract parameters
        entity_type = params.get("entity_type", "host")
        entity_id = params.get("entity_id")
        time_range = params.get("time_range", "24h")
        filters = params.get("filters", {})

        if not entity_id:
            raise ValueError("entity_id is required")

        # Handle case where filters is None FIRST
        if filters is None:
            filters = {}

        # Apply field mapping to convert user-friendly names to Wazuh field names
        field_mapping = get_field_mapping()
        mapped_filters = {}
        for key, value in filters.items():
            mapped_key = field_mapping.get(key, key)  # Use mapping if available, otherwise keep original
            mapped_filters[mapped_key] = value
        filters = mapped_filters

        # ENHANCED PROCESS DETECTION - Handle process queries dynamically
        process_search_terms = []

        # Collect all potential process-related search terms
        for key, value in list(filters.items()):
            if isinstance(value, str):
                # Detect process-related searches in any field
                if any(keyword in key.lower() for keyword in ['process', 'executable', 'image', 'command']):
                    process_search_terms.append(value)
                # Also detect rule searches that might be process names
                elif key in ['rule.id', 'rule.description'] and not value.isdigit():
                    # Check if it looks like a process name
                    if any(proc in value.lower() for proc in ['powershell', 'chrome', 'cmd', 'notepad', 'explorer', 'svchost', 'winlogon', '.exe']):
                        process_search_terms.append(value)
                        # Remove from rule search since we'll handle it as process
                        del filters[key]
                        logger.info("Detected process name in rule field, converting to process search",
                                   original_field=key, process_term=value)

        # If we found process terms, normalize them
        if process_search_terms:
            logger.info("Detected process search terms", terms=process_search_terms)
            # Remove existing process filters to replace with normalized version
            process_fields = ["data.win.eventdata.originalFileName", "data.win.eventdata.image"]
            for field in process_fields:
                if field in filters:
                    del filters[field]

            # Normalize the first process term
            for search_term in process_search_terms:
                normalized_term = search_term.lower().strip()
                # Auto-append .exe if not present and not a full path
                if not normalized_term.endswith('.exe') and '\\' not in normalized_term and '/' not in normalized_term:
                    exe_term = normalized_term + '.exe'
                else:
                    exe_term = normalized_term

                logger.info("Creating process search for entity investigation",
                           original=search_term, normalized=exe_term)
                filters["data.win.eventdata.originalFileName"] = exe_term
                break
        
        logger.info("Getting alerts for entity",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    time_range=time_range,
                    filters=filters)

        # Build entity query
        entity_query = opensearch_client.build_entity_query(entity_type, entity_id)

        # Build main query with entity and time filters
        query = {
            "query": {
                "bool": {
                    "must": [
                        opensearch_client.build_single_time_filter(time_range),
                        entity_query
                    ]
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ],
            "aggs": {
                "total_count": {
                    "value_count": {
                        "field": "_id"
                    }
                },
                "severity_distribution": {
                    "terms": {
                        "field": "rule.level",
                        "size": 20
                    }
                },
                "rule_distribution": {
                    "terms": {
                        "field": "rule.id",
                        "size": 10
                    },
                    "aggs": {
                        "rule_details": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["rule.description", "rule.level", "rule.groups"]
                            }
                        }
                    }
                },
                "timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "format": "yyyy-MM-dd HH:mm"
                    }
                }
            }
        }

        # Add additional filters if provided (severity, rule filters, etc.)
        if filters:
            filter_queries = opensearch_client.build_filters_query(filters)
            query["query"]["bool"]["must"].extend(filter_queries)
            logger.info("Applied additional filters to entity query",
                       filters=filters,
                       filter_queries=filter_queries)

        # ENHANCED: If we detected process search terms, add comprehensive process search
        if process_search_terms:
            for search_term in process_search_terms:
                normalized_term = search_term.lower().strip()
                if not normalized_term.endswith('.exe') and '\\' not in normalized_term and '/' not in normalized_term:
                    exe_term = normalized_term + '.exe'
                else:
                    exe_term = normalized_term

                # Create comprehensive process search across multiple fields
                process_query = {
                    "bool": {
                        "should": [
                            {"wildcard": {"data.win.eventdata.originalFileName": f"*{exe_term}*"}},
                            {"wildcard": {"data.win.eventdata.image": f"*{exe_term}*"}},
                            {"wildcard": {"data.win.eventdata.commandLine": f"*{exe_term}*"}},
                            {"wildcard": {"rule.description": f"*{normalized_term}*"}},
                            {"wildcard": {"rule.description": f"*{exe_term}*"}}
                        ],
                        "minimum_should_match": 1
                    }
                }
                query["query"]["bool"]["must"].append(process_query)
                logger.info("Added comprehensive process search to entity query",
                           search_term=search_term, normalized=exe_term)
                break

        # Execute query
        response = await opensearch_client.search(
            opensearch_client.alerts_index, 
            query, 
            size=50  # Return up to 50 recent alerts
        )
        
        # Format results
        total_alerts = response["aggregations"]["total_count"]["value"]
        
        # Process alerts
        alerts = []
        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            # Extract Windows event data for detailed process information
            win_eventdata = source.get("data", {}).get("win", {}).get("eventdata", {})

            alert = {
                "timestamp": source.get("@timestamp", ""),
                "rule_id": source.get("rule", {}).get("id", ""),
                "rule_description": source.get("rule", {}).get("description", ""),
                "rule_level": source.get("rule", {}).get("level", 0),
                "rule_groups": source.get("rule", {}).get("groups", []),
                "agent_name": source.get("agent", {}).get("name", ""),
                "source_ip": source.get("data", {}).get("srcip", ""),
                "source_user": source.get("data", {}).get("srcuser", ""),
                "destination_ip": source.get("data", {}).get("dstip", ""),
                # Process information with proper field extraction
                "process_name": win_eventdata.get("originalFileName", win_eventdata.get("processName", "")),
                "process_image": win_eventdata.get("image", ""),
                "command_line": win_eventdata.get("commandLine", ""),
                "parent_command_line": win_eventdata.get("parentCommandLine", ""),
                "process_id": win_eventdata.get("processId", ""),
                "target_user": win_eventdata.get("targetUserName", ""),
                "target_filename": win_eventdata.get("targetFilename", ""),
                "file_name": source.get("data", {}).get("file", {}).get("name", ""),
                "full_log": source.get("full_log", "")
            }
            alerts.append(alert)
        
        # Process severity distribution
        severity_stats = {}
        for bucket in response["aggregations"]["severity_distribution"]["buckets"]:
            level = bucket["key"]
            severity_stats[str(level)] = {
                "count": bucket["doc_count"],
                "severity_name": get_severity_name(level)
            }
        
        # Process rule distribution
        rule_stats = []
        for bucket in response["aggregations"]["rule_distribution"]["buckets"]:
            rule_data = {
                "rule_id": bucket["key"],
                "count": bucket["doc_count"]
            }
            
            # Get rule details
            if bucket["rule_details"]["hits"]["hits"]:
                rule_source = bucket["rule_details"]["hits"]["hits"][0]["_source"]
                rule_data["description"] = rule_source.get("rule", {}).get("description", "")
                rule_data["level"] = rule_source.get("rule", {}).get("level", 0)
                rule_data["groups"] = rule_source.get("rule", {}).get("groups", [])
            
            rule_stats.append(rule_data)
        
        # Process timeline
        timeline = []
        for bucket in response["aggregations"]["timeline"]["buckets"]:
            timeline.append({
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })
        
        result = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "time_range": time_range,
            "total_alerts": total_alerts,
            "alerts": alerts,
            "severity_distribution": severity_stats,
            "top_rules": rule_stats,
            "timeline": timeline,
            "summary": {
                "most_common_rule": rule_stats[0] if rule_stats else None,
                "highest_severity": max([int(k) for k in severity_stats.keys()]) if severity_stats else 0,
                "alert_frequency": total_alerts / max(1, len(timeline)) if timeline else 0
            }
        }
        
        logger.info("Entity alert investigation completed",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    total_alerts=total_alerts)
        
        return result
        
    except Exception as e:
        logger.error("Entity alert investigation failed",
                     error=str(e),
                     params=params)
        raise Exception(f"Failed to get alerts for entity: {str(e)}")


def get_severity_name(level: int) -> str:
    """Convert Wazuh alert level to severity name"""
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
