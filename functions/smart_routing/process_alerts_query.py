"""
Smart query router for process-based alert queries.
Handles common patterns like "Find [process] alerts on [host] for [time]" efficiently.
"""

import structlog
import re
from typing import Dict, Any, Optional
from functions._shared.opensearch_client import WazuhOpenSearchClient

logger = structlog.get_logger()


async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Smart router for process-based alert queries that bypasses ReAct iterations.

    Handles patterns like:
    - "Find all powershell.exe alerts on win-3 over the last 12 hours"
    - "Show chrome.exe alerts on host-01 for the past 24h"
    - "Get net.exe alerts from server-02 in the last 6 hours"

    Args:
        opensearch_client: OpenSearch client instance
        params: Query parameters including:
            - process_name: Process executable name (e.g., "powershell.exe")
            - host: Target host/agent name
            - time_range: Time range (e.g., "12h", "24h", "6h")
            - limit: Maximum results (default: 50)

    Returns:
        Comprehensive alert analysis for the specified process on the target host
    """

    process_name = params.get("process_name", "").strip()
    host = params.get("host", "").strip()
    time_range = params.get("time_range", "24h")
    limit = params.get("limit", 50)

    logger.info("Smart process alerts query initiated",
               process=process_name, host=host, time_range=time_range, limit=limit)

    if not process_name:
        return {"error": "process_name parameter is required"}

    if not host:
        return {"error": "host parameter is required"}

    # Build comprehensive query using enhanced process filtering
    query = {
        "query": {
            "bool": {
                "must": [
                    opensearch_client.build_single_time_filter(time_range)
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "aggs": {
            "total_count": {
                "value_count": {"field": "_id"}
            },
            "severity_summary": {
                "terms": {
                    "field": "rule.level",
                    "size": 10,
                    "order": {"_key": "desc"}
                }
            },
            "rule_summary": {
                "terms": {
                    "field": "rule.id",
                    "size": 10,
                    "order": {"_count": "desc"}
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
            "time_distribution": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h",
                    "format": "yyyy-MM-dd HH:mm"
                }
            }
        }
    }

    # Use enhanced process and host filtering
    filters = {
        "process_name": process_name,
        "host": host
    }

    filter_queries = opensearch_client.build_filters_query(filters)
    query["query"]["bool"]["must"].extend(filter_queries)

    try:
        # Execute the optimized query
        response = await opensearch_client.search(
            opensearch_client.alerts_index,
            query,
            size=limit
        )

        # Process results
        total_alerts = response["aggregations"]["total_count"]["value"]
        hits = response.get("hits", {}).get("hits", [])

        # Process severity summary
        severity_summary = {}
        for bucket in response["aggregations"]["severity_summary"]["buckets"]:
            level = bucket["key"]
            count = bucket["doc_count"]
            severity_name = _get_severity_name(level)
            severity_summary[severity_name] = {
                "level": level,
                "count": count
            }

        # Process rule summary
        top_rules = []
        for bucket in response["aggregations"]["rule_summary"]["buckets"]:
            rule_id = bucket["key"]
            count = bucket["doc_count"]
            rule_details = bucket["rule_details"]["hits"]["hits"][0]["_source"]

            top_rules.append({
                "rule_id": rule_id,
                "count": count,
                "description": rule_details.get("rule", {}).get("description", ""),
                "level": rule_details.get("rule", {}).get("level", 0),
                "groups": rule_details.get("rule", {}).get("groups", [])
            })

        # Process time distribution
        time_distribution = []
        for bucket in response["aggregations"]["time_distribution"]["buckets"]:
            time_distribution.append({
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })

        # Extract sample alerts
        sample_alerts = []
        for hit in hits[:10]:  # Top 10 recent alerts
            source = hit["_source"]
            win_eventdata = source.get("data", {}).get("win", {}).get("eventdata", {})

            sample_alerts.append({
                "timestamp": source.get("@timestamp", ""),
                "rule_id": source.get("rule", {}).get("id", ""),
                "rule_description": source.get("rule", {}).get("description", ""),
                "rule_level": source.get("rule", {}).get("level", 0),
                "host": source.get("agent", {}).get("name", ""),
                "process_image": win_eventdata.get("image", ""),
                "process_name": win_eventdata.get("originalFileName", ""),
                "command_line": win_eventdata.get("commandLine", ""),
                "user": win_eventdata.get("user", ""),
                "process_id": win_eventdata.get("processId", "")
            })

        # Determine overall risk assessment
        risk_level = "Low"
        critical_count = severity_summary.get("Critical", {}).get("count", 0)
        high_count = severity_summary.get("High", {}).get("count", 0)

        if critical_count > 0:
            risk_level = "Critical"
        elif high_count > 5:
            risk_level = "High"
        elif high_count > 0:
            risk_level = "Medium"

        result = {
            "query_summary": {
                "process_name": process_name,
                "host": host,
                "time_range": time_range,
                "total_alerts": total_alerts,
                "risk_level": risk_level
            },
            "severity_breakdown": severity_summary,
            "top_triggered_rules": top_rules,
            "time_distribution": time_distribution,
            "sample_alerts": sample_alerts,
            "analysis": {
                "alert_frequency": round(total_alerts / _parse_hours_from_range(time_range), 2) if total_alerts > 0 else 0,
                "most_common_rule": top_rules[0]["rule_id"] if top_rules else None,
                "peak_activity_hour": max(time_distribution, key=lambda x: x["count"])["timestamp"] if time_distribution else None
            }
        }

        logger.info("Smart process alerts query completed successfully",
                   process=process_name, host=host, total_alerts=total_alerts, risk_level=risk_level)

        return result

    except Exception as e:
        logger.error("Smart process alerts query failed",
                    process=process_name, host=host, error=str(e))
        return {"error": f"Query failed: {str(e)}"}


def _get_severity_name(level: int) -> str:
    """Convert numerical severity level to name."""
    if level >= 12:
        return "Critical"
    elif level >= 8:
        return "High"
    elif level >= 5:
        return "Medium"
    else:
        return "Low"


def _parse_hours_from_range(time_range: str) -> float:
    """Parse time range string to hours for frequency calculation."""
    if time_range.endswith('h'):
        return float(time_range[:-1])
    elif time_range.endswith('d'):
        return float(time_range[:-1]) * 24
    elif time_range.endswith('w'):
        return float(time_range[:-1]) * 24 * 7
    elif time_range.endswith('m'):
        return float(time_range[:-1]) * 24 * 30
    else:
        return 24.0  # Default to 24 hours