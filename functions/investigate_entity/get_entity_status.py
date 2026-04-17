"""
Get current status and health information for a specific entity
"""
from typing import Dict, Any
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient

logger = structlog.get_logger()


async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get current status and health information for a specific entity
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including entity_type, entity_id, time_range
        
    Returns:
        Current status, health metrics, and monitoring information
    """
    try:
        # Extract parameters
        entity_type = params.get("entity_type", "host")
        entity_id = params.get("entity_id")
        time_range = params.get("time_range", "1h")  # Default to 1 hour for status
        
        if not entity_id:
            raise ValueError("entity_id is required")
        
        logger.info("Getting entity status",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    time_range=time_range)
        
        # Build entity query
        entity_query = opensearch_client.build_entity_query(entity_type, entity_id)
        
        # Build status query with recent time range
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
                "current_status": {
                    "terms": {
                        "field": "agent.name" if entity_type == "host" else f"data.{entity_type}",
                        "size": 1
                    },
                    "aggs": {
                        "last_seen": {
                            "max": {"field": "@timestamp"}
                        },
                        "recent_alerts": {
                            "filter": {
                                "range": {
                                    "@timestamp": {
                                        "gte": "now-5m"
                                    }
                                }
                            }
                        },
                        "current_severity": {
                            "terms": {
                                "field": "rule.level",
                                "size": 1,
                                "order": {"_key": "desc"}
                            }
                        }
                    }
                },
                "health_indicators": {
                    "terms": {
                        "field": "rule.groups",
                        "size": 10
                    },
                    "aggs": {
                        "latest_occurrence": {
                            "max": {"field": "@timestamp"}
                        }
                    }
                },
                "agent_status": {
                    "terms": {
                        "field": "agent.id",
                        "size": 1
                    },
                    "aggs": {
                        "agent_info": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"@timestamp": {"order": "desc"}}],
                                "_source": ["agent.name", "agent.ip", "manager.name"]
                            }
                        },
                        "last_communication": {
                            "max": {"field": "@timestamp"}
                        }
                    }
                },
                "error_indicators": {
                    "filter": {
                        "range": {
                            "rule.level": {
                                "gte": 8
                            }
                        }
                    },
                    "aggs": {
                        "critical_errors": {
                            "terms": {
                                "field": "rule.id",
                                "size": 5
                            },
                            "aggs": {
                                "error_details": {
                                    "top_hits": {
                                        "size": 1,
                                        "sort": [{"@timestamp": {"order": "desc"}}],
                                        "_source": ["rule.description", "rule.level", "full_log"]
                                    }
                                }
                            }
                        }
                    }
                },
                "monitoring_health": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "5m",
                        "format": "yyyy-MM-dd HH:mm"
                    },
                    "aggs": {
                        "avg_severity": {
                            "avg": {"field": "rule.level"}
                        },
                        "max_severity": {
                            "max": {"field": "rule.level"}
                        }
                    }
                },
                "service_status": {
                    "terms": {
                        "field": "data.win.eventdata.serviceName",
                        "size": 10
                    },
                    "aggs": {
                        "service_state": {
                            "terms": {
                                "field": "data.win.eventdata.state",
                                "size": 5
                            }
                        }
                    }
                },
                "process_status": {
                    "terms": {
                        "field": "data.win.eventdata.originalFileName",
                        "size": 10
                    },
                    "aggs": {
                        "process_activity": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "5m",
                                "format": "yyyy-MM-dd HH:mm"
                            }
                        }
                    }
                }
            }
        }
        
        # Execute query
        response = await opensearch_client.search(
            opensearch_client.alerts_index, 
            query, 
            size=5  # Get a few recent alerts for context
        )
        
        # Process results
        total_alerts = response["aggregations"]["total_count"]["value"]


        # Process current status
        current_status = {}
        if response["aggregations"]["current_status"]["buckets"]:
            bucket = response["aggregations"]["current_status"]["buckets"][0]
            current_status = {
                "entity_name": bucket["key"],
                "last_seen": bucket["last_seen"]["value_as_string"],
                "recent_alerts_count": bucket["recent_alerts"]["doc_count"],
                "current_severity": bucket["current_severity"]["buckets"][0]["key"] if bucket["current_severity"]["buckets"] else 0
            }
        
        # Process health indicators
        health_indicators = []
        for bucket in response["aggregations"]["health_indicators"]["buckets"]:
            health_indicators.append({
                "indicator": bucket["key"],
                "count": bucket["doc_count"],
                "last_occurrence": bucket["latest_occurrence"]["value_as_string"]
            })
        
        # Process agent status
        agent_status = {}
        if response["aggregations"]["agent_status"]["buckets"]:
            bucket = response["aggregations"]["agent_status"]["buckets"][0]
            agent_info = bucket["agent_info"]["hits"]["hits"][0]["_source"]
            agent_status = {
                "agent_id": bucket["key"],
                "agent_name": agent_info.get("agent", {}).get("name", ""),
                "agent_ip": agent_info.get("agent", {}).get("ip", ""),
                "manager_name": agent_info.get("manager", {}).get("name", ""),
                "last_communication": bucket["last_communication"]["value_as_string"]
            }
        
        # Process error indicators
        error_indicators = []
        if response["aggregations"]["error_indicators"]["critical_errors"]["buckets"]:
            for bucket in response["aggregations"]["error_indicators"]["critical_errors"]["buckets"]:
                error_details = bucket["error_details"]["hits"]["hits"][0]["_source"]
                error_indicators.append({
                    "rule_id": bucket["key"],
                    "count": bucket["doc_count"],
                    "description": error_details.get("rule", {}).get("description", ""),
                    "level": error_details.get("rule", {}).get("level", 0),
                    "sample_log": error_details.get("full_log", "")[:100] + "..." if len(error_details.get("full_log", "")) > 100 else error_details.get("full_log", "")
                })
        
        # Process monitoring health
        monitoring_health = []
        for bucket in response["aggregations"]["monitoring_health"]["buckets"]:
            monitoring_health.append({
                "timestamp": bucket["key_as_string"],
                "alert_count": bucket["doc_count"],
                "avg_severity": round(bucket["avg_severity"]["value"], 2) if bucket["avg_severity"]["value"] else 0,
                "max_severity": bucket["max_severity"]["value"] if bucket["max_severity"]["value"] else 0
            })
        
        # Process service status
        service_status = []
        for bucket in response["aggregations"]["service_status"]["buckets"]:
            if bucket["key"]:  # Skip empty service names
                states = []
                for state_bucket in bucket["service_state"]["buckets"]:
                    states.append({
                        "state": state_bucket["key"],
                        "count": state_bucket["doc_count"]
                    })
                
                service_status.append({
                    "service_name": bucket["key"],
                    "alert_count": bucket["doc_count"],
                    "states": states
                })
        
        # Process process status
        process_status = []
        for bucket in response["aggregations"]["process_status"]["buckets"]:
            if bucket["key"]:  # Skip empty process names
                activity = []
                for activity_bucket in bucket["process_activity"]["buckets"]:
                    activity.append({
                        "timestamp": activity_bucket["key_as_string"],
                        "count": activity_bucket["doc_count"]
                    })
                
                process_status.append({
                    "process_name": bucket["key"],
                    "alert_count": bucket["doc_count"],
                    "activity_timeline": activity
                })
        
        # Get recent alerts for context
        recent_alerts = []
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
                # Process information with proper field extraction
                "process_name": win_eventdata.get("originalFileName", win_eventdata.get("processName", "")),
                "process_image": win_eventdata.get("image", ""),
                "command_line": win_eventdata.get("commandLine", ""),
                "parent_command_line": win_eventdata.get("parentCommandLine", ""),
                "process_id": win_eventdata.get("processId", ""),
                "target_user": win_eventdata.get("targetUserName", ""),
                "target_filename": win_eventdata.get("targetFilename", "")
            }
            recent_alerts.append(alert)
        
        # Calculate overall health score
        health_score = calculate_health_score(current_status, error_indicators, monitoring_health)
        
        # Determine entity status
        entity_status = determine_entity_status(current_status, health_score, error_indicators)
        
        result = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "time_range": time_range,
            "entity_status": entity_status,
            "health_score": health_score,
            "current_status": current_status,
            "total_recent_alerts": total_alerts,
            "health_indicators": health_indicators,
            "agent_status": agent_status,
            "error_indicators": error_indicators,
            "monitoring_health": monitoring_health,
            "service_status": service_status,
            "process_status": process_status,
            "recent_alerts": recent_alerts,
            "recommendations": generate_recommendations(entity_status, health_score, error_indicators)
        }
        
        logger.info("Entity status investigation completed",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    entity_status=entity_status,
                    health_score=health_score)
        
        return result
        
    except Exception as e:
        logger.error("Entity status investigation failed",
                     error=str(e),
                     params=params)
        raise Exception(f"Failed to get entity status: {str(e)}")


def calculate_health_score(current_status: Dict, error_indicators: list, monitoring_health: list) -> int:
    """Calculate overall health score (0-100)"""
    score = 100
    
    # Deduct points for recent alerts
    recent_alerts = current_status.get("recent_alerts_count", 0)
    if recent_alerts > 0:
        score -= min(recent_alerts * 5, 30)  # Max 30 points deduction
    
    # Deduct points for current severity
    current_severity = current_status.get("current_severity", 0)
    if current_severity >= 12:  # Critical
        score -= 40
    elif current_severity >= 8:  # High
        score -= 25
    elif current_severity >= 5:  # Medium
        score -= 10
    
    # Deduct points for error indicators
    critical_errors = len(error_indicators)
    if critical_errors > 0:
        score -= min(critical_errors * 10, 30)  # Max 30 points deduction
    
    # Consider monitoring health trend
    if monitoring_health:
        recent_severities = [item["avg_severity"] for item in monitoring_health[-3:]]  # Last 3 data points
        if recent_severities:
            avg_recent_severity = sum(recent_severities) / len(recent_severities)
            if avg_recent_severity > 5:
                score -= 15
    
    return max(0, score)


def determine_entity_status(current_status: Dict, health_score: int, error_indicators: list) -> str:
    """Determine overall entity status"""
    if health_score >= 90:
        return "Healthy"
    elif health_score >= 70:
        return "Warning"
    elif health_score >= 50:
        return "Critical"
    else:
        return "Severe"


def generate_recommendations(entity_status: str, health_score: int, error_indicators: list) -> list:
    """Generate recommendations based on entity status"""
    recommendations = []
    
    if entity_status == "Severe":
        recommendations.append("Immediate investigation required - entity showing severe issues")
        recommendations.append("Check for active incidents and escalate if necessary")
    elif entity_status == "Critical":
        recommendations.append("Entity requires attention - multiple security events detected")
        recommendations.append("Review recent alerts and investigate potential security incidents")
    elif entity_status == "Warning":
        recommendations.append("Monitor entity closely - some concerning activity detected")
        recommendations.append("Consider implementing additional monitoring or security controls")
    
    if error_indicators:
        recommendations.append(f"Investigate {len(error_indicators)} critical error(s) detected")
        recommendations.append("Review error logs and implement fixes for recurring issues")
    
    if health_score < 50:
        recommendations.append("Consider isolating entity if security compromise is suspected")
        recommendations.append("Perform comprehensive security assessment")
    
    return recommendations