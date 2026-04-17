"""
Get detailed information about a specific entity (host, user, process, file, ip)
"""
from typing import Dict, Any
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient

logger = structlog.get_logger()


async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get detailed information about a specific entity
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including entity_type, entity_id, time_range
        
    Returns:
        Detailed entity information including summary, metadata, and recent activity
    """
    try:
        # Extract parameters
        entity_type = params.get("entity_type", "host")
        entity_id = params.get("entity_id")
        time_range = params.get("time_range", "24h")
        
        if not entity_id:
            raise ValueError("entity_id is required")
        
        logger.info("Getting entity details",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    time_range=time_range)
        
        # Build entity query
        entity_query = opensearch_client.build_entity_query(entity_type, entity_id)
        
        # Build comprehensive query for entity details
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
                "entity_summary": {
                    "terms": {
                        "field": "agent.name" if entity_type == "host" else f"data.{entity_type}",
                        "size": 1
                    },
                    "aggs": {
                        "first_seen": {
                            "min": {"field": "@timestamp"}
                        },
                        "last_seen": {
                            "max": {"field": "@timestamp"}
                        },
                        "total_alerts": {
                            "value_count": {"field": "@timestamp"}
                        }
                    }
                },
                "alert_severity_breakdown": {
                    "terms": {
                        "field": "rule.level",
                        "size": 10
                    }
                },
                "top_rules": {
                    "terms": {
                        "field": "rule.id",
                        "size": 5
                    },
                    "aggs": {
                        "rule_info": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["rule.description", "rule.level", "rule.groups"]
                            }
                        }
                    }
                },
                "mitre_techniques": {
                    "terms": {
                        "field": "rule.mitre.id",
                        "size": 10
                    },
                    "aggs": {
                        "technique_info": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["rule.mitre.technique", "rule.mitre.tactic"]
                            }
                        }
                    }
                },
                "event_types": {
                    "terms": {
                        "field": "rule.groups",
                        "size": 10
                    }
                },
                "activity_timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "format": "yyyy-MM-dd HH:mm"
                    }
                }
            }
        }
        
        # Execute query
        response = await opensearch_client.search(
            opensearch_client.alerts_index, 
            query, 
            size=10  # Get recent sample alerts
        )
        
        # Process results
        total_alerts = response["aggregations"]["total_count"]["value"]

        # Process entity summary
        entity_summary = {}
        if response["aggregations"]["entity_summary"]["buckets"]:
            bucket = response["aggregations"]["entity_summary"]["buckets"][0]
            entity_summary = {
                "entity_name": bucket["key"],
                "first_seen": bucket["first_seen"]["value_as_string"],
                "last_seen": bucket["last_seen"]["value_as_string"],
                "total_alerts": bucket["total_alerts"]["value"]
            }
        
        # Process severity breakdown
        severity_breakdown = {}
        for bucket in response["aggregations"]["alert_severity_breakdown"]["buckets"]:
            level = bucket["key"]
            severity_breakdown[str(level)] = {
                "count": bucket["doc_count"],
                "severity_name": get_severity_name(level),
                "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0
            }
        
        # Process top rules
        top_rules = []
        for bucket in response["aggregations"]["top_rules"]["buckets"]:
            rule_data = {
                "rule_id": bucket["key"],
                "count": bucket["doc_count"],
                "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0
            }
            
            if bucket["rule_info"]["hits"]["hits"]:
                rule_source = bucket["rule_info"]["hits"]["hits"][0]["_source"]
                rule_data["description"] = rule_source.get("rule", {}).get("description", "")
                rule_data["level"] = rule_source.get("rule", {}).get("level", 0)
                rule_data["groups"] = rule_source.get("rule", {}).get("groups", [])
            
            top_rules.append(rule_data)
        
        # Process MITRE techniques
        mitre_techniques = []
        for bucket in response["aggregations"]["mitre_techniques"]["buckets"]:
            if bucket["key"]:  # Skip empty MITRE IDs
                technique_data = {
                    "technique_id": bucket["key"],
                    "count": bucket["doc_count"]
                }
                
                if bucket["technique_info"]["hits"]["hits"]:
                    technique_source = bucket["technique_info"]["hits"]["hits"][0]["_source"]
                    technique_data["technique_name"] = technique_source.get("rule", {}).get("mitre", {}).get("technique", ["Unknown"])[0]
                    technique_data["tactics"] = technique_source.get("rule", {}).get("mitre", {}).get("tactic", [])
                
                mitre_techniques.append(technique_data)
        
        # Process event types
        event_types = []
        for bucket in response["aggregations"]["event_types"]["buckets"]:
            event_types.append({
                "event_type": bucket["key"],
                "count": bucket["doc_count"]
            })
        
        # Process activity timeline
        activity_timeline = []
        for bucket in response["aggregations"]["activity_timeline"]["buckets"]:
            activity_timeline.append({
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })
        
        # Get recent sample alerts
        recent_alerts = []
        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            alert = {
                "timestamp": source.get("@timestamp", ""),
                "rule_id": source.get("rule", {}).get("id", ""),
                "rule_description": source.get("rule", {}).get("description", ""),
                "rule_level": source.get("rule", {}).get("level", 0),
                "full_log": source.get("full_log", "")[:200] + "..." if len(source.get("full_log", "")) > 200 else source.get("full_log", "")
            }
            recent_alerts.append(alert)
        
        result = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "time_range": time_range,
            "entity_summary": entity_summary,
            "total_alerts": total_alerts,
            "severity_breakdown": severity_breakdown,
            "top_rules": top_rules,
            "mitre_techniques": mitre_techniques,
            "event_types": event_types,
            "activity_timeline": activity_timeline,
            "recent_alerts": recent_alerts,
            "risk_assessment": {
                "risk_score": calculate_risk_score(severity_breakdown, mitre_techniques),
                "highest_severity": max([int(k) for k in severity_breakdown.keys()]) if severity_breakdown else 0,
                "mitre_coverage": len(mitre_techniques),
                "activity_frequency": total_alerts / max(1, len(activity_timeline)) if activity_timeline else 0
            }
        }
        
        logger.info("Entity details investigation completed",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    total_alerts=total_alerts,
                    risk_score=result["risk_assessment"]["risk_score"])
        
        return result
        
    except Exception as e:
        logger.error("Entity details investigation failed",
                     error=str(e),
                     params=params)
        raise Exception(f"Failed to get entity details: {str(e)}")


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


def calculate_risk_score(severity_breakdown: Dict, mitre_techniques: list) -> int:
    """Calculate a risk score based on severity distribution and MITRE techniques"""
    risk_score = 0
    
    # Add points based on severity distribution
    for level_str, data in severity_breakdown.items():
        level = int(level_str)
        count = data["count"]
        
        if level >= 12:  # Critical
            risk_score += count * 10
        elif level >= 8:  # High
            risk_score += count * 5
        elif level >= 5:  # Medium
            risk_score += count * 2
        elif level >= 3:  # Low
            risk_score += count * 1
    
    # Add points for MITRE technique diversity
    risk_score += len(mitre_techniques) * 3
    
    # Cap the risk score at 100
    return min(risk_score, 100)
