"""
Get activity patterns and behavior analysis for a specific entity
"""
from typing import Dict, Any
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient

logger = structlog.get_logger()


async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get activity patterns and behavior analysis for a specific entity
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including entity_type, entity_id, time_range
        
    Returns:
        Activity patterns, behavior analysis, and temporal patterns
    """
    try:
        # Extract parameters
        entity_type = params.get("entity_type", "host")
        entity_id = params.get("entity_id")
        time_range = params.get("time_range", "24h")
        
        if not entity_id:
            raise ValueError("entity_id is required")
        
        logger.info("Getting entity activity patterns",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    time_range=time_range)
        
        # Build entity query
        entity_query = opensearch_client.build_entity_query(entity_type, entity_id)
        
        # Build activity analysis query
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
                "hourly_activity": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "format": "yyyy-MM-dd HH:mm"
                    },
                    "aggs": {
                        "avg_severity": {
                            "avg": {"field": "rule.level"}
                        },
                        "unique_rules": {
                            "cardinality": {"field": "rule.id"}
                        }
                    }
                },
                "daily_patterns": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1d",
                        "format": "yyyy-MM-dd"
                    }
                },
                "hour_of_day": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "format": "HH"
                    }
                },
                "day_of_week": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1d",
                        "format": "e"
                    }
                },
                "activity_by_rule_group": {
                    "terms": {
                        "field": "rule.groups",
                        "size": 15
                    },
                    "aggs": {
                        "activity_timeline": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1h",
                                "format": "yyyy-MM-dd HH:mm"
                            }
                        }
                    }
                },
                "process_activity": {
                    "terms": {
                        "field": "data.win.eventdata.originalFileName",
                        "size": 10
                    },
                    "aggs": {
                        "process_timeline": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1h",
                                "format": "yyyy-MM-dd HH:mm"
                            }
                        }
                    }
                },
                "user_activity": {
                    "terms": {
                        "field": "data.srcuser",
                        "size": 10
                    },
                    "aggs": {
                        "user_timeline": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1h",
                                "format": "yyyy-MM-dd HH:mm"
                            }
                        }
                    }
                },
                "network_activity": {
                    "terms": {
                        "field": "data.srcip",
                        "size": 10
                    },
                    "aggs": {
                        "network_timeline": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1h",
                                "format": "yyyy-MM-dd HH:mm"
                            }
                        }
                    }
                },
                "activity_bursts": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "15m",
                        "format": "yyyy-MM-dd HH:mm"
                    },
                    "aggs": {
                        "burst_threshold": {
                            "bucket_selector": {
                                "buckets_path": {
                                    "count": "_count"
                                },
                                "script": {
                                    "source": "params.count > 5"
                                }
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
            size=0  # We only need aggregations
        )
        
        # Process results
        total_alerts = response["aggregations"]["total_count"]["value"]

        # Process hourly activity
        hourly_activity = []
        for bucket in response["aggregations"]["hourly_activity"]["buckets"]:
            hourly_activity.append({
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"],
                "avg_severity": round(bucket["avg_severity"]["value"], 2) if bucket["avg_severity"]["value"] else 0,
                "unique_rules": bucket["unique_rules"]["value"]
            })
        
        # Process daily patterns
        daily_patterns = []
        for bucket in response["aggregations"]["daily_patterns"]["buckets"]:
            daily_patterns.append({
                "date": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })
        
        # Process hour of day patterns
        hour_patterns = {}
        for bucket in response["aggregations"]["hour_of_day"]["buckets"]:
            hour = bucket["key_as_string"]
            hour_patterns[hour] = bucket["doc_count"]
        
        # Process day of week patterns
        day_patterns = {}
        day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        for bucket in response["aggregations"]["day_of_week"]["buckets"]:
            day_num = int(bucket["key_as_string"]) - 1  # Convert to 0-based index
            day_name = day_names[day_num] if 0 <= day_num < 7 else "Unknown"
            day_patterns[day_name] = bucket["doc_count"]
        
        # Process activity by rule group
        rule_group_activity = []
        for bucket in response["aggregations"]["activity_by_rule_group"]["buckets"]:
            timeline = []
            for time_bucket in bucket["activity_timeline"]["buckets"]:
                timeline.append({
                    "timestamp": time_bucket["key_as_string"],
                    "count": time_bucket["doc_count"]
                })
            
            rule_group_activity.append({
                "rule_group": bucket["key"],
                "total_count": bucket["doc_count"],
                "timeline": timeline
            })
        
        # Process activity
        process_activity = []
        for bucket in response["aggregations"]["process_activity"]["buckets"]:
            if bucket["key"]:  # Skip empty process names
                timeline = []
                for time_bucket in bucket["process_timeline"]["buckets"]:
                    timeline.append({
                        "timestamp": time_bucket["key_as_string"],
                        "count": time_bucket["doc_count"]
                    })
                
                process_activity.append({
                    "process_name": bucket["key"],
                    "total_count": bucket["doc_count"],
                    "timeline": timeline
                })
        
        # User activity
        user_activity = []
        for bucket in response["aggregations"]["user_activity"]["buckets"]:
            if bucket["key"]:  # Skip empty user names
                timeline = []
                for time_bucket in bucket["user_timeline"]["buckets"]:
                    timeline.append({
                        "timestamp": time_bucket["key_as_string"],
                        "count": time_bucket["doc_count"]
                    })
                
                user_activity.append({
                    "username": bucket["key"],
                    "total_count": bucket["doc_count"],
                    "timeline": timeline
                })
        
        # Process network activity
        network_activity = []
        for bucket in response["aggregations"]["network_activity"]["buckets"]:
            if bucket["key"]:  # Skip empty IPs
                timeline = []
                for time_bucket in bucket["network_timeline"]["buckets"]:
                    timeline.append({
                        "timestamp": time_bucket["key_as_string"],
                        "count": time_bucket["doc_count"]
                    })
                
                network_activity.append({
                    "source_ip": bucket["key"],
                    "total_count": bucket["doc_count"],
                    "timeline": timeline
                })
        
        # Process activity bursts
        activity_bursts = []
        for bucket in response["aggregations"]["activity_bursts"]["buckets"]:
            if bucket["doc_count"] > 5:  # Only include significant bursts
                activity_bursts.append({
                    "timestamp": bucket["key_as_string"],
                    "count": bucket["doc_count"]
                })
        
        # Calculate activity metrics
        activity_metrics = calculate_activity_metrics(hourly_activity, daily_patterns, hour_patterns, day_patterns)
        
        result = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "time_range": time_range,
            "total_alerts": total_alerts,
            "hourly_activity": hourly_activity,
            "daily_patterns": daily_patterns,
            "hour_patterns": hour_patterns,
            "day_patterns": day_patterns,
            "rule_group_activity": rule_group_activity,
            "process_activity": process_activity,
            "user_activity": user_activity,
            "network_activity": network_activity,
            "activity_bursts": activity_bursts,
            "activity_metrics": activity_metrics,
            "behavioral_analysis": {
                "peak_activity_hour": max(hour_patterns.items(), key=lambda x: x[1])[0] if hour_patterns else None,
                "peak_activity_day": max(day_patterns.items(), key=lambda x: x[1])[0] if day_patterns else None,
                "most_active_process": process_activity[0]["process_name"] if process_activity else None,
                "most_active_user": user_activity[0]["username"] if user_activity else None,
                "burst_periods": len(activity_bursts),
                "activity_consistency": activity_metrics.get("consistency_score", 0)
            }
        }
        
        logger.info("Entity activity investigation completed",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    total_alerts=total_alerts,
                    burst_periods=len(activity_bursts))
        
        return result
        
    except Exception as e:
        logger.error("Entity activity investigation failed",
                     error=str(e),
                     params=params)
        raise Exception(f"Failed to get entity activity: {str(e)}")


def calculate_activity_metrics(hourly_activity: list, daily_patterns: list, hour_patterns: dict, day_patterns: dict) -> Dict[str, Any]:
    """Calculate various activity metrics"""
    metrics = {}
    
    if hourly_activity:
        # Calculate activity statistics
        counts = [item["count"] for item in hourly_activity]
        avg_severities = [item["avg_severity"] for item in hourly_activity if item["avg_severity"] > 0]
        
        metrics["avg_alerts_per_hour"] = sum(counts) / len(counts) if counts else 0
        metrics["max_alerts_per_hour"] = max(counts) if counts else 0
        metrics["min_alerts_per_hour"] = min(counts) if counts else 0
        metrics["avg_severity"] = sum(avg_severities) / len(avg_severities) if avg_severities else 0
        
        # Calculate consistency score (lower variance = higher consistency)
        if len(counts) > 1:
            mean = sum(counts) / len(counts)
            variance = sum((x - mean) ** 2 for x in counts) / len(counts)
            metrics["consistency_score"] = max(0, 100 - (variance / mean * 10)) if mean > 0 else 0
        else:
            metrics["consistency_score"] = 100
    
    if daily_patterns:
        daily_counts = [item["count"] for item in daily_patterns]
        metrics["avg_alerts_per_day"] = sum(daily_counts) / len(daily_counts) if daily_counts else 0
        metrics["max_alerts_per_day"] = max(daily_counts) if daily_counts else 0
    
    # Calculate peak activity metrics
    if hour_patterns:
        total_hour_alerts = sum(hour_patterns.values())
        metrics["peak_hour_percentage"] = (max(hour_patterns.values()) / total_hour_alerts * 100) if total_hour_alerts > 0 else 0
    
    if day_patterns:
        total_day_alerts = sum(day_patterns.values())
        metrics["peak_day_percentage"] = (max(day_patterns.values()) / total_day_alerts * 100) if total_day_alerts > 0 else 0
    
    return metrics
