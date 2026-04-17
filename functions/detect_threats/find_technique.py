"""
Find specific MITRE ATT&CK techniques in Wazuh alerts
"""
from typing import Dict, Any, List
import structlog

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Find specific MITRE ATT&CK techniques in alerts
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including technique_id, timeframe, filters
        
    Returns:
        Technique detection results with affected hosts, timeline, and alert details
    """
    try:
        # Extract parameters
        technique_id = params.get("technique_id")
        timeframe = params.get("timeframe", "7d")
        host_filter = params.get("host_filter")
        limit = params.get("limit", 50)
        
        logger.info("Finding MITRE ATT&CK technique", 
                   technique_id=technique_id,
                   timeframe=timeframe,
                   host_filter=host_filter)
        
        # Build base query
        must_conditions = [
            opensearch_client.build_single_time_filter(timeframe)
        ]
        
        # Add technique-specific filters
        if technique_id:
            # Search for technique in various MITRE-related fields (arrays)
            technique_conditions = [
                {"terms": {"rule.mitre.technique": [technique_id]}},
                {"terms": {"rule.mitre.id": [technique_id]}},
                {"wildcard": {"rule.description": f"*{technique_id}*"}},
                {"wildcard": {"rule.groups": f"*{technique_id.lower()}*"}}
            ]
            must_conditions.append({
                "bool": {
                    "should": technique_conditions,
                    "minimum_should_match": 1
                }
            })
        else:
            # If no specific technique, look for any MITRE-related alerts
            must_conditions.append({
                "bool": {
                    "should": [
                        {"exists": {"field": "rule.mitre.technique"}},
                        {"exists": {"field": "rule.mitre.id"}},
                        {"wildcard": {"rule.description": "*T[0-9]*"}},
                        {"terms": {"rule.groups": ["mitre", "attack", "technique"]}}
                    ],
                    "minimum_should_match": 1
                }
            })
        
        # Add host filter if specified
        if host_filter:
            must_conditions.append({
                "bool": {
                    "should": [
                        {"term": {"agent.name": host_filter}},
                        {"term": {"agent.ip": host_filter}},
                        {"term": {"agent.id": host_filter}}
                    ],
                    "minimum_should_match": 1
                }
            })
        
        # Build main query
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ],
            "size": limit,
            "aggs": {
                "total_count": {
                    "value_count": {
                        "field": "_id"
                    }
                },
                "techniques": {
                    "terms": {
                        "field": "rule.mitre.technique",
                        "size": 20,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "affected_hosts": {
                            "terms": {
                                "field": "agent.name",
                                "size": 10
                            }
                        },
                        "severity_breakdown": {
                            "terms": {
                                "field": "rule.level",
                                "size": 10
                            }
                        },
                        "timeline": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1h",
                                "order": {"_key": "desc"}
                            }
                        }
                    }
                },
                "tactics": {
                    "terms": {
                        "field": "rule.mitre.tactic",
                        "size": 15,
                        "order": {"_count": "desc"}
                    }
                },
                "affected_hosts": {
                    "terms": {
                        "field": "agent.name",
                        "size": 20,
                        "order": {"_count": "desc"}
                    }
                },
                "rule_groups": {
                    "terms": {
                        "field": "rule.groups",
                        "size": 15,
                        "order": {"_count": "desc"}
                    }
                }
            }
        }
        
        # Execute search
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query
        )
        
        # Extract results
        hits = response.get("hits", {})
        total_alerts = response["aggregations"]["total_count"]["value"]
        alert_hits = hits.get("hits", [])
        
        # Process aggregations
        techniques_agg = response.get("aggregations", {}).get("techniques", {})
        tactics_agg = response.get("aggregations", {}).get("tactics", {})
        hosts_agg = response.get("aggregations", {}).get("affected_hosts", {})
        groups_agg = response.get("aggregations", {}).get("rule_groups", {})
        
        # Process technique results
        technique_results = []
        for bucket in techniques_agg.get("buckets", []):
            technique_name = bucket["key"]
            alert_count = bucket["doc_count"]
            
            # Get affected hosts for this technique
            affected_hosts = []
            for host_bucket in bucket.get("affected_hosts", {}).get("buckets", []):
                affected_hosts.append({
                    "host": host_bucket["key"],
                    "alert_count": host_bucket["doc_count"]
                })
            
            # Get severity breakdown
            severity_breakdown = {}
            for sev_bucket in bucket.get("severity_breakdown", {}).get("buckets", []):
                severity_breakdown[str(sev_bucket["key"])] = sev_bucket["doc_count"]
            
            # Get timeline
            timeline = []
            for time_bucket in bucket.get("timeline", {}).get("buckets", []):
                timeline.append({
                    "timestamp": time_bucket["key_as_string"],
                    "count": time_bucket["doc_count"]
                })
            
            technique_results.append({
                "technique": technique_name,
                "alert_count": alert_count,
                "affected_hosts": affected_hosts,
                "severity_breakdown": severity_breakdown,
                "timeline": timeline[:24]  # Last 24 hours
            })
        
        # Process tactics
        tactics_found = []
        for bucket in tactics_agg.get("buckets", []):
            tactics_found.append({
                "tactic": bucket["key"],
                "alert_count": bucket["doc_count"]
            })
        
        # Process affected hosts
        affected_hosts = []
        for bucket in hosts_agg.get("buckets", []):
            affected_hosts.append({
                "host": bucket["key"],
                "alert_count": bucket["doc_count"]
            })
        
        # Process rule groups
        rule_groups = []
        for bucket in groups_agg.get("buckets", []):
            rule_groups.append({
                "group": bucket["key"],
                "alert_count": bucket["doc_count"]
            })
        
        # Process recent alerts
        recent_alerts = []
        for hit in alert_hits[:10]:  # Top 10 most recent
            source = hit.get("_source", {})
            rule = source.get("rule", {})
            agent = source.get("agent", {})
            
            recent_alerts.append({
                "timestamp": source.get("@timestamp"),
                "rule_id": rule.get("id"),
                "rule_description": rule.get("description"),
                "rule_level": rule.get("level"),
                "technique": rule.get("mitre", {}).get("technique"),
                "tactic": rule.get("mitre", {}).get("tactic"),
                "host": agent.get("name"),
                "host_ip": agent.get("ip")
            })
        
        # Build result
        result = {
            "total_alerts": total_alerts,
            "search_criteria": {
                "technique_id": technique_id,
                "timeframe": timeframe,
                "host_filter": host_filter
            },
            "techniques_found": technique_results,
            "tactics_detected": tactics_found,
            "affected_hosts": affected_hosts,
            "rule_groups": rule_groups,
            "recent_alerts": recent_alerts,
            "summary": {
                "unique_techniques": len(technique_results),
                "unique_tactics": len(tactics_found),
                "hosts_affected": len(affected_hosts),
                "most_common_technique": technique_results[0]["technique"] if technique_results else None,
                "most_affected_host": affected_hosts[0]["host"] if affected_hosts else None
            }
        }
        
        logger.info("MITRE technique detection completed", 
                   total_alerts=total_alerts,
                   techniques_found=len(technique_results),
                   tactics_found=len(tactics_found))
        
        return result
        
    except Exception as e:
        logger.error("MITRE technique detection failed", error=str(e))
        raise Exception(f"Failed to find MITRE techniques: {str(e)}")