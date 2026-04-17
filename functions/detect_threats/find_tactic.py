"""
Find specific MITRE ATT&CK tactics in Wazuh alerts
"""
from typing import Dict, Any, List
import structlog

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Find specific MITRE ATT&CK tactics in alerts
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including tactic_name, timeframe, filters
        
    Returns:
        Tactic detection results with associated techniques, affected hosts, and timeline
    """
    try:
        # Extract parameters
        tactic_name = params.get("tactic_name")
        timeframe = params.get("timeframe", "7d")
        host_filter = params.get("host_filter")
        limit = params.get("limit", 50)
        
        logger.info("Finding MITRE ATT&CK tactic", 
                   tactic_name=tactic_name,
                   timeframe=timeframe,
                   host_filter=host_filter)
        
        # Build base query
        must_conditions = [
            opensearch_client.build_single_time_filter(timeframe)
        ]
        
        # Add tactic-specific filters
        if tactic_name:
            # Search for tactic in various MITRE-related fields (arrays)
            tactic_conditions = [
                {"terms": {"rule.mitre.tactic": [tactic_name]}},
                {"wildcard": {"rule.description": f"*{tactic_name}*"}},
                {"wildcard": {"rule.groups": f"*{tactic_name.lower().replace(' ', '_')}*"}}
            ]
            must_conditions.append({
                "bool": {
                    "should": tactic_conditions,
                    "minimum_should_match": 1
                }
            })
        else:
            # If no specific tactic, look for any tactic-related alerts
            must_conditions.append({
                "bool": {
                    "should": [
                        {"exists": {"field": "rule.mitre.tactic"}},
                        {"terms": {"rule.groups": ["mitre", "attack", "tactic"]}}
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
                "tactics": {
                    "terms": {
                        "field": "rule.mitre.tactic",
                        "size": 20,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "associated_techniques": {
                            "terms": {
                                "field": "rule.mitre.technique",
                                "size": 15
                            }
                        },
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
                                "fixed_interval": "4h",
                                "order": {"_key": "desc"}
                            }
                        }
                    }
                },
                "technique_frequency": {
                    "terms": {
                        "field": "rule.mitre.technique",
                        "size": 25,
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
                "rule_distribution": {
                    "terms": {
                        "field": "rule.description",
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
        tactics_agg = response.get("aggregations", {}).get("tactics", {})
        techniques_agg = response.get("aggregations", {}).get("technique_frequency", {})
        hosts_agg = response.get("aggregations", {}).get("affected_hosts", {})
        rules_agg = response.get("aggregations", {}).get("rule_distribution", {})
        
        # Process tactic results
        tactic_results = []
        for bucket in tactics_agg.get("buckets", []):
            tactic_name_found = bucket["key"]
            alert_count = bucket["doc_count"]
            
            # Get associated techniques for this tactic
            associated_techniques = []
            for tech_bucket in bucket.get("associated_techniques", {}).get("buckets", []):
                associated_techniques.append({
                    "technique": tech_bucket["key"],
                    "alert_count": tech_bucket["doc_count"]
                })
            
            # Get affected hosts for this tactic
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
            
            tactic_results.append({
                "tactic": tactic_name_found,
                "alert_count": alert_count,
                "associated_techniques": associated_techniques,
                "affected_hosts": affected_hosts,
                "severity_breakdown": severity_breakdown,
                "timeline": timeline[:42]  # Last 42 periods (7 days * 6 4-hour periods)
            })
        
        # Process most frequent techniques
        frequent_techniques = []
        for bucket in techniques_agg.get("buckets", []):
            frequent_techniques.append({
                "technique": bucket["key"],
                "alert_count": bucket["doc_count"]
            })
        
        # Process affected hosts
        affected_hosts = []
        for bucket in hosts_agg.get("buckets", []):
            affected_hosts.append({
                "host": bucket["key"],
                "alert_count": bucket["doc_count"]
            })
        
        # Process rule distribution
        rule_distribution = []
        for bucket in rules_agg.get("buckets", []):
            rule_distribution.append({
                "rule": bucket["key"],
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
        
        # Calculate tactic coverage and threat landscape
        tactic_coverage = {
            "reconnaissance": 0,
            "resource_development": 0,
            "initial_access": 0,
            "execution": 0,
            "persistence": 0,
            "privilege_escalation": 0,
            "defense_evasion": 0,
            "credential_access": 0,
            "discovery": 0,
            "lateral_movement": 0,
            "collection": 0,
            "command_and_control": 0,
            "exfiltration": 0,
            "impact": 0
        }
        
        # Map detected tactics to MITRE framework
        for tactic_result in tactic_results:
            tactic_lower = tactic_result["tactic"].lower().replace(" ", "_")
            if tactic_lower in tactic_coverage:
                tactic_coverage[tactic_lower] = tactic_result["alert_count"]
        
        # Build result
        result = {
            "total_alerts": total_alerts,
            "search_criteria": {
                "tactic_name": params.get("tactic_name"),
                "timeframe": timeframe,
                "host_filter": host_filter
            },
            "tactics_found": tactic_results,
            "technique_frequency": frequent_techniques,
            "affected_hosts": affected_hosts,
            "rule_distribution": rule_distribution,
            "recent_alerts": recent_alerts,
            "tactic_coverage": tactic_coverage,
            "summary": {
                "unique_tactics": len(tactic_results),
                "unique_techniques": len(frequent_techniques),
                "hosts_affected": len(affected_hosts),
                "most_common_tactic": tactic_results[0]["tactic"] if tactic_results else None,
                "most_common_technique": frequent_techniques[0]["technique"] if frequent_techniques else None,
                "most_affected_host": affected_hosts[0]["host"] if affected_hosts else None,
                "tactics_detected": len([t for t in tactic_coverage.values() if t > 0])
            }
        }
        
        logger.info("MITRE tactic detection completed", 
                   total_alerts=total_alerts,
                   tactics_found=len(tactic_results),
                   techniques_found=len(frequent_techniques))
        
        return result
        
    except Exception as e:
        logger.error("MITRE tactic detection failed", error=str(e))
        raise Exception(f"Failed to find MITRE tactics: {str(e)}")