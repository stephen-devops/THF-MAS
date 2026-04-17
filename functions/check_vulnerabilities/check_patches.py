"""
Check patch status and Windows update-related security events in Wazuh alerts
"""
from typing import Dict, Any, List
import structlog
from datetime import datetime, timedelta
import re

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check patch status and Windows update events to identify potential security gaps
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including patch_status, timeframe, entity_filter
        
    Returns:
        Patch analysis results with update events, missing patches, and security recommendations
    """
    try:
        # Extract parameters
        patch_status = params.get("patch_status", None)  # installed, missing, failed
        timeframe = params.get("timeframe", "30d")
        entity_filter = params.get("entity_filter", None)
        limit = params.get("limit", 50)
        
        logger.info("Checking patch status and updates", 
                   patch_status=patch_status,
                   timeframe=timeframe,
                   entity_filter=entity_filter)
        
        # Build base query for patch/update-related events
        query = {
            "query": {
                "bool": {
                    "must": [opensearch_client.build_single_time_filter(timeframe)],
                    "should": [
                        # Windows Update events
                        {"wildcard": {"rule.description": "*windows*update*"}},
                        {"wildcard": {"rule.description": "*patch*"}},
                        {"wildcard": {"rule.description": "*hotfix*"}},
                        {"wildcard": {"rule.description": "*KB*"}},
                        # Windows Event IDs related to updates
                        {"terms": {"data.win.system.eventID": ["19", "20", "43", "44"]}},  # Windows Update events
                        {"terms": {"data.win.system.eventID": ["4697", "4698", "4699"]}},  # Service installation events
                        # Rule groups that might contain patch information
                        {"terms": {"rule.groups": ["windows", "system_audit", "policy_monitoring", "rootcheck"]}},
                        # System integrity events that might indicate patches
                        {"terms": {"rule.groups": ["syscheck"]}},
                        # Failed installation or security update events
                        {"bool": {"must": [{"wildcard": {"rule.description": "*failed*"}}, {"wildcard": {"rule.description": "*update*"}}]}},
                        # Security-related patch patterns
                        {"wildcard": {"rule.description": "*security*update*"}},
                        {"wildcard": {"rule.description": "*critical*update*"}},
                        # Registry changes that might indicate patches
                        {"bool": {"must": [{"wildcard": {"rule.description": "*registry*"}}, {"wildcard": {"rule.description": "*software*"}}]}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 0,
            "aggs": {
                "total_count": {
                    "value_count": {
                        "field": "_id"
                    }
                },
                "patch_timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1d",
                        "order": {"_key": "desc"}
                    },
                    "aggs": {
                        "patch_types": {
                            "terms": {
                                "field": "rule.groups",
                                "size": 10
                            }
                        },
                        "affected_hosts": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        }
                    }
                },
                "hosts_patch_status": {
                    "terms": {
                        "field": "agent.name",
                        "size": 100
                    },
                    "aggs": {
                        "host_ip": {
                            "terms": {
                                "field": "agent.ip",
                                "size": 1
                            }
                        },
                        "patch_events": {
                            "terms": {
                                "field": "rule.description",
                                "size": 30
                            },
                            "aggs": {
                                "event_count": {
                                    "value_count": {
                                        "field": "rule.id"
                                    }
                                },
                                "rule_groups": {
                                    "terms": {
                                        "field": "rule.groups",
                                        "size": 5
                                    }
                                },
                                "latest_event": {
                                    "top_hits": {
                                        "size": 1,
                                        "sort": [{"@timestamp": {"order": "desc"}}],
                                        "_source": ["@timestamp", "rule.level", "rule.id"]
                                    }
                                }
                            }
                        },
                        "windows_updates": {
                            "filter": {
                                "bool": {
                                    "should": [
                                        {"wildcard": {"rule.description": "*windows*update*"}},
                                        {"wildcard": {"rule.description": "*KB*"}},
                                        {"terms": {"data.win.system.eventID": ["19", "20", "43", "44"]}}
                                    ]
                                }
                            },
                            "aggs": {
                                "update_events": {
                                    "top_hits": {
                                        "size": 10,
                                        "sort": [{"@timestamp": {"order": "desc"}}],
                                        "_source": ["@timestamp", "rule.description", "data.win.system.eventID"]
                                    }
                                }
                            }
                        },
                        "failed_updates": {
                            "filter": {
                                "bool": {
                                    "must": [
                                        {"wildcard": {"rule.description": "*failed*"}},
                                        {"bool": {"should": [
                                            {"wildcard": {"rule.description": "*update*"}},
                                            {"wildcard": {"rule.description": "*patch*"}},
                                            {"wildcard": {"rule.description": "*install*"}}
                                        ]}}
                                    ]
                                }
                            }
                        },
                        "security_updates": {
                            "filter": {
                                "wildcard": {"rule.description": "*security*update*"}
                            }
                        }
                    }
                },
                "patch_event_analysis": {
                    "terms": {
                        "field": "rule.description",
                        "size": 50
                    },
                    "aggs": {
                        "host_coverage": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "frequency": {
                            "value_count": {
                                "field": "rule.id"
                            }
                        },
                        "rule_info": {
                            "terms": {
                                "field": "rule.groups",
                                "size": 10
                            }
                        },
                        "sample_events": {
                            "top_hits": {
                                "size": 3,
                                "sort": [{"@timestamp": {"order": "desc"}}],
                                "_source": ["@timestamp", "agent.name", "rule.level", "rule.id"]
                            }
                        }
                    }
                },
                "kb_pattern_analysis": {
                    "filter": {
                        "wildcard": {"rule.description": "*KB*"}
                    },
                    "aggs": {
                        "kb_events": {
                            "terms": {
                                "field": "rule.description",
                                "size": 30
                            },
                            "aggs": {
                                "affected_hosts": {
                                    "cardinality": {
                                        "field": "agent.name"
                                    }
                                }
                            }
                        }
                    }
                },
                "system_integrity_changes": {
                    "filter": {
                        "terms": {"rule.groups": ["syscheck", "rootcheck"]}
                    },
                    "aggs": {
                        "integrity_hosts": {
                            "terms": {
                                "field": "agent.name",
                                "size": 50
                            },
                            "aggs": {
                                "change_types": {
                                    "terms": {
                                        "field": "rule.description",
                                        "size": 15
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        # Apply entity filter if specified
        if entity_filter:
            query["query"]["bool"]["must"].append({
                "wildcard": {"agent.name": f"*{entity_filter}*"}
            })
        
        # Apply patch status filter if specified
        if patch_status:
            if patch_status.lower() == "failed":
                query["query"]["bool"]["must"].append({
                    "bool": {
                        "must": [
                            {"wildcard": {"rule.description": "*failed*"}},
                            {"bool": {"should": [
                                {"wildcard": {"rule.description": "*update*"}},
                                {"wildcard": {"rule.description": "*patch*"}},
                                {"wildcard": {"rule.description": "*install*"}}
                            ]}}
                        ]
                    }
                })
            elif patch_status.lower() == "installed":
                query["query"]["bool"]["must"].append({
                    "bool": {
                        "must": [
                            {"bool": {"should": [
                                {"wildcard": {"rule.description": "*installed*"}},
                                {"wildcard": {"rule.description": "*success*"}},
                                {"terms": {"data.win.system.eventID": ["19", "43"]}}
                            ]}}
                        ]
                    }
                })
        
        # Execute search
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query
        )
        
        # Extract results
        total_patch_events = response["aggregations"]["total_count"]["value"]
        
        # Process aggregation results
        timeline_agg = response.get("aggregations", {}).get("patch_timeline", {})
        hosts_agg = response.get("aggregations", {}).get("hosts_patch_status", {})
        events_agg = response.get("aggregations", {}).get("patch_event_analysis", {})
        kb_agg = response.get("aggregations", {}).get("kb_pattern_analysis", {})
        integrity_agg = response.get("aggregations", {}).get("system_integrity_changes", {})
        
        # Process patch timeline
        patch_timeline = []
        for bucket in timeline_agg.get("buckets", []):
            date = bucket["key_as_string"]
            event_count = bucket["doc_count"]
            affected_hosts = bucket.get("affected_hosts", {}).get("value", 0)
            
            patch_types = [type_bucket["key"] for type_bucket in bucket.get("patch_types", {}).get("buckets", [])]
            
            patch_timeline.append({
                "date": date,
                "patch_events": event_count,
                "affected_hosts": affected_hosts,
                "patch_types": patch_types
            })
        
        # Process host patch status
        host_patch_status = []
        for bucket in hosts_agg.get("buckets", [])[:limit]:
            host = bucket["key"]
            total_patch_events = bucket["doc_count"]
            
            # Get host IP
            host_ips = [ip_bucket["key"] for ip_bucket in bucket.get("host_ip", {}).get("buckets", [])]
            host_ip = host_ips[0] if host_ips else "Unknown"
            
            # Process patch events for this host
            patch_events = []
            for event_bucket in bucket.get("patch_events", {}).get("buckets", []):
                event_description = event_bucket["key"]
                event_count = event_bucket["doc_count"]
                
                # Get rule groups
                rule_groups = [group_bucket["key"] for group_bucket in event_bucket.get("rule_groups", {}).get("buckets", [])]
                
                # Get latest event timestamp
                latest_timestamp = ""
                latest_hits = event_bucket.get("latest_event", {}).get("hits", {}).get("hits", [])
                if latest_hits:
                    latest_timestamp = latest_hits[0]["_source"].get("@timestamp", "")
                
                # Classify patch event type
                event_type = _classify_patch_event(event_description, rule_groups)
                
                # Extract KB numbers if present
                kb_numbers = re.findall(r'KB\d{6,7}', event_description, re.IGNORECASE)
                
                patch_events.append({
                    "event_description": event_description,
                    "event_count": event_count,
                    "event_type": event_type,
                    "rule_groups": rule_groups,
                    "kb_numbers": kb_numbers,
                    "latest_occurrence": latest_timestamp
                })
            
            # Get Windows update events
            windows_updates = []
            update_hits = bucket.get("windows_updates", {}).get("update_events", {}).get("hits", {}).get("hits", [])
            for hit in update_hits:
                source = hit["_source"]
                windows_updates.append({
                    "timestamp": source.get("@timestamp", ""),
                    "description": source.get("rule", {}).get("description", ""),
                    "event_id": source.get("data", {}).get("win", {}).get("system", {}).get("eventID", "")
                })
            
            # Count failed updates and security updates
            failed_updates_count = bucket.get("failed_updates", {}).get("doc_count", 0)
            security_updates_count = bucket.get("security_updates", {}).get("doc_count", 0)
            
            # Calculate patch status score
            patch_score = _calculate_patch_status_score(
                total_patch_events, failed_updates_count, security_updates_count, len(patch_events)
            )
            
            host_patch_status.append({
                "host": host,
                "host_ip": host_ip,
                "total_patch_events": total_patch_events,
                "patch_events": patch_events[:15],  # Top 15 events
                "windows_updates": windows_updates[:10],
                "failed_updates_count": failed_updates_count,
                "security_updates_count": security_updates_count,
                "patch_status_score": patch_score,
                "patch_health": _get_patch_health_status(patch_score)
            })
        
        # Process patch event analysis
        patch_event_analysis = []
        for bucket in events_agg.get("buckets", []):
            event_description = bucket["key"]
            frequency = bucket["doc_count"]
            host_coverage = bucket.get("host_coverage", {}).get("value", 0)
            
            # Get rule groups
            rule_groups = [group_bucket["key"] for group_bucket in bucket.get("rule_info", {}).get("buckets", [])]
            
            # Get sample events
            sample_events = []
            sample_hits = bucket.get("sample_events", {}).get("hits", {}).get("hits", [])
            for hit in sample_hits:
                source = hit["_source"]
                sample_events.append({
                    "timestamp": source.get("@timestamp", ""),
                    "host": source.get("agent", {}).get("name", ""),
                    "severity": source.get("rule", {}).get("level", 0)
                })
            
            # Extract KB numbers and classify event
            kb_numbers = re.findall(r'KB\d{6,7}', event_description, re.IGNORECASE)
            event_type = _classify_patch_event(event_description, rule_groups)
            
            patch_event_analysis.append({
                "event_description": event_description,
                "event_type": event_type,
                "frequency": frequency,
                "host_coverage": host_coverage,
                "kb_numbers": kb_numbers,
                "rule_groups": rule_groups,
                "sample_events": sample_events
            })
        
        # Process KB pattern analysis
        kb_analysis = []
        kb_events_agg = kb_agg.get("kb_events", {})
        for bucket in kb_events_agg.get("buckets", []):
            kb_description = bucket["key"]
            frequency = bucket["doc_count"]
            affected_hosts = bucket.get("affected_hosts", {}).get("value", 0)
            
            # Extract KB numbers
            kb_numbers = re.findall(r'KB\d{6,7}', kb_description, re.IGNORECASE)
            
            kb_analysis.append({
                "kb_description": kb_description,
                "kb_numbers": kb_numbers,
                "frequency": frequency,
                "affected_hosts": affected_hosts
            })
        
        # Process system integrity changes
        integrity_changes = []
        for bucket in integrity_agg.get("integrity_hosts", {}).get("buckets", []):
            host = bucket["key"]
            change_count = bucket["doc_count"]
            
            change_types = [change_bucket["key"] for change_bucket in bucket.get("change_types", {}).get("buckets", [])]
            
            integrity_changes.append({
                "host": host,
                "change_count": change_count,
                "change_types": change_types[:10]  # Top 10 change types
            })
        
        # Sort results
        host_patch_status.sort(key=lambda x: x["patch_status_score"], reverse=True)
        patch_event_analysis.sort(key=lambda x: x["frequency"], reverse=True)
        kb_analysis.sort(key=lambda x: x["affected_hosts"], reverse=True)
        
        # Extract all KB numbers found
        all_kb_numbers = set()
        for host in host_patch_status:
            for event in host["patch_events"]:
                all_kb_numbers.update(event["kb_numbers"])
        for event in patch_event_analysis:
            all_kb_numbers.update(event["kb_numbers"])
        
        # Build result
        result = {
            "search_parameters": {
                "patch_status": patch_status,
                "timeframe": timeframe,
                "entity_filter": entity_filter
            },
            "total_patch_events": total_patch_events,
            "analysis_summary": {
                "hosts_analyzed": len(host_patch_status),
                "kb_numbers_identified": list(all_kb_numbers),
                "total_kb_numbers": len(all_kb_numbers),
                "patch_event_types": len(patch_event_analysis),
                "integrity_changes_detected": len(integrity_changes)
            },
            "patch_timeline": patch_timeline[:30],  # Last 30 days
            "host_patch_status": host_patch_status[:limit],
            "patch_event_analysis": patch_event_analysis[:20],
            "kb_analysis": kb_analysis[:20],
            "system_integrity_changes": integrity_changes[:20],
            "patch_compliance_summary": _generate_patch_compliance_summary(host_patch_status),
            "recommendations": _generate_patch_recommendations(host_patch_status, patch_event_analysis, all_kb_numbers)
        }
        
        logger.info("Patch status check completed", 
                   total_events=total_patch_events,
                   hosts_analyzed=len(host_patch_status),
                   kb_numbers_found=len(all_kb_numbers))
        
        return result
        
    except Exception as e:
        logger.error("Patch status check failed", error=str(e))
        raise Exception(f"Failed to check patch status: {str(e)}")


def _classify_patch_event(description: str, groups: List[str]) -> str:
    """Classify the type of patch event based on description and groups"""
    description_lower = description.lower()
    
    if any(keyword in description_lower for keyword in ["failed", "error", "unsuccessful"]):
        return "Failed Update/Patch"
    elif any(keyword in description_lower for keyword in ["installed", "success", "completed"]):
        return "Successful Update/Patch"
    elif any(keyword in description_lower for keyword in ["security update", "security patch"]):
        return "Security Update"
    elif "kb" in description_lower and any(keyword in description_lower for keyword in ["windows", "microsoft"]):
        return "Windows KB Update"
    elif any(keyword in description_lower for keyword in ["hotfix", "critical update"]):
        return "Critical Hotfix"
    elif any(group in ["syscheck", "rootcheck"] for group in groups):
        return "System Integrity Change"
    elif "registry" in description_lower:
        return "Registry Modification"
    else:
        return "General Update Event"


def _calculate_patch_status_score(total_events: int, failed_count: int, security_count: int, event_types: int) -> float:
    """Calculate patch status health score for a host"""
    score = 50.0  # Base score
    
    # Positive factors
    score += min(security_count * 5, 30)  # Security updates boost score
    score += min(total_events * 0.5, 20)  # Update activity is good
    
    # Negative factors
    score -= min(failed_count * 10, 40)  # Failed updates hurt score
    
    # Diversity factor
    score += min(event_types * 2, 10)  # Variety of patch events
    
    return max(0, min(score, 100))  # Clamp between 0-100


def _get_patch_health_status(score: float) -> str:
    """Convert patch status score to health status"""
    if score >= 80:
        return "Excellent"
    elif score >= 65:
        return "Good"
    elif score >= 50:
        return "Fair"
    elif score >= 30:
        return "Poor"
    else:
        return "Critical"


def _generate_patch_compliance_summary(host_status: List[Dict]) -> Dict[str, Any]:
    """Generate patch compliance summary"""
    if not host_status:
        return {"overall_compliance": "Unknown", "host_distribution": {}}
    
    health_distribution = {}
    for host in host_status:
        health = host["patch_health"]
        health_distribution[health] = health_distribution.get(health, 0) + 1
    
    # Determine overall compliance
    excellent_count = health_distribution.get("Excellent", 0)
    good_count = health_distribution.get("Good", 0)
    total_hosts = len(host_status)
    
    if (excellent_count + good_count) / total_hosts >= 0.8:
        overall_compliance = "High"
    elif (excellent_count + good_count) / total_hosts >= 0.6:
        overall_compliance = "Medium"
    else:
        overall_compliance = "Low"
    
    return {
        "overall_compliance": overall_compliance,
        "host_distribution": health_distribution,
        "total_hosts_analyzed": total_hosts,
        "compliant_hosts": excellent_count + good_count,
        "compliance_percentage": round(((excellent_count + good_count) / total_hosts) * 100, 2)
    }


def _generate_patch_recommendations(host_status: List[Dict], event_analysis: List[Dict], kb_numbers: List[str]) -> List[str]:
    """Generate actionable patch management recommendations"""
    recommendations = []
    
    if host_status:
        critical_hosts = [h for h in host_status if h["patch_health"] in ["Critical", "Poor"]]
        if critical_hosts:
            recommendations.append(f"Immediate attention required for {len(critical_hosts)} hosts with poor patch status")
        
        failed_updates = sum(h["failed_updates_count"] for h in host_status)
        if failed_updates > 0:
            recommendations.append(f"Investigate {failed_updates} failed update attempts across environment")
    
    if event_analysis:
        failed_events = [e for e in event_analysis if e["event_type"] == "Failed Update/Patch"]
        if failed_events:
            recommendations.append(f"Address {len(failed_events)} types of recurring update failures")
    
    if kb_numbers:
        recommendations.append(f"Review patch status for {len(kb_numbers)} KB updates identified")
    
    if not recommendations:
        recommendations.append("Patch management appears healthy - continue monitoring")
    
    return recommendations