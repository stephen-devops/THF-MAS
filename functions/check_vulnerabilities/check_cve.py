"""
Check for specific CVE (Common Vulnerabilities and Exposures) references in Wazuh alerts
"""
from typing import Dict, Any, List
import structlog
from datetime import datetime, timedelta
import re

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check for specific CVE references in Wazuh alerts and analyze their impact
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including cve_id, timeframe, severity
        
    Returns:
        CVE analysis results with affected hosts, alert details, and impact assessment
    """
    try:
        # Extract parameters
        cve_id = params.get("cve_id", None)
        timeframe = params.get("timeframe", "90d")
        severity = params.get("severity", None)
        limit = params.get("limit", 100)
        
        logger.info("Checking CVE references", 
                   cve_id=cve_id,
                   timeframe=timeframe,
                   severity=severity)
        
        # Build CVE search patterns
        cve_patterns = []
        if cve_id:
            # Normalize CVE ID format
            cve_id_normalized = cve_id.upper().replace("CVE-", "").replace("CVE", "")
            if not cve_id_normalized.startswith("CVE-"):
                cve_id_normalized = f"CVE-{cve_id_normalized}"
            
            cve_patterns = [
                cve_id_normalized,
                cve_id_normalized.lower(),
                cve_id.upper(),
                cve_id.lower()
            ]
        
        # Build base query for CVE-related alerts
        base_conditions = [opensearch_client.build_single_time_filter(timeframe)]
        
        # CVE-specific search conditions
        cve_conditions = []
        if cve_id:
            for pattern in cve_patterns:
                cve_conditions.extend([
                    {"wildcard": {"rule.description": f"*{pattern}*"}},
                    {"wildcard": {"rule.description": f"*{pattern}*"}},
                    {"match": {"rule.description": pattern}}
                ])
        else:
            # General CVE pattern search
            cve_conditions = [
                {"wildcard": {"rule.description": "*CVE-*"}},
                {"wildcard": {"rule.description": "*cve-*"}},
                {"regexp": {"rule.description": ".*CVE-[0-9]{4}-[0-9]{4,7}.*"}}
            ]
        
        query = {
            "query": {
                "bool": {
                    "must": base_conditions,
                    "should": cve_conditions,
                    "minimum_should_match": 1 if cve_conditions else 0
                }
            },
            "size": 0,
            "aggs": {
                "total_count": {
                    "value_count": {
                        "field": "_id"
                    }
                },
                "cve_alerts_timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1d",
                        "order": {"_key": "desc"}
                    },
                    "aggs": {
                        "unique_hosts": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "severity_levels": {
                            "terms": {
                                "field": "rule.level",
                                "size": 10
                            }
                        }
                    }
                },
                "affected_hosts": {
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
                        "cve_rules": {
                            "terms": {
                                "field": "rule.id",
                                "size": 20
                            },
                            "aggs": {
                                "rule_description": {
                                    "terms": {
                                        "field": "rule.description",
                                        "size": 1
                                    }
                                },
                                "rule_groups": {
                                    "terms": {
                                        "field": "rule.groups",
                                        "size": 10
                                    }
                                },
                                "severity_distribution": {
                                    "terms": {
                                        "field": "rule.level",
                                        "size": 10
                                    }
                                },
                                "latest_occurrence": {
                                    "top_hits": {
                                        "size": 1,
                                        "sort": [{"@timestamp": {"order": "desc"}}],
                                        "_source": ["@timestamp", "rule.level", "rule.description"]
                                    }
                                }
                            }
                        },
                        "alert_frequency": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1d",
                                "order": {"_key": "desc"}
                            }
                        }
                    }
                },
                "cve_rule_analysis": {
                    "terms": {
                        "field": "rule.description",
                        "size": 50
                    },
                    "aggs": {
                        "affected_host_count": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "rule_groups": {
                            "terms": {
                                "field": "rule.groups",
                                "size": 10
                            }
                        },
                        "severity_stats": {
                            "stats": {
                                "field": "rule.level"
                            }
                        },
                        "sample_alerts": {
                            "top_hits": {
                                "size": 5,
                                "sort": [{"@timestamp": {"order": "desc"}}],
                                "_source": ["@timestamp", "agent.name", "agent.ip", "rule.level", "rule.id"]
                            }
                        }
                    }
                },
                "severity_impact": {
                    "terms": {
                        "field": "rule.level",
                        "size": 15
                    },
                    "aggs": {
                        "unique_hosts": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "unique_rules": {
                            "cardinality": {
                                "field": "rule.id"
                            }
                        }
                    }
                }
            }
        }
        
        # Apply severity filter if specified
        if severity:
            severity_mapping = {
                "low": {"range": {"rule.level": {"lte": 4}}},
                "medium": {"range": {"rule.level": {"gte": 5, "lte": 7}}},
                "high": {"range": {"rule.level": {"gte": 8, "lte": 10}}},
                "critical": {"range": {"rule.level": {"gte": 11}}}
            }
            if severity.lower() in severity_mapping:
                query["query"]["bool"]["must"].append(severity_mapping[severity.lower()])
        
        # Execute search
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query
        )
        
        # Extract results
        total_alerts = response["aggregations"]["total_count"]["value"]
        
        # Process aggregation results
        timeline_agg = response.get("aggregations", {}).get("cve_alerts_timeline", {})
        hosts_agg = response.get("aggregations", {}).get("affected_hosts", {})
        rules_agg = response.get("aggregations", {}).get("cve_rule_analysis", {})
        severity_agg = response.get("aggregations", {}).get("severity_impact", {})
        
        # Process timeline data
        alert_timeline = []
        for bucket in timeline_agg.get("buckets", []):
            date = bucket["key_as_string"]
            alert_count = bucket["doc_count"]
            unique_hosts = bucket.get("unique_hosts", {}).get("value", 0)
            
            severity_breakdown = {}
            for sev_bucket in bucket.get("severity_levels", {}).get("buckets", []):
                level = sev_bucket["key"]
                count = sev_bucket["doc_count"]
                severity_breakdown[f"Level_{level}"] = count
            
            alert_timeline.append({
                "date": date,
                "alert_count": alert_count,
                "unique_hosts_affected": unique_hosts,
                "severity_breakdown": severity_breakdown
            })
        
        # Process affected hosts
        affected_hosts = []
        for bucket in hosts_agg.get("buckets", [])[:limit]:
            host = bucket["key"]
            total_cve_alerts = bucket["doc_count"]
            
            # Get host IP
            host_ips = [ip_bucket["key"] for ip_bucket in bucket.get("host_ip", {}).get("buckets", [])]
            host_ip = host_ips[0] if host_ips else "Unknown"
            
            # Process CVE rules for this host
            cve_rules = []
            for rule_bucket in bucket.get("cve_rules", {}).get("buckets", []):
                rule_id = rule_bucket["key"]
                rule_count = rule_bucket["doc_count"]
                
                # Get rule description
                rule_description = "Unknown"
                desc_buckets = rule_bucket.get("rule_description", {}).get("buckets", [])
                if desc_buckets:
                    rule_description = desc_buckets[0]["key"]
                
                # Get rule groups
                rule_groups = [group_bucket["key"] for group_bucket in rule_bucket.get("rule_groups", {}).get("buckets", [])]
                
                # Get latest occurrence
                latest_occurrence = ""
                latest_hits = rule_bucket.get("latest_occurrence", {}).get("hits", {}).get("hits", [])
                if latest_hits:
                    latest_occurrence = latest_hits[0]["_source"].get("@timestamp", "")
                
                # Extract CVE IDs from description
                cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', rule_description, re.IGNORECASE)
                
                cve_rules.append({
                    "rule_id": rule_id,
                    "rule_description": rule_description,
                    "rule_groups": rule_groups,
                    "alert_count": rule_count,
                    "cve_ids": cve_matches,
                    "latest_occurrence": latest_occurrence
                })
            
            # Process alert frequency
            alert_frequency = []
            for freq_bucket in bucket.get("alert_frequency", {}).get("buckets", []):
                date = freq_bucket["key_as_string"]
                count = freq_bucket["doc_count"]
                alert_frequency.append({"date": date, "count": count})
            
            affected_hosts.append({
                "host": host,
                "host_ip": host_ip,
                "total_cve_alerts": total_cve_alerts,
                "cve_rules": cve_rules,
                "alert_frequency": alert_frequency[:30],  # Last 30 days
                "risk_score": _calculate_cve_host_risk_score(total_cve_alerts, len(cve_rules), cve_rules)
            })
        
        # Process CVE rule analysis
        cve_rule_analysis = []
        for bucket in rules_agg.get("buckets", []):
            rule_description = bucket["key"]
            alert_count = bucket["doc_count"]
            affected_host_count = bucket.get("affected_host_count", {}).get("value", 0)
            
            # Get rule groups
            rule_groups = [group_bucket["key"] for group_bucket in bucket.get("rule_groups", {}).get("buckets", [])]
            
            # Get severity statistics
            severity_stats = bucket.get("severity_stats", {})
            avg_severity = severity_stats.get("avg", 0)
            max_severity = severity_stats.get("max", 0)
            
            # Extract CVE IDs
            cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', rule_description, re.IGNORECASE)
            
            # Get sample alerts
            sample_alerts = []
            sample_hits = bucket.get("sample_alerts", {}).get("hits", {}).get("hits", [])
            for hit in sample_hits:
                source = hit["_source"]
                sample_alerts.append({
                    "timestamp": source.get("@timestamp", ""),
                    "host": source.get("agent", {}).get("name", ""),
                    "host_ip": source.get("agent", {}).get("ip", ""),
                    "severity": source.get("rule", {}).get("level", 0),
                    "rule_id": source.get("rule", {}).get("id", "")
                })
            
            cve_rule_analysis.append({
                "rule_description": rule_description,
                "alert_count": alert_count,
                "affected_hosts": affected_host_count,
                "cve_ids": cve_matches,
                "rule_groups": rule_groups,
                "average_severity": round(avg_severity, 2),
                "max_severity": max_severity,
                "sample_alerts": sample_alerts,
                "impact_score": _calculate_rule_impact_score(alert_count, affected_host_count, max_severity)
            })
        
        # Process severity impact
        severity_impact = []
        for bucket in severity_agg.get("buckets", []):
            severity_level = bucket["key"]
            alert_count = bucket["doc_count"]
            unique_hosts = bucket.get("unique_hosts", {}).get("value", 0)
            unique_rules = bucket.get("unique_rules", {}).get("value", 0)
            
            severity_impact.append({
                "severity_level": severity_level,
                "severity_category": _get_severity_category(severity_level),
                "alert_count": alert_count,
                "unique_hosts_affected": unique_hosts,
                "unique_rules_triggered": unique_rules
            })
        
        # Sort results
        affected_hosts.sort(key=lambda x: x["risk_score"], reverse=True)
        cve_rule_analysis.sort(key=lambda x: x["impact_score"], reverse=True)
        severity_impact.sort(key=lambda x: x["severity_level"], reverse=True)
        
        # Extract unique CVEs found
        all_cve_ids = set()
        for host in affected_hosts:
            for rule in host["cve_rules"]:
                all_cve_ids.update(rule["cve_ids"])
        for rule_analysis in cve_rule_analysis:
            all_cve_ids.update(rule_analysis["cve_ids"])
        
        # Build result
        result = {
            "search_parameters": {
                "cve_id": cve_id,
                "timeframe": timeframe,
                "severity_filter": severity
            },
            "total_cve_alerts": total_alerts,
            "analysis_summary": {
                "unique_cves_found": list(all_cve_ids),
                "total_unique_cves": len(all_cve_ids),
                "hosts_affected": len(affected_hosts),
                "rules_triggered": len(cve_rule_analysis),
                "date_range_analyzed": f"{timeframe} from latest data"
            },
            "alert_timeline": alert_timeline[:30],  # Last 30 days
            "affected_hosts": affected_hosts[:limit],
            "cve_rule_analysis": cve_rule_analysis[:20],
            "severity_impact": severity_impact,
            "risk_assessment": _generate_cve_risk_assessment(total_alerts, len(affected_hosts), len(all_cve_ids), severity_impact),
            "recommendations": _generate_cve_recommendations(cve_id, all_cve_ids, affected_hosts, cve_rule_analysis)
        }
        
        logger.info("CVE check completed", 
                   total_alerts=total_alerts,
                   hosts_affected=len(affected_hosts),
                   cves_found=len(all_cve_ids))
        
        return result
        
    except Exception as e:
        logger.error("CVE check failed", error=str(e))
        raise Exception(f"Failed to check CVE references: {str(e)}")


def _calculate_cve_host_risk_score(total_alerts: int, rule_count: int, cve_rules: List[Dict]) -> float:
    """Calculate risk score for a host based on CVE-related factors"""
    score = 0.0
    
    # Base score from alert volume
    score += min(total_alerts * 2, 40)  # Cap at 40
    
    # Rule diversity factor
    score += rule_count * 3
    
    # CVE severity weighting
    for rule in cve_rules:
        # Estimate severity based on typical CVE rule levels
        if any("critical" in desc.lower() or "exploit" in desc.lower() for desc in [rule.get("rule_description", "")]):
            score += 20
        elif any("high" in desc.lower() for desc in [rule.get("rule_description", "")]):
            score += 10
        else:
            score += 5
    
    return min(score, 100)  # Cap at 100


def _calculate_rule_impact_score(alert_count: int, host_count: int, max_severity: float) -> float:
    """Calculate impact score for a CVE rule"""
    score = 0.0
    
    # Alert volume factor
    score += min(alert_count * 0.5, 30)
    
    # Host spread factor
    score += min(host_count * 2, 40)
    
    # Severity factor
    score += max_severity * 3
    
    return min(score, 100)  # Cap at 100


def _get_severity_category(severity_level: int) -> str:
    """Convert numeric severity to category"""
    if severity_level >= 11:
        return "Critical"
    elif severity_level >= 8:
        return "High" 
    elif severity_level >= 5:
        return "Medium"
    elif severity_level >= 3:
        return "Low"
    else:
        return "Info"


def _generate_cve_risk_assessment(total_alerts: int, hosts_affected: int, cves_found: int, severity_impact: List[Dict]) -> Dict[str, Any]:
    """Generate overall risk assessment"""
    risk_level = "Low"
    risk_factors = []
    
    # Determine risk level
    critical_alerts = sum(s["alert_count"] for s in severity_impact if s["severity_level"] >= 11)
    high_alerts = sum(s["alert_count"] for s in severity_impact if s["severity_level"] >= 8)
    
    if critical_alerts > 0:
        risk_level = "Critical"
        risk_factors.append(f"{critical_alerts} critical severity CVE alerts")
    elif high_alerts > 10:
        risk_level = "High"
        risk_factors.append(f"{high_alerts} high severity CVE alerts")
    elif hosts_affected > 20:
        risk_level = "Medium"
        risk_factors.append(f"{hosts_affected} hosts affected by CVE-related alerts")
    elif cves_found > 5:
        risk_level = "Medium"
        risk_factors.append(f"{cves_found} unique CVEs identified")
    
    if not risk_factors:
        risk_factors.append("Limited CVE-related security activity detected")
    
    return {
        "overall_risk_level": risk_level,
        "risk_factors": risk_factors,
        "total_alerts": total_alerts,
        "hosts_affected": hosts_affected,
        "unique_cves": cves_found
    }


def _generate_cve_recommendations(cve_id: str, all_cves: List[str], affected_hosts: List[Dict], rule_analysis: List[Dict]) -> List[str]:
    """Generate actionable recommendations based on CVE analysis"""
    recommendations = []
    
    if cve_id and all_cves:
        if cve_id.upper() in [cve.upper() for cve in all_cves]:
            recommendations.append(f"Confirmed presence of {cve_id} - immediate patching required")
        else:
            recommendations.append(f"No direct evidence of {cve_id} found in current alerts")
    
    if affected_hosts:
        high_risk_hosts = [h for h in affected_hosts if h["risk_score"] > 70]
        if high_risk_hosts:
            recommendations.append(f"Prioritize patching for {len(high_risk_hosts)} high-risk hosts")
    
    if rule_analysis:
        high_impact_rules = [r for r in rule_analysis if r["impact_score"] > 70]
        if high_impact_rules:
            recommendations.append(f"Investigate {len(high_impact_rules)} high-impact vulnerability patterns")
    
    if len(all_cves) > 10:
        recommendations.append(f"Comprehensive vulnerability assessment recommended - {len(all_cves)} CVEs detected")
    
    if not recommendations:
        recommendations.append("Continue monitoring for CVE-related security events")
    
    return recommendations