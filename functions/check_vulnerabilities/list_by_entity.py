"""
List vulnerabilities and related security issues by entity (host/agent)
"""
from typing import Dict, Any, List
import structlog
from datetime import datetime, timedelta
import re

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    List vulnerabilities and security issues by specific entity (host/agent)
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including entity_filter, severity, timeframe
        
    Returns:
        Vulnerability listing results with CVE references, security alerts, and patch-related information
    """
    try:
        # Extract parameters
        entity_filter = params.get("entity_filter", None)
        severity = params.get("severity", None)
        timeframe = params.get("timeframe", "30d")
        limit = params.get("limit", 50)
        
        logger.info("Listing vulnerabilities by entity", 
                   entity_filter=entity_filter,
                   severity=severity,
                   timeframe=timeframe)
        
        # Build base query for vulnerability-related data
        query = {
            "query": {
                "bool": {
                    "must": [opensearch_client.build_single_time_filter(timeframe)],
                    "should": [
                        # CVE patterns in rule descriptions
                        {"wildcard": {"rule.description": "*CVE-*"}},
                        {"wildcard": {"rule.description": "*cve-*"}},
                        {"wildcard": {"rule.description": "*vulnerability*"}},
                        {"wildcard": {"rule.description": "*exploit*"}},
                        # Vulnerability-related rule groups
                        {"terms": {"rule.groups": ["vulnerability", "vulnerabilities", "cve", "exploit", "security_vulnerability"]}},
                        # Windows update/patch events
                        {"terms": {"rule.groups": ["windows", "system_audit", "policy_monitoring"]}},
                        {"range": {"rule.id": {"gte": 18100, "lte": 18199}}},  # Wazuh vulnerability detection rules
                        # System integrity monitoring that might catch patches
                        {"terms": {"rule.groups": ["syscheck", "rootcheck"]}},
                        # High severity alerts that could be vulnerability-related
                        {"bool": {"must": [{"range": {"rule.level": {"gte": 7}}}, {"wildcard": {"rule.description": "*security*"}}]}}
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
                "vulnerability_hosts": {
                    "terms": {
                        "field": "agent.name",
                        "size": 100
                    },
                    "aggs": {
                        "vulnerability_rules": {
                            "terms": {
                                "field": "rule.id",
                                "size": 50
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
                                "severity_levels": {
                                    "terms": {
                                        "field": "rule.level",
                                        "size": 15
                                    }
                                },
                                "latest_alert": {
                                    "top_hits": {
                                        "size": 1,
                                        "sort": [{"@timestamp": {"order": "desc"}}],
                                        "_source": ["@timestamp", "rule.level", "rule.description", "agent.ip"]
                                    }
                                }
                            }
                        },
                        "os_info": {
                            "terms": {
                                "field": "os.name",
                                "size": 5
                            }
                        },
                        "agent_ip": {
                            "terms": {
                                "field": "agent.ip",
                                "size": 1
                            }
                        },
                        "severity_summary": {
                            "terms": {
                                "field": "rule.level",
                                "size": 15
                            }
                        }
                    }
                },
                "cve_patterns": {
                    "filter": {
                        "wildcard": {"rule.description": "*CVE-*"}
                    },
                    "aggs": {
                        "cve_hosts": {
                            "terms": {
                                "field": "agent.name",
                                "size": 50
                            },
                            "aggs": {
                                "cve_alerts": {
                                    "top_hits": {
                                        "size": 10,
                                        "sort": [{"@timestamp": {"order": "desc"}}],
                                        "_source": ["@timestamp", "rule.description", "rule.level", "agent.ip"]
                                    }
                                }
                            }
                        }
                    }
                },
                "high_severity_security": {
                    "filter": {
                        "bool": {
                            "must": [
                                {"range": {"rule.level": {"gte": 8}}},
                                {"wildcard": {"rule.description": "*security*"}}
                            ]
                        }
                    },
                    "aggs": {
                        "affected_hosts": {
                            "terms": {
                                "field": "agent.name",
                                "size": 30
                            },
                            "aggs": {
                                "security_issues": {
                                    "terms": {
                                        "field": "rule.description",
                                        "size": 20
                                    }
                                }
                            }
                        }
                    }
                },
                "patch_related": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"wildcard": {"rule.description": "*patch*"}},
                                {"wildcard": {"rule.description": "*update*"}},
                                {"wildcard": {"rule.description": "*hotfix*"}},
                                {"wildcard": {"rule.description": "*KB*"}},
                                {"terms": {"rule.groups": ["windows", "policy_monitoring"]}}
                            ],
                            "minimum_should_match": 1
                        }
                    },
                    "aggs": {
                        "patch_hosts": {
                            "terms": {
                                "field": "agent.name",
                                "size": 30
                            },
                            "aggs": {
                                "patch_events": {
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
        
        # Process vulnerability data by host
        vuln_hosts_agg = response.get("aggregations", {}).get("vulnerability_hosts", {})
        cve_patterns_agg = response.get("aggregations", {}).get("cve_patterns", {})
        high_severity_agg = response.get("aggregations", {}).get("high_severity_security", {})
        patch_related_agg = response.get("aggregations", {}).get("patch_related", {})
        
        # Parse vulnerability information by host
        vulnerability_hosts = []
        for bucket in vuln_hosts_agg.get("buckets", [])[:limit]:
            host = bucket["key"]
            total_vulnerability_alerts = bucket["doc_count"]
            
            # Get agent IP
            agent_ips = [ip_bucket["key"] for ip_bucket in bucket.get("agent_ip", {}).get("buckets", [])]
            agent_ip = agent_ips[0] if agent_ips else "Unknown"
            
            # Get OS info if available
            os_info = [os_bucket["key"] for os_bucket in bucket.get("os_info", {}).get("buckets", [])]
            operating_system = os_info[0] if os_info else "Unknown"
            
            # Process severity summary
            severity_breakdown = {}
            for sev_bucket in bucket.get("severity_summary", {}).get("buckets", []):
                level = sev_bucket["key"]
                count = sev_bucket["doc_count"]
                if level <= 4:
                    severity_breakdown["Low"] = severity_breakdown.get("Low", 0) + count
                elif level <= 7:
                    severity_breakdown["Medium"] = severity_breakdown.get("Medium", 0) + count
                elif level <= 10:
                    severity_breakdown["High"] = severity_breakdown.get("High", 0) + count
                else:
                    severity_breakdown["Critical"] = severity_breakdown.get("Critical", 0) + count
            
            # Process vulnerability rules
            vulnerability_rules = []
            for rule_bucket in bucket.get("vulnerability_rules", {}).get("buckets", []):
                rule_id = rule_bucket["key"]
                rule_count = rule_bucket["doc_count"]
                
                # Get rule description
                rule_description = "Unknown"
                desc_buckets = rule_bucket.get("rule_description", {}).get("buckets", [])
                if desc_buckets:
                    rule_description = desc_buckets[0]["key"]
                
                # Get rule groups
                rule_groups = [group_bucket["key"] for group_bucket in rule_bucket.get("rule_groups", {}).get("buckets", [])]
                
                # Get latest alert info
                latest_alert_info = {}
                latest_hits = rule_bucket.get("latest_alert", {}).get("hits", {}).get("hits", [])
                if latest_hits:
                    source = latest_hits[0]["_source"]
                    latest_alert_info = {
                        "timestamp": source.get("@timestamp", ""),
                        "severity": source.get("rule", {}).get("level", 0),
                        "description": source.get("rule", {}).get("description", "")
                    }
                
                # Extract CVE patterns from description
                cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', rule_description, re.IGNORECASE)
                
                vulnerability_rules.append({
                    "rule_id": rule_id,
                    "rule_description": rule_description,
                    "rule_groups": rule_groups,
                    "alert_count": rule_count,
                    "cve_references": cve_matches,
                    "latest_alert": latest_alert_info,
                    "vulnerability_type": _classify_vulnerability_type(rule_description, rule_groups)
                })
            
            # Sort rules by alert count
            vulnerability_rules.sort(key=lambda x: x["alert_count"], reverse=True)
            
            # Calculate risk score
            risk_score = _calculate_host_risk_score(severity_breakdown, len(vulnerability_rules), total_vulnerability_alerts)
            
            vulnerability_hosts.append({
                "host": host,
                "agent_ip": agent_ip,
                "operating_system": operating_system,
                "total_vulnerability_alerts": total_vulnerability_alerts,
                "severity_breakdown": severity_breakdown,
                "vulnerability_rules": vulnerability_rules[:10],  # Top 10 rules
                "risk_score": risk_score,
                "risk_level": _get_risk_level(risk_score)
            })
        
        # Parse CVE-specific information
        cve_findings = []
        cve_hosts_agg = cve_patterns_agg.get("cve_hosts", {})
        for bucket in cve_hosts_agg.get("buckets", []):
            host = bucket["key"]
            cve_alerts = []
            
            for hit in bucket.get("cve_alerts", {}).get("hits", {}).get("hits", []):
                source = hit["_source"]
                description = source.get("rule", {}).get("description", "")
                cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', description, re.IGNORECASE)
                
                cve_alerts.append({
                    "timestamp": source.get("@timestamp", ""),
                    "description": description,
                    "severity": source.get("rule", {}).get("level", 0),
                    "cve_ids": cve_matches
                })
            
            if cve_alerts:
                cve_findings.append({
                    "host": host,
                    "cve_alerts": cve_alerts
                })
        
        # Parse high severity security issues
        security_issues = []
        for bucket in high_severity_agg.get("affected_hosts", {}).get("buckets", []):
            host = bucket["key"]
            issues = [issue_bucket["key"] for issue_bucket in bucket.get("security_issues", {}).get("buckets", [])]
            
            security_issues.append({
                "host": host,
                "high_severity_issues": issues,
                "issue_count": len(issues)
            })
        
        # Parse patch-related information
        patch_information = []
        for bucket in patch_related_agg.get("patch_hosts", {}).get("buckets", []):
            host = bucket["key"]
            patch_events = [event_bucket["key"] for event_bucket in bucket.get("patch_events", {}).get("buckets", [])]
            
            patch_information.append({
                "host": host,
                "patch_events": patch_events,
                "event_count": len(patch_events)
            })
        
        # Sort hosts by risk score
        vulnerability_hosts.sort(key=lambda x: x["risk_score"], reverse=True)
        
        # Build result
        result = {
            "total_vulnerability_alerts": total_alerts,
            "analysis_period": timeframe,
            "entity_filter": entity_filter,
            "severity_filter": severity,
            "vulnerability_summary": {
                "hosts_with_vulnerabilities": len(vulnerability_hosts),
                "hosts_with_cves": len(cve_findings),
                "hosts_with_high_severity_issues": len(security_issues),
                "hosts_with_patch_activity": len(patch_information),
                "total_unique_cves": len(set([cve for finding in cve_findings for alert in finding["cve_alerts"] for cve in alert["cve_ids"]]))
            },
            "vulnerability_hosts": vulnerability_hosts[:limit],
            "cve_findings": cve_findings[:20],
            "security_issues": security_issues[:20],
            "patch_information": patch_information[:20],
            "recommendations": _generate_recommendations(vulnerability_hosts, cve_findings, security_issues)
        }
        
        logger.info("Vulnerability listing by entity completed", 
                   total_alerts=total_alerts,
                   hosts_analyzed=len(vulnerability_hosts))
        
        return result
        
    except Exception as e:
        logger.error("Vulnerability listing failed", error=str(e))
        raise Exception(f"Failed to list vulnerabilities by entity: {str(e)}")


def _classify_vulnerability_type(description: str, groups: List[str]) -> str:
    """Classify the type of vulnerability based on description and groups"""
    description_lower = description.lower()
    
    if any(group in ["exploit", "vulnerability"] for group in groups):
        return "Known Vulnerability"
    elif "cve-" in description_lower:
        return "CVE Reference"
    elif any(keyword in description_lower for keyword in ["privilege escalation", "elevation"]):
        return "Privilege Escalation"
    elif any(keyword in description_lower for keyword in ["buffer overflow", "stack overflow"]):
        return "Buffer Overflow"
    elif any(keyword in description_lower for keyword in ["injection", "sql", "command"]):
        return "Injection Attack"
    elif any(keyword in description_lower for keyword in ["authentication", "credential"]):
        return "Authentication Bypass"
    elif any(keyword in description_lower for keyword in ["denial of service", "dos"]):
        return "Denial of Service"
    elif "patch" in description_lower or "update" in description_lower:
        return "Patch/Update Issue"
    else:
        return "Security Alert"


def _calculate_host_risk_score(severity_breakdown: Dict[str, int], rule_count: int, total_alerts: int) -> float:
    """Calculate a risk score for a host based on vulnerability factors"""
    score = 0.0
    
    # Severity weighting
    score += severity_breakdown.get("Critical", 0) * 10
    score += severity_breakdown.get("High", 0) * 5
    score += severity_breakdown.get("Medium", 0) * 2
    score += severity_breakdown.get("Low", 0) * 1
    
    # Rule diversity factor
    score += rule_count * 2
    
    # Volume factor
    score += min(total_alerts * 0.1, 50)  # Cap volume contribution
    
    return min(score, 100)  # Cap at 100


def _get_risk_level(risk_score: float) -> str:
    """Convert risk score to risk level"""
    if risk_score >= 75:
        return "Critical"
    elif risk_score >= 50:
        return "High"
    elif risk_score >= 25:
        return "Medium"
    else:
        return "Low"


def _generate_recommendations(vuln_hosts: List[Dict], cve_findings: List[Dict], security_issues: List[Dict]) -> List[str]:
    """Generate security recommendations based on findings"""
    recommendations = []
    
    if vuln_hosts:
        critical_hosts = [h for h in vuln_hosts if h["risk_level"] == "Critical"]
        if critical_hosts:
            recommendations.append(f"Immediate attention required for {len(critical_hosts)} critical-risk hosts")
    
    if cve_findings:
        unique_cves = set([cve for finding in cve_findings for alert in finding["cve_alerts"] for cve in alert["cve_ids"]])
        recommendations.append(f"Review and patch {len(unique_cves)} identified CVEs across environment")
    
    if security_issues:
        recommendations.append(f"Investigate {len(security_issues)} hosts with high-severity security issues")
    
    if not recommendations:
        recommendations.append("No critical vulnerability patterns detected in current timeframe")
    
    return recommendations