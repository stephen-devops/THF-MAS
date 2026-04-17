"""
Check Wazuh agent operational health and performance metrics across the environment using Wazuh API
"""
from typing import Dict, Any, List
import structlog
from datetime import datetime
import re
from functions._shared.wazuh_api_client import create_wazuh_api_client_from_env

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check agent operational health and performance indicators using Wazuh API + OpenSearch
    
    Args:
        opensearch_client: OpenSearch client instance  
        params: Parameters including agent_id, timeframe, health_threshold
        
    Returns:
        Agent health analysis with performance metrics, error rates, and operational status
    """
    try:
        # Extract parameters
        agent_id = params.get("agent_id", None)
        timeframe = params.get("timeframe", "24h")
        health_threshold = params.get("health_threshold", 70.0)  # Health score threshold
        limit = params.get("limit", 100)
        
        logger.info("Checking agent health via Wazuh API + OpenSearch", 
                   agent_id=agent_id,
                   timeframe=timeframe,
                   health_threshold=health_threshold)
        
        # Create Wazuh API client for basic agent health
        wazuh_api_client = create_wazuh_api_client_from_env()
        
        # Get agent information from Wazuh API
        if agent_id:
            agent_data = await wazuh_api_client.search_agents(agent_id)
        else:
            agent_data = await wazuh_api_client.get_agents(limit=min(limit, 1000))
        
        agents = agent_data.get("agents", [])
        logger.info("Retrieved agents from Wazuh API for health analysis", count=len(agents))
        
        # Get detailed alert analysis from OpenSearch for health metrics
        alert_data = await _get_alert_health_data(opensearch_client, timeframe, agent_id)
        
        # Process agent health information
        agent_health_reports = []
        
        now = datetime.utcnow()
        
        for agent in agents[:limit]:
            agent_id_value = agent.get("id", "000")
            agent_name = agent.get("name", f"Agent-{agent_id_value}")
            agent_ip = agent.get("ip", "Unknown")
            agent_status = agent.get("status", "unknown").lower()
            agent_version = agent.get("version", "Unknown")
            last_keep_alive = agent.get("lastKeepAlive", "")
            manager_node = agent.get("node_name", "Unknown")
            os_info = {
                "name": agent.get("os", {}).get("name") if isinstance(agent.get("os"), dict) else agent.get("os.name", "Unknown"),
                "platform": agent.get("os", {}).get("platform") if isinstance(agent.get("os"), dict) else agent.get("os.platform", "Unknown"), 
                "version": agent.get("os", {}).get("version") if isinstance(agent.get("os"), dict) else agent.get("os.version", "Unknown")
            }
            
            # Parse last keep alive time for health calculation
            last_communication = None
            minutes_since_last = None
            
            if last_keep_alive and last_keep_alive != "n/a":
                try:
                    last_communication = datetime.strptime(last_keep_alive, "%Y-%m-%d %H:%M:%S")
                    minutes_since_last = int((now - last_communication).total_seconds() / 60)
                except ValueError:
                    try:
                        last_communication = datetime.fromisoformat(last_keep_alive.replace('Z', '+00:00')).replace(tzinfo=None)
                        minutes_since_last = int((now - last_communication).total_seconds() / 60)
                    except ValueError:
                        logger.warning("Failed to parse last_keep_alive for health", timestamp=last_keep_alive, agent_id=agent_id_value)
            
            # Get alert data for this agent from OpenSearch analysis
            agent_alert_data = alert_data.get(str(agent_id_value), {})
            
            # Calculate comprehensive health score
            health_score = _calculate_api_health_score(
                agent_status, minutes_since_last, agent_version,
                agent_alert_data.get("error_count", 0),
                agent_alert_data.get("critical_count", 0),
                agent_alert_data.get("total_alerts", 0),
                agent_alert_data.get("avg_severity", 0)
            )
            
            # Determine health status and risk factors
            health_status = _get_health_status(health_score)
            risk_factors = _identify_api_risk_factors(
                agent_status, minutes_since_last, agent_version,
                agent_alert_data.get("error_count", 0),
                agent_alert_data.get("critical_count", 0),
                agent_alert_data.get("connectivity_issues", 0)
            )
            
            agent_health_reports.append({
                "agent_id": agent_id_value,
                "agent_name": agent_name,
                "agent_ip": agent_ip,
                "manager_name": manager_node,
                "agent_status": agent_status,
                "version": agent_version,
                "last_keep_alive": last_keep_alive,
                "minutes_since_last_activity": minutes_since_last,
                "os_info": os_info,
                "health_score": health_score,
                "health_status": health_status,
                "risk_factors": risk_factors,
                # Alert-based metrics from OpenSearch
                "total_alerts": agent_alert_data.get("total_alerts", 0),
                "error_alerts": agent_alert_data.get("error_count", 0),
                "critical_alerts": agent_alert_data.get("critical_count", 0),
                "warning_alerts": agent_alert_data.get("warning_count", 0),
                "average_severity": agent_alert_data.get("avg_severity", 0),
                "connectivity_issues": agent_alert_data.get("connectivity_issues", 0),
                "configuration_issues": agent_alert_data.get("config_issues", 0),
                "performance_events": agent_alert_data.get("performance_events", []),
                "node_name": manager_node
            })
        
        # Sort agents by health score (worst first)
        agent_health_reports.sort(key=lambda x: x["health_score"])
        
        # Calculate overall health metrics
        total_agents = len(agent_health_reports)
        healthy_agents = len([a for a in agent_health_reports if a["health_score"] >= health_threshold])
        unhealthy_agents = total_agents - healthy_agents
        
        critical_health_agents = len([a for a in agent_health_reports if a["health_status"] == "Critical"])
        poor_health_agents = len([a for a in agent_health_reports if a["health_status"] == "Poor"])
        
        # Build comprehensive result
        result = {
            "search_parameters": {
                "agent_id": agent_id,
                "timeframe": timeframe, 
                "health_threshold": health_threshold,
                "data_source": "wazuh_api_with_opensearch_alerts"
            },
            "health_summary": {
                "total_agents": total_agents,
                "healthy_agents": healthy_agents,
                "unhealthy_agents": unhealthy_agents,
                "critical_health_agents": critical_health_agents,
                "poor_health_agents": poor_health_agents,
                "overall_health_percentage": round((healthy_agents / total_agents) * 100, 2) if total_agents > 0 else 0
            },
            "agent_health_reports": agent_health_reports,
            "environment_assessment": _generate_api_environment_health_assessment(
                healthy_agents, unhealthy_agents, critical_health_agents, total_agents
            ),
            "health_recommendations": _generate_api_health_recommendations(
                agent_health_reports, critical_health_agents, poor_health_agents
            )
        }
        
        logger.info("Agent health check completed via Wazuh API + OpenSearch", 
                   total_agents=total_agents,
                   healthy_agents=healthy_agents,
                   unhealthy_agents=unhealthy_agents,
                   critical_health_agents=critical_health_agents)
        
        return result
        
    except Exception as e:
        logger.error("Agent health check failed", error=str(e))
        raise Exception(f"Failed to check agent health: {str(e)}")


async def _get_alert_health_data(opensearch_client, timeframe: str, agent_id: str = None) -> Dict[str, Dict]:
    """Get alert-based health data from OpenSearch for detailed analysis"""
    try:
        # Build query for alert health analysis
        query = {
            "query": {
                "bool": {
                    "must": [opensearch_client.build_single_time_filter(timeframe)]
                }
            },
            "size": 0,
            "aggs": {
                "total_count": {
                    "value_count": {
                        "field": "_id"
                    }
                },
                "agents_health_analysis": {
                    "terms": {
                        "field": "agent.id",
                        "size": 1000
                    },
                    "aggs": {
                        "agent_info": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"@timestamp": {"order": "desc"}}],
                                "_source": ["agent.name", "agent.ip", "manager.name", "@timestamp"]
                            }
                        },
                        "activity_timeline": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1h",
                                "order": {"_key": "desc"}
                            }
                        },
                        "severity_analysis": {
                            "terms": {
                                "field": "rule.level",
                                "size": 15
                            }
                        },
                        "error_alerts": {
                            "filter": {
                                "range": {"rule.level": {"gte": 8}}
                            },
                            "aggs": {
                                "error_types": {
                                    "terms": {
                                        "field": "rule.description",
                                        "size": 20
                                    }
                                }
                            }
                        },
                        "critical_alerts": {
                            "filter": {
                                "range": {"rule.level": {"gte": 12}}
                            }
                        },
                        "warning_alerts": {
                            "filter": {
                                "range": {"rule.level": {"gte": 5, "lte": 7}}
                            }
                        },
                        "rule_groups_health": {
                            "terms": {
                                "field": "rule.groups",
                                "size": 30
                            }
                        },
                        "performance_indicators": {
                            "filter": {
                                "bool": {
                                    "should": [
                                        {"wildcard": {"rule.description": "*performance*"}},
                                        {"wildcard": {"rule.description": "*cpu*"}},
                                        {"wildcard": {"rule.description": "*memory*"}},
                                        {"wildcard": {"rule.description": "*disk*"}},
                                        {"wildcard": {"rule.description": "*load*"}},
                                        {"terms": {"rule.groups": ["system_audit", "performance"]}}
                                    ]
                                }
                            },
                            "aggs": {
                                "performance_events": {
                                    "terms": {
                                        "field": "rule.description",
                                        "size": 15
                                    }
                                }
                            }
                        },
                        "connectivity_issues": {
                            "filter": {
                                "bool": {
                                    "should": [
                                        {"wildcard": {"rule.description": "*connection*"}},
                                        {"wildcard": {"rule.description": "*network*"}},
                                        {"wildcard": {"rule.description": "*timeout*"}},
                                        {"wildcard": {"rule.description": "*disconnect*"}},
                                        {"terms": {"rule.groups": ["network", "connection"]}}
                                    ]
                                }
                            }
                        },
                        "configuration_issues": {
                            "filter": {
                                "bool": {
                                    "should": [
                                        {"wildcard": {"rule.description": "*configuration*"}},
                                        {"wildcard": {"rule.description": "*config*"}},
                                        {"wildcard": {"rule.description": "*invalid*"}},
                                        {"terms": {"rule.groups": ["config", "configuration"]}}
                                    ]
                                }
                            }
                        },
                        "source_ips": {
                            "terms": {
                                "field": "data.srcip",
                                "size": 10,
                                "missing": "unknown"
                            }
                        }
                    }
                },
                "environment_health": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "order": {"_key": "desc"}
                    },
                    "aggs": {
                        "unique_agents": {
                            "cardinality": {"field": "agent.id"}
                        },
                        "total_alerts": {
                            "value_count": {"field": "@timestamp"}
                        },
                        "avg_severity": {
                            "avg": {"field": "rule.level"}
                        },
                        "error_rate": {
                            "filter": {
                                "range": {"rule.level": {"gte": 8}}
                            }
                        }
                    }
                },
                "rule_health_distribution": {
                    "terms": {
                        "field": "rule.groups",
                        "size": 50
                    },
                    "aggs": {
                        "avg_severity": {
                            "avg": {"field": "rule.level"}
                        },
                        "agent_coverage": {
                            "cardinality": {"field": "agent.id"}
                        }
                    }
                },
                "system_health_indicators": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"terms": {"rule.groups": ["syscheck", "rootcheck", "system_audit"]}},
                                {"wildcard": {"rule.description": "*system*"}},
                                {"wildcard": {"rule.description": "*service*"}},
                                {"wildcard": {"rule.description": "*process*"}}
                            ]
                        }
                    },
                    "aggs": {
                        "system_events": {
                            "terms": {
                                "field": "rule.description",
                                "size": 25
                            },
                            "aggs": {
                                "affected_agents": {
                                    "cardinality": {"field": "agent.id"}
                                }
                            }
                        }
                    }
                }
            }
        }
        
        # Apply agent filter if specified
        if agent_id:
            # Auto-detect agent ID format
            if agent_id.isdigit():
                query["query"]["bool"]["must"].append({
                    "term": {"agent.id": agent_id}
                })
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', agent_id):
                query["query"]["bool"]["must"].append({
                    "term": {"agent.ip": agent_id}
                })
            else:
                query["query"]["bool"]["must"].append({
                    "wildcard": {"agent.name": f"*{agent_id}*"}
                })
        
        # Execute search
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query
        )
        
        # Extract results
        total_alerts = response["aggregations"]["total_count"]["value"]

        # Process aggregation results
        agents_agg = response.get("aggregations", {}).get("agents_health_analysis", {})
        
        # Return simplified alert health data for API integration
        alert_health_data = {}
        
        for bucket in agents_agg.get("buckets", []):
            agent_id_value = str(bucket["key"])
            agent_alert_count = bucket["doc_count"]
            
            # Process severity analysis
            severity_weighted_score = 0
            total_weighted = 0
            
            for sev_bucket in bucket.get("severity_analysis", {}).get("buckets", []):
                level = sev_bucket["key"]
                count = sev_bucket["doc_count"]
                severity_weighted_score += level * count
                total_weighted += count
            
            avg_severity = severity_weighted_score / total_weighted if total_weighted > 0 else 0
            
            # Get error and critical alerts
            error_count = bucket.get("error_alerts", {}).get("doc_count", 0)
            critical_count = bucket.get("critical_alerts", {}).get("doc_count", 0)
            warning_count = bucket.get("warning_alerts", {}).get("doc_count", 0)
            
            # Performance and connectivity issues
            performance_events = []
            perf_events_agg = bucket.get("performance_indicators", {}).get("performance_events", {})
            for perf_bucket in perf_events_agg.get("buckets", [])[:5]:
                performance_events.append({
                    "event": perf_bucket["key"],
                    "count": perf_bucket["doc_count"]
                })
            
            connectivity_issues = bucket.get("connectivity_issues", {}).get("doc_count", 0)
            config_issues = bucket.get("configuration_issues", {}).get("doc_count", 0)
            
            alert_health_data[agent_id_value] = {
                "total_alerts": agent_alert_count,
                "error_count": error_count,
                "critical_count": critical_count,
                "warning_count": warning_count,
                "avg_severity": round(avg_severity, 2),
                "connectivity_issues": connectivity_issues,
                "config_issues": config_issues,
                "performance_events": performance_events
            }
        
        return alert_health_data
        
    except Exception as e:
        logger.error("Agent health check failed", error=str(e))
        raise Exception(f"Failed to check agent health: {str(e)}")


def _calculate_comprehensive_health_score(
    total_alerts: int, error_count: int, critical_count: int, warning_count: int,
    avg_severity: float, connectivity_issues: int, config_issues: int,
    activity_variance: float, performance_events: int
) -> float:
    """Calculate comprehensive health score for an agent"""
    score = 100.0  # Start with perfect health
    
    # Activity level factor (healthy agents should have some activity)
    if total_alerts == 0:
        score -= 20  # No activity might indicate problems
    elif total_alerts > 0:
        score += min(5, total_alerts * 0.1)  # Reasonable activity is good
    
    # Error rate impact
    if total_alerts > 0:
        error_rate = error_count / total_alerts
        score -= min(30, error_rate * 100)  # Up to 30 points for errors
        
        critical_rate = critical_count / total_alerts
        score -= min(40, critical_rate * 200)  # Critical alerts heavily penalized
        
        warning_rate = warning_count / total_alerts
        score -= min(15, warning_rate * 50)  # Warnings moderately penalized
    
    # Severity impact
    score -= min(20, avg_severity * 2)  # Higher average severity reduces score
    
    # Connectivity issues
    score -= min(25, connectivity_issues * 5)
    
    # Configuration issues
    score -= min(20, config_issues * 4)
    
    # Activity variance (too much variance indicates instability)
    if activity_variance > 10:
        score -= min(15, activity_variance * 0.5)
    
    # Performance issues
    score -= min(10, performance_events * 2)
    
    return max(0, min(score, 100))  # Clamp between 0-100


def _get_health_status(score: float) -> str:
    """Convert health score to status"""
    if score >= 85:
        return "Excellent"
    elif score >= 70:
        return "Good"
    elif score >= 50:
        return "Fair"
    elif score >= 30:
        return "Poor"
    else:
        return "Critical"


def _identify_risk_factors(
    error_count: int, critical_count: int, connectivity_issues: int,
    config_issues: int, performance_events: List[Dict], avg_severity: float
) -> List[str]:
    """Identify specific risk factors for an agent"""
    risk_factors = []
    
    if critical_count > 0:
        risk_factors.append(f"{critical_count} critical alerts detected")
    
    if error_count > 5:
        risk_factors.append(f"High error rate ({error_count} error alerts)")
    
    if connectivity_issues > 0:
        risk_factors.append(f"{connectivity_issues} connectivity issues")
    
    if config_issues > 0:
        risk_factors.append(f"{config_issues} configuration problems")
    
    if performance_events:
        risk_factors.append(f"{len(performance_events)} performance issues detected")
    
    if avg_severity > 8:
        risk_factors.append(f"High average alert severity ({avg_severity:.1f})")
    
    if not risk_factors:
        risk_factors.append("No significant risk factors identified")
    
    return risk_factors


def _assess_rule_group_health(avg_severity: float, alert_count: int) -> str:
    """Assess health indicator for rule groups"""
    if avg_severity >= 10:
        return "Critical"
    elif avg_severity >= 8:
        return "High Risk"
    elif avg_severity >= 5:
        return "Medium Risk"
    elif alert_count > 1000:
        return "High Volume"
    else:
        return "Normal"


def _assess_system_event_impact(description: str, event_count: int, affected_agents: int) -> str:
    """Assess impact level of system events"""
    desc_lower = description.lower()
    
    if any(word in desc_lower for word in ["critical", "error", "failed", "corruption"]):
        return "High Impact"
    elif any(word in desc_lower for word in ["warning", "timeout", "slow"]):
        return "Medium Impact"
    elif affected_agents > 10:
        return "Widespread"
    elif event_count > 100:
        return "Frequent"
    else:
        return "Low Impact"


def _generate_environment_health_assessment(
    healthy: int, unhealthy: int, critical: int, total: int
) -> Dict[str, Any]:
    """Generate overall environment health assessment"""
    if total == 0:
        return {"assessment": "No agents analyzed", "risk_level": "Unknown"}
    
    health_rate = (healthy / total) * 100
    critical_rate = (critical / total) * 100
    
    if health_rate >= 95 and critical_rate == 0:
        assessment = "Excellent environment health"
        risk_level = "Low"
    elif health_rate >= 80 and critical_rate < 5:
        assessment = "Good environment health"
        risk_level = "Low"
    elif health_rate >= 60 and critical_rate < 10:
        assessment = "Acceptable environment health"
        risk_level = "Medium"
    elif health_rate >= 40:
        assessment = "Poor environment health"
        risk_level = "High"
    else:
        assessment = "Critical environment health issues"
        risk_level = "Critical"
    
    return {
        "assessment": assessment,
        "risk_level": risk_level,
        "health_percentage": round(health_rate, 2),
        "critical_percentage": round(critical_rate, 2)
    }


def _generate_health_recommendations(
    agent_reports: List[Dict], critical_count: int, poor_count: int
) -> List[str]:
    """Generate actionable health recommendations"""
    recommendations = []
    
    if critical_count > 0:
        recommendations.append(f"Immediate attention required for {critical_count} agents with critical health issues")
    
    if poor_count > 0:
        recommendations.append(f"Investigate {poor_count} agents with poor health scores")
    
    # Find common issues
    high_error_agents = [a for a in agent_reports if a["error_alerts"] > 10]
    if high_error_agents:
        recommendations.append(f"Address high error rates on {len(high_error_agents)} agents")
    
    connectivity_issues = [a for a in agent_reports if a["connectivity_issues"] > 0]
    if connectivity_issues:
        recommendations.append(f"Resolve network connectivity issues for {len(connectivity_issues)} agents")
    
    config_issues = [a for a in agent_reports if a["configuration_issues"] > 0]
    if config_issues:
        recommendations.append(f"Fix configuration problems on {len(config_issues)} agents")
    
    if not recommendations:
        recommendations.append("Agent health across the environment appears optimal")
    
    return recommendations


def _calculate_api_health_score(
    agent_status: str, minutes_since_last: int, agent_version: str,
    error_count: int, critical_count: int, total_alerts: int, avg_severity: float
) -> float:
    """Calculate health score based on Wazuh API data and OpenSearch alerts"""
    score = 50.0  # Base score
    
    # Agent connectivity status (primary factor)
    if agent_status == "active":
        score += 35
    elif agent_status == "disconnected":
        score -= 25
    elif agent_status == "never_connected":
        score -= 35
    
    # Time since last communication
    if minutes_since_last is not None:
        if minutes_since_last <= 5:
            score += 15  # Very recent communication
        elif minutes_since_last <= 30:
            score += 10
        elif minutes_since_last <= 60:
            score += 5
        elif minutes_since_last <= 1440:  # Within 24 hours
            score -= 5
        else:
            score -= min(minutes_since_last * 0.01, 20)
    
    # Version factor
    if agent_version and agent_version != "Unknown":
        if "4.5" in agent_version or "4.6" in agent_version or "4.7" in agent_version:
            score += 5
        elif "4." in agent_version:
            score += 2
        elif "3." in agent_version:
            score -= 5
    else:
        score -= 8
    
    # Alert-based health factors
    if total_alerts > 0:
        error_rate = error_count / total_alerts
        score -= min(20, error_rate * 100)
        
        critical_rate = critical_count / total_alerts
        score -= min(25, critical_rate * 150)
    
    # Severity impact
    score -= min(10, avg_severity * 1.5)
    
    return max(0, min(score, 100))


def _identify_api_risk_factors(
    agent_status: str, minutes_since_last: int, agent_version: str,
    error_count: int, critical_count: int, connectivity_issues: int
) -> List[str]:
    """Identify risk factors based on API and alert data"""
    risk_factors = []
    
    # Connectivity issues
    if agent_status == "disconnected":
        risk_factors.append("Agent is currently disconnected")
    elif agent_status == "never_connected":
        risk_factors.append("Agent has never connected to manager")
    
    # Communication timing
    if minutes_since_last is not None:
        if minutes_since_last > 1440:  # Over 24 hours
            risk_factors.append(f"No communication for {minutes_since_last // 60} hours")
        elif minutes_since_last > 60:
            risk_factors.append(f"Last communication {minutes_since_last} minutes ago")
    
    # Version concerns
    if agent_version == "Unknown":
        risk_factors.append("Agent version information not available")
    elif "3." in agent_version:
        risk_factors.append(f"Legacy agent version ({agent_version})")
    
    # Alert-based risks
    if critical_count > 0:
        risk_factors.append(f"{critical_count} critical alerts in monitoring period")
    
    if error_count > 5:
        risk_factors.append(f"High error rate ({error_count} error alerts)")
    
    if connectivity_issues > 0:
        risk_factors.append(f"{connectivity_issues} network connectivity alerts")
    
    if not risk_factors:
        risk_factors.append("No significant risk factors identified")
    
    return risk_factors


def _generate_api_environment_health_assessment(
    healthy: int, unhealthy: int, critical: int, total: int
) -> Dict[str, Any]:
    """Generate environment health assessment based on API data"""
    if total == 0:
        return {"assessment": "No agents found", "risk_level": "Unknown"}
    
    health_rate = (healthy / total) * 100
    critical_rate = (critical / total) * 100
    
    if health_rate >= 95 and critical_rate == 0:
        assessment = "Excellent agent health across environment"
        risk_level = "Low"
    elif health_rate >= 85 and critical_rate < 5:
        assessment = "Good agent health overall"
        risk_level = "Low"
    elif health_rate >= 70 and critical_rate < 10:
        assessment = "Acceptable agent health"
        risk_level = "Medium"
    elif health_rate >= 50:
        assessment = "Poor agent health detected"
        risk_level = "High"
    else:
        assessment = "Critical agent health issues"
        risk_level = "Critical"
    
    return {
        "assessment": assessment,
        "risk_level": risk_level,
        "health_percentage": round(health_rate, 2),
        "critical_percentage": round(critical_rate, 2)
    }


def _generate_api_health_recommendations(
    agent_reports: List[Dict], critical_count: int, poor_count: int
) -> List[str]:
    """Generate health recommendations based on API analysis"""
    recommendations = []
    
    if critical_count > 0:
        recommendations.append(f"Immediate attention required for {critical_count} agents with critical health issues")
    
    if poor_count > 0:
        recommendations.append(f"Investigate {poor_count} agents with poor health scores")
    
    # Specific API-based recommendations
    disconnected_agents = [a for a in agent_reports if a["agent_status"] == "disconnected"]
    if disconnected_agents:
        recommendations.append(f"Restore connectivity for {len(disconnected_agents)} disconnected agents")
    
    never_connected = [a for a in agent_reports if a["agent_status"] == "never_connected"]
    if never_connected:
        recommendations.append(f"Complete initial setup for {len(never_connected)} agents that never connected")
    
    old_versions = [a for a in agent_reports if a.get("version", "").startswith("3.")]
    if old_versions:
        recommendations.append(f"Upgrade {len(old_versions)} agents running legacy versions")
    
    long_silence = [a for a in agent_reports if a.get("minutes_since_last_activity") and a["minutes_since_last_activity"] > 1440]
    if long_silence:
        recommendations.append(f"Investigate {len(long_silence)} agents silent for over 24 hours")
    
    if not recommendations:
        recommendations.append("Agent health appears optimal across the environment")
    
    return recommendations
