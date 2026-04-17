"""
Check Wazuh agent connectivity and status across the environment using Wazuh API
"""
from typing import Dict, Any, List
import structlog
from datetime import datetime
from functions._shared.wazuh_api_client import create_wazuh_api_client_from_env

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check agent connectivity status and operational state using Wazuh API
    
    Args:
        opensearch_client: OpenSearch client instance (kept for compatibility)
        params: Parameters including agent_id, status_filter, timeframe
        
    Returns:
        Agent status results with connectivity, last activity, and operational state
    """
    try:
        # Extract parameters
        agent_id = params.get("agent_id", None)
        status_filter = params.get("status_filter", None)  # active, inactive, disconnected
        timeframe = params.get("timeframe", "24h")
        limit = params.get("limit", 100)
        
        logger.info("Checking agent status via Wazuh API", 
                   agent_id=agent_id,
                   status_filter=status_filter,
                   timeframe=timeframe)
        
        # Create Wazuh API client
        wazuh_api_client = create_wazuh_api_client_from_env()
        
        # Get agent information from Wazuh API
        if agent_id:
            # Search for specific agent (by ID, name, or IP)
            agent_data = await wazuh_api_client.search_agents(agent_id)
        else:
            # Get all agents
            agent_data = await wazuh_api_client.get_agents(
                status=status_filter, 
                limit=min(limit, 1000)  # Cap at 1000 for API limits
            )
        
        agents = agent_data.get("agents", [])
        total_agents_found = agent_data.get("total_agents", 0)
        
        logger.info("Retrieved agents from Wazuh API", count=len(agents))
        
        # Process agent status information
        agent_statuses = []
        status_counts = {"active": 0, "disconnected": 0, "never_connected": 0}
        
        now = datetime.utcnow()
        
        for agent in agents[:limit]:
            agent_id_value = agent.get("id", "000")
            agent_name = agent.get("name", f"Agent-{agent_id_value}")
            agent_ip = agent.get("ip", "Unknown")
            agent_status = agent.get("status", "unknown").lower()
            agent_version = agent.get("version", "Unknown")
            last_keep_alive = agent.get("lastKeepAlive", "")
            manager_node = agent.get("node_name", "Unknown")
            # Construct OS info from individual fields
            os_info = {
                "name": agent.get("os", {}).get("name") if isinstance(agent.get("os"), dict) else agent.get("os.name", "Unknown"),
                "platform": agent.get("os", {}).get("platform") if isinstance(agent.get("os"), dict) else agent.get("os.platform", "Unknown"), 
                "version": agent.get("os", {}).get("version") if isinstance(agent.get("os"), dict) else agent.get("os.version", "Unknown")
            }
            
            # Count statuses
            if agent_status in status_counts:
                status_counts[agent_status] += 1
            
            # Parse last keep alive time
            last_communication = None
            minutes_since_last = None
            
            if last_keep_alive and last_keep_alive != "n/a":
                try:
                    # Parse Wazuh timestamp format (e.g., "2024-01-15 10:30:25")
                    last_communication = datetime.strptime(last_keep_alive, "%Y-%m-%d %H:%M:%S")
                    minutes_since_last = int((now - last_communication).total_seconds() / 60)
                except ValueError:
                    try:
                        # Try ISO format as fallback
                        last_communication = datetime.fromisoformat(last_keep_alive.replace('Z', '+00:00')).replace(tzinfo=None)
                        minutes_since_last = int((now - last_communication).total_seconds() / 60)
                    except ValueError:
                        logger.warning("Failed to parse last_keep_alive", timestamp=last_keep_alive, agent_id=agent_id_value)
            
            # Map Wazuh API status to our status format
            if agent_status == "active":
                status = "Active"
                status_color = "Green"
            elif agent_status == "disconnected":
                status = "Inactive"
                status_color = "Red"
            elif agent_status == "never_connected":
                status = "Never Connected"
                status_color = "Gray"
            else:
                status = "Unknown"
                status_color = "Gray"
            
            # Calculate health score based on Wazuh API data
            health_score = _calculate_api_agent_health_score(
                agent_status, minutes_since_last, agent_version
            )
            
            # Apply status filter if specified
            if status_filter:
                filter_status = status_filter.lower()
                if filter_status == "active" and agent_status != "active":
                    continue
                elif filter_status in ["inactive", "disconnected"] and agent_status != "disconnected":
                    continue
                elif filter_status == "never_connected" and agent_status != "never_connected":
                    continue
            
            agent_statuses.append({
                "agent_id": agent_id_value,
                "agent_name": agent_name,
                "agent_ip": agent_ip,
                "manager_name": manager_node,
                "status": status,
                "status_color": status_color,
                "last_communication": last_keep_alive,
                "last_keep_alive": last_keep_alive,
                "minutes_since_last_activity": minutes_since_last,
                "version": agent_version,
                "os_info": {
                    "name": os_info.get("name", "Unknown"),
                    "platform": os_info.get("platform", "Unknown"),
                    "version": os_info.get("version", "Unknown")
                },
                "health_score": health_score,
                "health_status": _get_health_status(health_score),
                "api_status": agent_status,
                "node_name": manager_node
            })
        
        # Sort agents by status priority and health score
        priority_order = {"Never Connected": 0, "Inactive": 1, "Active": 2}
        agent_statuses.sort(key=lambda x: (priority_order.get(x["status"], 3), -x["health_score"]))
        
        # Calculate summary statistics
        total_agents = len(agent_statuses)
        active_agents = len([a for a in agent_statuses if a["status"] == "Active"])
        inactive_agents = len([a for a in agent_statuses if a["status"] == "Inactive"])
        never_connected_agents = len([a for a in agent_statuses if a["status"] == "Never Connected"])
        
        # Get manager summary by grouping agents
        manager_summary = {}
        for agent in agent_statuses:
            manager = agent["manager_name"]
            if manager not in manager_summary:
                manager_summary[manager] = {
                    "manager_name": manager,
                    "total_agents": 0,
                    "active_agents": 0,
                    "inactive_agents": 0
                }
            manager_summary[manager]["total_agents"] += 1
            if agent["status"] == "Active":
                manager_summary[manager]["active_agents"] += 1
            elif agent["status"] == "Inactive":
                manager_summary[manager]["inactive_agents"] += 1
        
        manager_distribution = list(manager_summary.values())
        
        # Build result using Wazuh API data
        result = {
            "search_parameters": {
                "agent_id": agent_id,
                "status_filter": status_filter,
                "timeframe": timeframe,
                "data_source": "wazuh_api"
            },
            "agent_summary": {
                "total_agents": total_agents,
                "active_agents": active_agents,
                "inactive_agents": inactive_agents,
                "never_connected_agents": never_connected_agents,
                "connectivity_rate": round((active_agents / total_agents) * 100, 2) if total_agents > 0 else 0
            },
            "agent_statuses": agent_statuses,
            "manager_distribution": manager_distribution,
            "api_summary": status_counts,
            "connectivity_assessment": _generate_api_connectivity_assessment(
                active_agents, inactive_agents, never_connected_agents, total_agents
            ),
            "recommendations": _generate_api_status_recommendations(
                agent_statuses, inactive_agents, never_connected_agents
            )
        }
        
        logger.info("Agent status check completed via Wazuh API", 
                   total_agents=total_agents,
                   active_agents=active_agents,
                   inactive_agents=inactive_agents,
                   never_connected=never_connected_agents)
        
        return result
        
    except Exception as e:
        logger.error("Agent status check failed", error=str(e))
        raise Exception(f"Failed to check agent status: {str(e)}")


def _calculate_api_agent_health_score(agent_status: str, minutes_since_last: int, agent_version: str) -> float:
    """Calculate health score for an agent based on Wazuh API data"""
    score = 50.0  # Base score
    
    # Status factor - primary indicator
    if agent_status == "active":
        score += 40
    elif agent_status == "disconnected":
        score -= 30
    elif agent_status == "never_connected":
        score -= 40
    
    # Time since last communication
    if minutes_since_last is not None:
        if minutes_since_last <= 5:
            score += 15  # Very recent communication
        elif minutes_since_last <= 30:
            score += 10  # Recent communication
        elif minutes_since_last <= 60:
            score += 5   # Within an hour
        elif minutes_since_last <= 1440:  # Within 24 hours
            score -= 5
        else:
            score -= min(minutes_since_last * 0.01, 20)  # Longer disconnection
    
    # Version factor - penalize unknown or very old versions
    if agent_version and agent_version != "Unknown":
        try:
            # Simple version scoring - newer versions get bonus
            if "4.5" in agent_version or "4.6" in agent_version or "4.7" in agent_version:
                score += 5  # Recent version bonus
            elif "4." in agent_version:
                score += 2  # Version 4.x is acceptable
            elif "3." in agent_version:
                score -= 5  # Older version
        except:
            pass
    else:
        score -= 10  # Unknown version is concerning
    
    return max(0, min(score, 100))  # Clamp between 0-100


def _calculate_agent_health_score(status: str, total_alerts: int, error_count: int, avg_severity: float, minutes_since_last: int) -> float:
    """Calculate health score for an agent (legacy function for OpenSearch data)"""
    score = 50.0  # Base score
    
    # Status factor
    if status == "Active":
        score += 40
    elif status == "Warning":
        score += 20
    elif status == "Inactive":
        score -= 30
    
    # Activity factor
    if total_alerts > 0:
        score += min(total_alerts * 0.1, 20)  # Cap at 20
    
    # Error factor
    if error_count > 0:
        score -= min(error_count * 2, 30)  # Cap penalty at 30
    
    # Severity factor
    score -= min(avg_severity * 2, 15)  # Higher avg severity reduces score
    
    # Time since last activity
    if minutes_since_last is not None:
        if minutes_since_last <= 15:
            score += 10
        elif minutes_since_last <= 60:
            score -= 5
        else:
            score -= min(minutes_since_last * 0.1, 25)
    
    return max(0, min(score, 100))  # Clamp between 0-100


def _get_health_status(score: float) -> str:
    """Convert health score to status"""
    if score >= 80:
        return "Excellent"
    elif score >= 60:
        return "Good"
    elif score >= 40:
        return "Fair"
    elif score >= 20:
        return "Poor"
    else:
        return "Critical"


def _generate_api_connectivity_assessment(active: int, inactive: int, never_connected: int, total: int) -> Dict[str, Any]:
    """Generate overall connectivity assessment based on Wazuh API data"""
    if total == 0:
        return {"assessment": "No agents found", "risk_level": "Unknown"}
    
    active_percentage = (active / total) * 100
    inactive_percentage = (inactive / total) * 100
    never_connected_percentage = (never_connected / total) * 100
    
    if active_percentage >= 95:
        assessment = "Excellent connectivity"
        risk_level = "Low"
    elif active_percentage >= 85:
        assessment = "Good connectivity"
        risk_level = "Low"
    elif active_percentage >= 70:
        assessment = "Acceptable connectivity"
        risk_level = "Medium"
    elif active_percentage >= 50:
        assessment = "Poor connectivity"
        risk_level = "High"
    else:
        assessment = "Critical connectivity issues"
        risk_level = "Critical"
    
    # Adjust for never connected agents
    if never_connected_percentage > 20:
        risk_level = "High"
        assessment += f" ({never_connected} agents never connected)"
    
    return {
        "assessment": assessment,
        "risk_level": risk_level,
        "active_percentage": round(active_percentage, 2),
        "inactive_percentage": round(inactive_percentage, 2),
        "never_connected_percentage": round(never_connected_percentage, 2)
    }


def _generate_api_status_recommendations(agent_statuses: List[Dict], inactive_count: int, never_connected_count: int) -> List[str]:
    """Generate actionable recommendations based on Wazuh API data"""
    recommendations = []
    
    if never_connected_count > 0:
        recommendations.append(f"Configure {never_connected_count} agents that have never connected to the Wazuh manager")
    
    if inactive_count > 0:
        recommendations.append(f"Investigate {inactive_count} disconnected agents - check network connectivity and agent services")
    
    # Find agents with old versions
    old_version_agents = [a for a in agent_statuses if a.get("version", "").startswith("3.")]
    if old_version_agents:
        recommendations.append(f"Upgrade {len(old_version_agents)} agents running legacy version 3.x")
    
    # Find agents disconnected for a long time
    long_disconnected = [a for a in agent_statuses if a.get("minutes_since_last_activity") and a["minutes_since_last_activity"] > 1440]
    if long_disconnected:
        recommendations.append(f"Review {len(long_disconnected)} agents disconnected for more than 24 hours")
    
    if not recommendations:
        recommendations.append("Agent connectivity and versions appear to be well maintained")
    
    return recommendations


def _generate_connectivity_assessment(active: int, warning: int, inactive: int, total: int) -> Dict[str, Any]:
    """Generate overall connectivity assessment"""
    if total == 0:
        return {"assessment": "No agents found", "risk_level": "Unknown"}
    
    active_percentage = (active / total) * 100
    inactive_percentage = (inactive / total) * 100
    
    if active_percentage >= 95:
        assessment = "Excellent connectivity"
        risk_level = "Low"
    elif active_percentage >= 85:
        assessment = "Good connectivity"
        risk_level = "Low"
    elif active_percentage >= 70:
        assessment = "Acceptable connectivity"
        risk_level = "Medium"
    elif active_percentage >= 50:
        assessment = "Poor connectivity"
        risk_level = "High"
    else:
        assessment = "Critical connectivity issues"
        risk_level = "Critical"
    
    return {
        "assessment": assessment,
        "risk_level": risk_level,
        "active_percentage": round(active_percentage, 2),
        "inactive_percentage": round(inactive_percentage, 2)
    }


def _generate_status_recommendations(agent_statuses: List[Dict], inactive_count: int, warning_count: int) -> List[str]:
    """Generate actionable recommendations"""
    recommendations = []
    
    if inactive_count > 0:
        recommendations.append(f"Investigate {inactive_count} inactive agents - check network connectivity and agent services")
    
    if warning_count > 0:
        recommendations.append(f"Monitor {warning_count} agents with intermittent connectivity")
    
    # Find agents with high error rates
    high_error_agents = [a for a in agent_statuses if a["error_alerts"] > 10]
    if high_error_agents:
        recommendations.append(f"Review {len(high_error_agents)} agents with high error alert rates")
    
    # Find agents with poor health scores
    poor_health_agents = [a for a in agent_statuses if a["health_score"] < 40]
    if poor_health_agents:
        recommendations.append(f"Address health issues for {len(poor_health_agents)} agents with poor health scores")
    
    if not recommendations:
        recommendations.append("Agent connectivity and health appear normal")
    
    return recommendations