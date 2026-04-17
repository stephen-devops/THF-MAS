"""
Check Wazuh agent versions and identify outdated agents across the environment using Wazuh API
"""
from typing import Dict, Any, List
import structlog
import re
from collections import Counter
from functions._shared.wazuh_api_client import create_wazuh_api_client_from_env

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check agent versions and identify version compliance issues using Wazuh API
    
    Args:
        opensearch_client: OpenSearch client instance (kept for compatibility)
        params: Parameters including agent_id, version_requirements, timeframe
        
    Returns:
        Agent version analysis with compliance, outdated agents, and upgrade recommendations
    """
    try:
        # Extract parameters
        agent_id = params.get("agent_id", None)
        version_requirements = params.get("version_requirements", None)  # e.g., ">=4.5.0"
        timeframe = params.get("timeframe", "24h")
        limit = params.get("limit", 100)
        
        logger.info("Checking agent versions via Wazuh API", 
                   agent_id=agent_id,
                   version_requirements=version_requirements,
                   timeframe=timeframe)
        
        # Create Wazuh API client
        wazuh_api_client = create_wazuh_api_client_from_env()
        
        # Get agent information from Wazuh API
        if agent_id:
            # Search for specific agent (by ID, name, or IP)
            agent_data = await wazuh_api_client.search_agents(agent_id)
        else:
            # Get all agents
            agent_data = await wazuh_api_client.get_agents(limit=min(limit, 1000))
        
        agents = agent_data.get("agents", [])
        total_agents_found = agent_data.get("total_agents", 0)
        
        logger.info("Retrieved agents from Wazuh API for version analysis", count=len(agents))
        
        # Process agent version information
        agent_versions = []
        version_counter = Counter()
        
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
            
            # Count version occurrences
            if agent_version and agent_version != "Unknown":
                version_counter[agent_version] += 1
            
            # Analyze version compliance
            compliance_status = "Unknown"
            compliance_notes = []
            
            if agent_version != "Unknown":
                compliance_status, compliance_notes = _analyze_version_compliance(
                    agent_version, version_requirements
                )
            else:
                compliance_notes = ["Agent version not available from API"]
            
            # Estimate agent age based on version
            estimated_age = _estimate_agent_age(agent_version)
            
            # Determine version source
            version_source = "Wazuh API" if agent_version != "Unknown" else "Not Available"
            
            agent_versions.append({
                "agent_id": agent_id_value,
                "agent_name": agent_name,
                "agent_ip": agent_ip,
                "manager_name": manager_node,
                "version": agent_version,
                "version_source": version_source,
                "compliance_status": compliance_status,
                "compliance_notes": compliance_notes,
                "estimated_age_months": estimated_age,
                "last_keep_alive": last_keep_alive,
                "agent_status": agent_status,
                "os_info": os_info,
                "node_name": manager_node
            })
        
        # Group agents by manager for version distribution analysis
        manager_versions = {}
        for agent in agent_versions:
            manager = agent["manager_name"]
            if manager not in manager_versions:
                manager_versions[manager] = {
                    "manager_name": manager,
                    "total_agents": 0,
                    "versions": Counter(),
                    "active_agents": 0,
                    "disconnected_agents": 0
                }
            
            manager_versions[manager]["total_agents"] += 1
            manager_versions[manager]["versions"][agent["version"]] += 1
            
            if agent["agent_status"] == "active":
                manager_versions[manager]["active_agents"] += 1
            elif agent["agent_status"] == "disconnected":
                manager_versions[manager]["disconnected_agents"] += 1
        
        # Convert manager data to list format
        manager_summary = []
        for manager_data in manager_versions.values():
            # Get most common version for this manager
            most_common_version = manager_data["versions"].most_common(1)
            primary_version = most_common_version[0][0] if most_common_version else "Unknown"
            
            manager_summary.append({
                "manager_name": manager_data["manager_name"],
                "total_agents": manager_data["total_agents"],
                "active_agents": manager_data["active_agents"],
                "disconnected_agents": manager_data["disconnected_agents"],
                "primary_version": primary_version,
                "version_distribution": dict(manager_data["versions"].most_common(5)),
                "status": "Active" if manager_data["active_agents"] > 0 else "No Active Agents"
            })
        
        # Sort agents by compliance status and version
        agent_versions.sort(key=lambda x: (
            x["compliance_status"] == "Non-Compliant",
            x["version"] == "Unknown",
            -x["estimated_age_months"] if x["estimated_age_months"] else 0
        ))
        
        # Calculate summary statistics
        total_agents = len(agent_versions)
        compliant_agents = len([a for a in agent_versions if a["compliance_status"] == "Compliant"])
        non_compliant_agents = len([a for a in agent_versions if a["compliance_status"] == "Non-Compliant"])
        unknown_version_agents = len([a for a in agent_versions if a["version"] == "Unknown"])
        
        # Get most common versions across all agents
        common_versions = version_counter.most_common(10)
        
        # Build result using Wazuh API data
        result = {
            "search_parameters": {
                "agent_id": agent_id,
                "version_requirements": version_requirements,
                "timeframe": timeframe,
                "data_source": "wazuh_api"
            },
            "version_summary": {
                "total_agents": total_agents,
                "compliant_agents": compliant_agents,
                "non_compliant_agents": non_compliant_agents,
                "unknown_version_agents": unknown_version_agents,
                "compliance_rate": round((compliant_agents / total_agents) * 100, 2) if total_agents > 0 else 0
            },
            "agent_versions": agent_versions,
            "version_distribution": common_versions,
            "manager_versions": manager_summary,
            "compliance_assessment": _generate_version_compliance_assessment(
                compliant_agents, non_compliant_agents, unknown_version_agents, total_agents
            ),
            "upgrade_recommendations": _generate_upgrade_recommendations(
                agent_versions, common_versions, version_requirements
            )
        }
        
        logger.info("Agent version check completed via Wazuh API", 
                   total_agents=total_agents,
                   compliant_agents=compliant_agents,
                   non_compliant_agents=non_compliant_agents,
                   unknown_version_agents=unknown_version_agents)
        
        return result
        
    except Exception as e:
        logger.error("Agent version check failed", error=str(e))
        raise Exception(f"Failed to check agent versions: {str(e)}")


def _extract_version_from_description(description: str) -> str:
    """Extract version number from rule description"""
    # Common version patterns
    patterns = [
        r'wazuh.*?(\d+\.\d+\.\d+)',
        r'version.*?(\d+\.\d+\.\d+)', 
        r'v(\d+\.\d+\.\d+)',
        r'(\d+\.\d+\.\d+)',
        r'agent.*?(\d+\.\d+\.\d+)'
    ]
    
    description_lower = description.lower()
    for pattern in patterns:
        match = re.search(pattern, description_lower)
        if match:
            return match.group(1)
    
    return None


def _analyze_version_compliance(version: str, requirements: str) -> tuple:
    """Analyze if version meets requirements"""
    if not requirements or version == "Unknown":
        return "Unknown", ["Version requirements not specified"]
    
    # Parse version numbers
    try:
        version_parts = [int(x) for x in version.split('.')]
        
        # Simple compliance check (can be enhanced)
        if requirements.startswith(">="):
            required_version = requirements[2:].strip()
            required_parts = [int(x) for x in required_version.split('.')]
            
            if version_parts >= required_parts:
                return "Compliant", [f"Meets requirement {requirements}"]
            else:
                return "Non-Compliant", [f"Below required version {required_version}"]
        
        elif requirements.startswith("=="):
            required_version = requirements[2:].strip()
            if version == required_version:
                return "Compliant", [f"Matches required version"]
            else:
                return "Non-Compliant", [f"Version mismatch, requires {required_version}"]
        
        else:
            # Basic version assessment
            if version_parts[0] >= 4:  # Assume 4.x+ is modern
                return "Compliant", ["Modern version detected"]
            else:
                return "Non-Compliant", ["Legacy version detected"]
                
    except ValueError:
        return "Unknown", ["Unable to parse version number"]


def _estimate_agent_age(version: str) -> int:
    """Estimate agent age in months based on version"""
    if version == "Unknown":
        return None
    
    try:
        version_parts = [int(x) for x in version.split('.')]
        major, minor = version_parts[0], version_parts[1] if len(version_parts) > 1 else 0
        
        # Rough estimation based on Wazuh release timeline
        if major >= 5:
            return 0  # Very recent
        elif major == 4 and minor >= 5:
            return 6  # ~6 months
        elif major == 4 and minor >= 0:
            return 12  # ~1 year
        elif major == 3:
            return 24  # ~2 years
        else:
            return 36  # Very old
    except ValueError:
        return None


def _generate_version_compliance_assessment(compliant: int, non_compliant: int, unknown: int, total: int) -> Dict[str, Any]:
    """Generate overall version compliance assessment"""
    if total == 0:
        return {"assessment": "No agents analyzed", "risk_level": "Unknown"}
    
    compliance_rate = (compliant / total) * 100
    unknown_rate = (unknown / total) * 100
    
    if compliance_rate >= 95:
        assessment = "Excellent version compliance"
        risk_level = "Low"
    elif compliance_rate >= 80:
        assessment = "Good version compliance"
        risk_level = "Low"
    elif compliance_rate >= 60:
        assessment = "Acceptable version compliance"
        risk_level = "Medium"
    elif compliance_rate >= 40:
        assessment = "Poor version compliance"
        risk_level = "High"
    else:
        assessment = "Critical version compliance issues"
        risk_level = "Critical"
    
    # Adjust for unknown versions
    if unknown_rate > 30:
        risk_level = "High"
        assessment += " (many unknown versions)"
    
    return {
        "assessment": assessment,
        "risk_level": risk_level,
        "compliance_rate": round(compliance_rate, 2),
        "unknown_rate": round(unknown_rate, 2)
    }


def _generate_upgrade_recommendations(agent_versions: List[Dict], common_versions: List[tuple], version_requirements: str) -> List[str]:
    """Generate actionable upgrade recommendations"""
    recommendations = []
    
    # Count agents needing upgrades
    non_compliant = [a for a in agent_versions if a["compliance_status"] == "Non-Compliant"]
    unknown_versions = [a for a in agent_versions if a["version"] == "Unknown"]
    old_agents = [a for a in agent_versions if a["estimated_age_months"] and a["estimated_age_months"] > 12]
    
    if non_compliant:
        recommendations.append(f"Upgrade {len(non_compliant)} non-compliant agents to meet version requirements")
    
    if unknown_versions:
        recommendations.append(f"Investigate {len(unknown_versions)} agents with unknown versions")
    
    if old_agents:
        recommendations.append(f"Consider upgrading {len(old_agents)} agents older than 1 year")
    
    # Recommend standardization
    if len(common_versions) > 3:
        recommendations.append("Consider standardizing on a single agent version across the environment")
    
    if not recommendations:
        recommendations.append("Agent versions appear to be well maintained")
    
    return recommendations