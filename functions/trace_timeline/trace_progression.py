"""
Trace attack progression and evolution of events over time
"""
from typing import Dict, Any, List, Optional
import structlog
from datetime import datetime
from collections import defaultdict
import re
from functions._shared.time_parser import build_time_range_filter

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Trace how events progress and evolve over time, focusing on attack chains
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including start_time, end_time, entity, event_types
        
    Returns:
        Attack progression analysis with technique chains and evolution patterns
    """
    try:
        # Extract parameters
        start_time = params.get("start_time")
        end_time = params.get("end_time")
        entity = params.get("entity")
        event_types = params.get("event_types", [])
        limit = params.get("limit", 100)  # Reduced default limit for progression analysis
        
        logger.info("Executing attack progression tracing", 
                   start_time=start_time,
                   end_time=end_time,
                   entity=entity,
                   event_types=event_types)
        
        # Build time range filter
        time_filter = build_time_range_filter(start_time, end_time)
        
        # Build the search query focused on progression indicators
        query = {
            "track_total_hits": True,
            "query": {
                "bool": {
                    "must": [time_filter],
                    "should": [
                        # Prioritize critical severity events (higher weight)
                        {"range": {"rule.level": {"gte": 10}}},
                        # MITRE ATT&CK techniques (essential for progression)
                        {"exists": {"field": "rule.mitre.id"}},
                        # Critical security events only
                        {"terms": {"rule.groups": ["mitre", "attack"]}},
                        # High-value process events
                        {"bool": {"must": [
                            {"terms": {"rule.groups": ["audit", "process"]}},
                            {"range": {"rule.level": {"gte": 7}}}
                        ]}},
                        # Authentication failures and escalations
                        {"bool": {"must": [
                            {"terms": {"rule.groups": ["authentication", "pam", "ssh", "windows_security", "authentication_success", "authentication_failed"]}},
                            {"range": {"rule.level": {"gte": 5}}}
                        ]}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "sort": [
                {"@timestamp": {"order": "asc"}}
            ],
            "size": min(limit, 200),  # Hard cap for progression analysis
            "_source": [
                "@timestamp", "rule.description", "rule.level", "rule.id",
                "agent.name", "agent.id", "agent.ip", "manager.name",
                "data.srcip", "data.dstip", "data.srcuser", "data.dstuser",
                "data.command", "data.process", "data.protocol",
                "data.win.eventdata.commandLine", "data.win.eventdata.image",
                "data.win.eventdata.processName", "data.win.eventdata.targetUserName",
                "data.win.eventdata.targetFilename", "data.win.system.eventID",
                "rule.mitre.id", "rule.mitre.tactic", "rule.mitre.technique",
                "rule.groups", "location", "decoder.name"
            ]
        }
        
        # Apply entity filter if specified
        if entity:
            entity_filter = _build_entity_filter(entity)
            if entity_filter:
                query["query"]["bool"]["must"].append(entity_filter)
        
        # Apply event type filters if specified
        if event_types:
            event_type_filters = _build_event_type_filters(event_types)
            if event_type_filters:
                query["query"]["bool"]["must"].extend(event_type_filters)
        
        # Execute search
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query
        )
        
        # Process results
        hits = response.get("hits", {})
        # Get total count directly since no aggregations are used
        total_events = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else hits.get("total", 0)
        events = hits.get("hits", [])
        
        logger.info("Retrieved events for progression analysis", count=len(events), total=total_events)
        
        # Process events for progression analysis
        progression_events = []
        for hit in events:
            source = hit.get("_source", {})
            
            event_data = _extract_progression_event_data(source)
            progression_events.append(event_data)
        
        # Analyze attack progression
        progression_analysis = await _analyze_attack_progression(progression_events)
        
        # Build result
        result = {
            "search_parameters": {
                "start_time": start_time,
                "end_time": end_time,
                "entity": entity,
                "event_types": event_types,
                "view_type": "progression",
                "data_source": "opensearch_alerts"
            },
            "progression_summary": {
                "total_events": len(progression_events),
                "attack_chains": len(progression_analysis["attack_chains"]),
                "mitre_techniques": len(progression_analysis["mitre_progression"]),
                "severity_escalation": progression_analysis["severity_escalation"],
                "affected_entities": len(progression_analysis["entity_progression"])
            },
            "attack_chains": progression_analysis["attack_chains"],
            "mitre_progression": progression_analysis["mitre_progression"],
            "entity_progression": progression_analysis["entity_progression"],
            "technique_timeline": progression_analysis["technique_timeline"],
            "progression_events": progression_events,
            "risk_assessment": _assess_progression_risk(progression_analysis),
            "recommendations": _generate_progression_recommendations(progression_analysis)
        }
        
        logger.info("Attack progression tracing completed", 
                   total_events=len(progression_events),
                   attack_chains=len(progression_analysis["attack_chains"]),
                   mitre_techniques=len(progression_analysis["mitre_progression"]))
        
        return result
        
    except Exception as e:
        logger.error("Attack progression tracing failed", error=str(e))
        raise Exception(f"Failed to trace attack progression: {str(e)}")




def _parse_time_to_datetime(time_str: str) -> str:
    """Parse time string to full datetime string"""
    import re
    from datetime import datetime, date, timedelta
    
    # If it's already a full datetime, return as-is
    if 'T' in time_str:
        return time_str
    
    # Handle datetime format without T (YYYY-MM-DD HH:MM:SS or YYYY-MM-DD HH:MM)
    datetime_pattern = r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$'
    if re.match(datetime_pattern, time_str):
        if len(time_str.split(' ')[1].split(':')) == 2:
            # Add seconds if not provided and convert to ISO format
            return f"{time_str}:00".replace(' ', 'T')
        # Convert to ISO format with T separator
        return time_str.replace(' ', 'T')
    
    # Handle relative date terms with time
    if time_str.startswith('yesterday '):
        time_part = time_str.replace('yesterday ', '')
        time_pattern = r'^\d{2}:\d{2}(:\d{2})?$'
        if re.match(time_pattern, time_part):
            if len(time_part.split(':')) == 2:
                time_part += ':00'
            yesterday = date.today() - timedelta(days=1)
            return f"{yesterday.isoformat()}T{time_part}"
    
    if time_str.startswith('today '):
        time_part = time_str.replace('today ', '')
        time_pattern = r'^\d{2}:\d{2}(:\d{2})?$'
        if re.match(time_pattern, time_part):
            if len(time_part.split(':')) == 2:
                time_part += ':00'
            today = date.today()
            return f"{today.isoformat()}T{time_part}"
    
    # Handle "X days ago" format
    days_ago_pattern = r'^(\d+) days? ago$'
    match = re.match(days_ago_pattern, time_str)
    if match:
        days = int(match.group(1))
        target_date = date.today() - timedelta(days=days)
        return f"{target_date.isoformat()}T00:00:00"
    
    # Handle "a week ago", "2 weeks ago"
    weeks_ago_pattern = r'^(?:a|(\d+)) weeks? ago$'
    match = re.match(weeks_ago_pattern, time_str)
    if match:
        weeks = 1 if match.group(1) is None else int(match.group(1))
        target_date = date.today() - timedelta(weeks=weeks)
        return f"{target_date.isoformat()}T00:00:00"
    
    # Handle time-only format (HH:MM:SS or HH:MM)
    time_pattern = r'^\d{2}:\d{2}(:\d{2})?$'
    if re.match(time_pattern, time_str):
        if len(time_str.split(':')) == 2:
            time_str += ':00'
        # Use today's date with the specified time
        today = date.today()
        return f"{today.isoformat()}T{time_str}"
    
    # Handle date-only format (YYYY-MM-DD)
    date_pattern = r'^\d{4}-\d{2}-\d{2}$'
    if re.match(date_pattern, time_str):
        return f"{time_str}T00:00:00"
    
    # Handle relative time formats (fallback)
    if time_str.endswith(('h', 'd', 'm', 's')):
        # Check if it already has 'now-' prefix
        if time_str.startswith('now-'):
            return time_str  # Already in correct format
        elif time_str.startswith('-'):
            # Handle format like "-20m" -> "now-20m"
            return f"now{time_str}"  # Combine now with -20m
        else:
            return f"now-{time_str}"  # Add 'now-' prefix
    
    # Return as-is if unrecognized format
    return time_str


def _build_entity_filter(entity: str) -> Optional[Dict[str, Any]]:
    """Build entity filter based on entity identifier"""
    # Auto-detect entity type and build appropriate filter
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', entity):
        # IP address
        return {
            "bool": {
                "should": [
                    {"term": {"agent.ip": entity}},
                    {"term": {"data.srcip": entity}},
                    {"term": {"data.dstip": entity}}
                ]
            }
        }
    elif entity.isdigit():
        # Agent ID
        return {"term": {"agent.id": entity}}
    else:
        # Hostname or general entity
        return {
            "bool": {
                "should": [
                    {"wildcard": {"agent.name": f"*{entity}*"}},
                    {"wildcard": {"data.srcuser": f"*{entity}*"}},
                    {"wildcard": {"data.dstuser": f"*{entity}*"}},
                    {"wildcard": {"data.win.eventdata.targetUserName": f"*{entity}*"}},
                    {"wildcard": {"data.win.eventdata.subjectUserName": f"*{entity}*"}},
                    {"wildcard": {"data.win.eventdata.commandLine": f"*{entity}*"}},
                    {"wildcard": {"data.win.eventdata.image": f"*{entity}*"}}
                ]
            }
        }


def _build_event_type_filters(event_types: List[str]) -> List[Dict[str, Any]]:
    """Build filters for specific event types relevant to progression"""
    filters = []
    
    for event_type in event_types:
        event_type_lower = event_type.lower()
        
        if event_type_lower in ["initial_access", "reconnaissance"]:
            filters.append({
                "bool": {
                    "should": [
                        {"terms": {"rule.mitre.tactic": ["reconnaissance", "initial-access"]}},
                        {"terms": {"rule.groups": ["authentication", "ssh", "login", "windows_security", "authentication_success", "authentication_failed"]}}
                    ]
                }
            })
        elif event_type_lower in ["execution", "command"]:
            filters.append({
                "bool": {
                    "should": [
                        {"terms": {"rule.mitre.tactic": ["execution"]}},
                        {"exists": {"field": "data.command"}},
                        {"exists": {"field": "data.win.eventdata.commandLine"}},
                        {"exists": {"field": "data.win.eventdata.image"}}
                    ]
                }
            })
        elif event_type_lower in ["persistence", "privilege_escalation"]:
            filters.append({
                "terms": {"rule.mitre.tactic": ["persistence", "privilege-escalation"]}
            })
        elif event_type_lower in ["lateral_movement"]:
            filters.append({
                "terms": {"rule.mitre.tactic": ["lateral-movement"]}
            })
        elif event_type_lower in ["exfiltration", "impact"]:
            filters.append({
                "terms": {"rule.mitre.tactic": ["exfiltration", "impact"]}
            })
    
    return filters


def _extract_progression_event_data(source: Dict[str, Any]) -> Dict[str, Any]:
    """Extract relevant data for progression analysis"""
    timestamp = source.get("@timestamp", "")
    
    event_data = {
        "timestamp": timestamp,
        "formatted_time": _format_timestamp(timestamp),
        "rule_id": source.get("rule", {}).get("id", ""),
        "rule_description": source.get("rule", {}).get("description", ""),
        "rule_level": source.get("rule", {}).get("level", 0),
        "agent_name": source.get("agent", {}).get("name", ""),
        "agent_id": source.get("agent", {}).get("id", ""),
        "agent_ip": source.get("agent", {}).get("ip", ""),
        "location": source.get("location", ""),
        "rule_groups": source.get("rule", {}).get("groups", [])
    }
    
    # Extract progression-relevant data
    data = source.get("data", {})
    win_eventdata = data.get("win", {}).get("eventdata", {})
    
    event_data["progression_indicators"] = {
        "src_ip": data.get("srcip", ""),
        "dst_ip": data.get("dstip", ""),
        "src_user": data.get("srcuser", ""),
        "dst_user": data.get("dstuser", ""),
        "command": data.get("command", win_eventdata.get("commandLine", "")),
        "process": data.get("process", win_eventdata.get("image", win_eventdata.get("processName", ""))),
        "file_path": data.get("path", win_eventdata.get("targetFilename", "")),
        "protocol": data.get("protocol", ""),
        "target_user": win_eventdata.get("targetUserName", ""),
        "event_id": data.get("win", {}).get("system", {}).get("eventID", "")
    }
    
    # Extract MITRE ATT&CK information
    mitre = source.get("rule", {}).get("mitre", {})
    if mitre:
        event_data["mitre_attack"] = {
            "technique_id": mitre.get("id", []),
            "tactic": mitre.get("tactic", []),
            "technique": mitre.get("technique", [])
        }
    
    return event_data


async def _analyze_attack_progression(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze attack progression patterns"""
    
    # Initialize analysis structures
    attack_chains = []
    mitre_progression = defaultdict(list)
    entity_progression = defaultdict(list)
    technique_timeline = []
    severity_escalation = []
    
    # Track progression by entity
    for event in events:
        entity_key = event.get("agent_name", event.get("agent_ip", "unknown"))
        entity_progression[entity_key].append(event)
        
        # Track MITRE techniques
        if "mitre_attack" in event:
            for technique_id in event["mitre_attack"].get("technique_id", []):
                mitre_progression[technique_id].append(event)
                technique_timeline.append({
                    "technique_id": technique_id,
                    "technique_name": ", ".join(event["mitre_attack"].get("technique", [])),
                    "tactic": ", ".join(event["mitre_attack"].get("tactic", [])),
                    "timestamp": event["timestamp"],
                    "formatted_time": event["formatted_time"],
                    "entity": entity_key,
                    "severity": event["rule_level"]
                })
    
    # Identify attack chains (sequences of techniques on same entity)
    for entity, entity_events in entity_progression.items():
        if len(entity_events) > 1:
            # Sort by timestamp
            entity_events.sort(key=lambda x: x["timestamp"])
            
            # Look for MITRE technique chains
            mitre_chain = []
            for event in entity_events:
                if "mitre_attack" in event and event["mitre_attack"]["technique_id"]:
                    mitre_chain.extend([{
                        "technique_id": tid,
                        "technique_name": ", ".join(event["mitre_attack"].get("technique", [])),
                        "tactic": ", ".join(event["mitre_attack"].get("tactic", [])),
                        "timestamp": event["formatted_time"],
                        "severity": event["rule_level"]
                    } for tid in event["mitre_attack"]["technique_id"]])
            
            if len(mitre_chain) > 1:
                attack_chains.append({
                    "entity": entity,
                    "chain_length": len(mitre_chain),
                    "start_time": entity_events[0]["formatted_time"],
                    "end_time": entity_events[-1]["formatted_time"],
                    "max_severity": max([e["rule_level"] for e in entity_events]),
                    "technique_chain": mitre_chain,
                    "total_events": len(entity_events)
                })
    
    # Analyze severity escalation
    for i in range(1, len(events)):
        if events[i]["rule_level"] > events[i-1]["rule_level"]:
            severity_escalation.append({
                "from_severity": events[i-1]["rule_level"],
                "to_severity": events[i]["rule_level"],
                "time_diff_minutes": _calculate_time_diff(events[i-1]["timestamp"], events[i]["timestamp"]),
                "entity": events[i]["agent_name"],
                "escalation_trigger": events[i]["rule_description"]
            })
    
    # Sort technique timeline by timestamp
    technique_timeline.sort(key=lambda x: x["timestamp"])
    
    return {
        "attack_chains": attack_chains,
        "mitre_progression": dict(mitre_progression),
        "entity_progression": dict(entity_progression),
        "technique_timeline": technique_timeline,
        "severity_escalation": severity_escalation
    }


def _assess_progression_risk(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Assess risk level based on progression analysis"""
    
    risk_score = 0
    risk_factors = []
    
    # Attack chain analysis
    attack_chains = analysis.get("attack_chains", [])
    if attack_chains:
        max_chain_length = max([chain["chain_length"] for chain in attack_chains])
        if max_chain_length >= 5:
            risk_score += 30
            risk_factors.append(f"Complex attack chain detected ({max_chain_length} techniques)")
        elif max_chain_length >= 3:
            risk_score += 20
            risk_factors.append(f"Multi-stage attack detected ({max_chain_length} techniques)")
    
    # Severity escalation
    escalations = analysis.get("severity_escalation", [])
    critical_escalations = [e for e in escalations if e["to_severity"] >= 12]
    if critical_escalations:
        risk_score += 25
        risk_factors.append(f"{len(critical_escalations)} critical severity escalations")
    
    # MITRE technique diversity
    mitre_count = len(analysis.get("mitre_progression", {}))
    if mitre_count >= 10:
        risk_score += 20
        risk_factors.append(f"High technique diversity ({mitre_count} techniques)")
    elif mitre_count >= 5:
        risk_score += 10
        risk_factors.append(f"Moderate technique diversity ({mitre_count} techniques)")
    
    # Multi-entity impact
    entity_count = len(analysis.get("entity_progression", {}))
    if entity_count >= 5:
        risk_score += 15
        risk_factors.append(f"Multiple entities affected ({entity_count} entities)")
    
    # Determine risk level
    if risk_score >= 70:
        risk_level = "Critical"
    elif risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_factors": risk_factors if risk_factors else ["No significant risk factors identified"]
    }


def _generate_progression_recommendations(analysis: Dict[str, Any]) -> List[str]:
    """Generate recommendations based on progression analysis"""
    recommendations = []
    
    attack_chains = analysis.get("attack_chains", [])
    if attack_chains:
        high_severity_chains = [c for c in attack_chains if c["max_severity"] >= 10]
        if high_severity_chains:
            recommendations.append(f"Immediate investigation required for {len(high_severity_chains)} high-severity attack chains")
        
        multi_technique_chains = [c for c in attack_chains if c["chain_length"] >= 3]
        if multi_technique_chains:
            recommendations.append(f"Analyze {len(multi_technique_chains)} complex attack sequences for APT indicators")
    
    # MITRE technique recommendations
    mitre_techniques = len(analysis.get("mitre_progression", {}))
    if mitre_techniques >= 5:
        recommendations.append(f"Correlate {mitre_techniques} MITRE techniques for complete attack story reconstruction")
    
    # Entity-based recommendations
    entities = len(analysis.get("entity_progression", {}))
    if entities >= 3:
        recommendations.append(f"Investigate lateral movement across {entities} affected entities")
    
    # Escalation recommendations
    escalations = len(analysis.get("severity_escalation", []))
    if escalations > 0:
        recommendations.append(f"Review {escalations} severity escalation patterns for attack progression indicators")
    
    if not recommendations:
        recommendations.append("Progression analysis shows limited attack activity - continue monitoring")
    
    return recommendations


def _format_timestamp(timestamp: str) -> str:
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return timestamp


def _calculate_time_diff(timestamp1: str, timestamp2: str) -> int:
    """Calculate time difference in minutes"""
    try:
        dt1 = datetime.fromisoformat(timestamp1.replace('Z', '+00:00'))
        dt2 = datetime.fromisoformat(timestamp2.replace('Z', '+00:00'))
        return int(abs((dt2 - dt1).total_seconds() / 60))
    except (ValueError, AttributeError):
        return 0