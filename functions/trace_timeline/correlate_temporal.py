"""
Correlate events that occur within temporal proximity for relationship analysis
"""
from typing import Dict, Any, List, Optional
import structlog
from datetime import datetime
from collections import defaultdict
import re
from ._shared.event_type_mapper import build_smart_event_filters
from functions._shared.time_parser import build_time_range_filter

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlate events that occur within temporal proximity to identify relationships
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including start_time, end_time, entity, event_types, correlation_window
        
    Returns:
        Temporal correlation analysis with related event groups and patterns
    """
    try:
        # Extract parameters
        start_time = params.get("start_time")
        end_time = params.get("end_time")
        entity = params.get("entity")
        event_types = params.get("event_types", [])
        correlation_window = params.get("correlation_window", 300)  # 5 minutes default
        limit = params.get("limit", 1000)
        
        logger.info("Executing temporal correlation analysis", 
                   start_time=start_time,
                   end_time=end_time,
                   entity=entity,
                   correlation_window=correlation_window)
        
        # Build time range filter
        time_filter = build_time_range_filter(start_time, end_time)
        
        # Build the search query
        query = {
            "track_total_hits": True,
            "query": {
                "bool": {
                    "must": [time_filter]
                }
            },
            "sort": [
                {"@timestamp": {"order": "asc"}}
            ],
            "size": limit,
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
        
        # Apply smart event type filters if specified
        if event_types:
            event_type_filters = _build_smart_event_filters(event_types)
            if event_type_filters:
                query["query"]["bool"]["should"] = event_type_filters
                query["query"]["bool"]["minimum_should_match"] = 1
        
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
        
        logger.info("Retrieved events for temporal correlation", count=len(events), total=total_events)
        
        # Process events for correlation analysis
        correlation_events = []
        for hit in events:
            source = hit.get("_source", {})
            event_data = _extract_correlation_event_data(source)
            correlation_events.append(event_data)
        
        # Perform temporal correlation analysis
        correlation_analysis = await _perform_temporal_correlation(
            correlation_events, correlation_window
        )
        
        # Build result
        result = {
            "search_parameters": {
                "start_time": start_time,
                "end_time": end_time,
                "entity": entity,
                "event_types": event_types,
                "correlation_window_seconds": correlation_window,
                "view_type": "temporal",
                "data_source": "opensearch_alerts"
            },
            "correlation_summary": {
                "total_events": len(correlation_events),
                "correlation_groups": len(correlation_analysis["correlation_groups"]),
                "isolated_events": len(correlation_analysis["isolated_events"]),
                "temporal_patterns": len(correlation_analysis["temporal_patterns"]),
                "cross_entity_correlations": len(correlation_analysis["cross_entity_correlations"])
            },
            "correlation_groups": correlation_analysis["correlation_groups"],
            "temporal_patterns": correlation_analysis["temporal_patterns"],
            "cross_entity_correlations": correlation_analysis["cross_entity_correlations"],
            "isolated_events": correlation_analysis["isolated_events"],
            "correlation_matrix": correlation_analysis["correlation_matrix"],
            "recommendations": _generate_correlation_recommendations(correlation_analysis)
        }
        
        logger.info("Temporal correlation analysis completed", 
                   total_events=len(correlation_events),
                   correlation_groups=len(correlation_analysis["correlation_groups"]),
                   patterns=len(correlation_analysis["temporal_patterns"]))
        
        return result
        
    except Exception as e:
        logger.error("Temporal correlation analysis failed", error=str(e))
        raise Exception(f"Failed to perform temporal correlation: {str(e)}")




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
        # Agent ID - keep as string to match data format
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


def _build_smart_event_filters(event_types: List[str]) -> List[Dict[str, Any]]:
    """Build smart event filters based on keywords instead of hardcoded mappings"""
    # Use the smart mapper to build filters
    return build_smart_event_filters("", event_types)


def _extract_correlation_event_data(source: Dict[str, Any]) -> Dict[str, Any]:
    """Extract relevant data for correlation analysis"""
    timestamp = source.get("@timestamp", "")
    
    event_data = {
        "timestamp": timestamp,
        "timestamp_dt": _parse_timestamp(timestamp),
        "formatted_time": _format_timestamp(timestamp),
        "rule_id": source.get("rule", {}).get("id", ""),
        "rule_description": source.get("rule", {}).get("description", ""),
        "rule_level": source.get("rule", {}).get("level", 0),
        "agent_name": source.get("agent", {}).get("name", ""),
        "agent_id": source.get("agent", {}).get("id", ""),
        "agent_ip": source.get("agent", {}).get("ip", ""),
        "location": source.get("location", ""),
        "decoder": source.get("decoder", {}).get("name", ""),
        "rule_groups": source.get("rule", {}).get("groups", [])
    }
    
    # Extract correlation indicators
    data = source.get("data", {})
    win_eventdata = data.get("win", {}).get("eventdata", {})
    
    event_data["correlation_indicators"] = {
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


async def _perform_temporal_correlation(events: List[Dict[str, Any]], window_seconds: int) -> Dict[str, Any]:
    """Perform temporal correlation analysis on events"""
    
    correlation_groups = []
    temporal_patterns = []
    cross_entity_correlations = []
    isolated_events = []
    correlation_matrix = defaultdict(lambda: defaultdict(int))
    
    # Sort events by timestamp
    events.sort(key=lambda x: x["timestamp_dt"] or datetime.min)
    
    # Group events within temporal windows
    i = 0
    while i < len(events):
        current_event = events[i]
        if not current_event["timestamp_dt"]:
            isolated_events.append(current_event)
            i += 1
            continue
            
        # Find all events within the correlation window
        correlated_events = [current_event]
        j = i + 1
        
        while j < len(events):
            next_event = events[j]
            if not next_event["timestamp_dt"]:
                j += 1
                continue
                
            time_diff = (next_event["timestamp_dt"] - current_event["timestamp_dt"]).total_seconds()
            
            if time_diff <= window_seconds:
                correlated_events.append(next_event)
                j += 1
            else:
                break
        
        # Create correlation group if multiple events found
        if len(correlated_events) > 1:
            group = await _analyze_correlation_group(correlated_events)
            correlation_groups.append(group)
            
            # Update correlation matrix
            for event1 in correlated_events:
                for event2 in correlated_events:
                    if event1 != event2:
                        key1 = f"{event1['agent_name']}:{event1['rule_id']}"
                        key2 = f"{event2['agent_name']}:{event2['rule_id']}"
                        correlation_matrix[key1][key2] += 1
            
            i = j
        else:
            isolated_events.append(current_event)
            i += 1
    
    # Identify temporal patterns
    temporal_patterns = _identify_temporal_patterns(correlation_groups)
    
    # Identify cross-entity correlations
    cross_entity_correlations = _identify_cross_entity_correlations(correlation_groups)
    
    return {
        "correlation_groups": correlation_groups,
        "temporal_patterns": temporal_patterns,
        "cross_entity_correlations": cross_entity_correlations,
        "isolated_events": isolated_events[:50],  # Limit for output size
        "correlation_matrix": dict(correlation_matrix)
    }


async def _analyze_correlation_group(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze a group of correlated events"""
    
    # Calculate group metadata
    start_time = min([e["timestamp_dt"] for e in events if e["timestamp_dt"]])
    end_time = max([e["timestamp_dt"] for e in events if e["timestamp_dt"]])
    duration_seconds = (end_time - start_time).total_seconds()
    
    # Analyze entities involved
    entities = set([e["agent_name"] for e in events if e["agent_name"]])
    
    # Analyze severity
    max_severity = max([e["rule_level"] for e in events])
    avg_severity = sum([e["rule_level"] for e in events]) / len(events)
    
    # Analyze MITRE techniques
    mitre_techniques = set()
    mitre_tactics = set()
    for event in events:
        if "mitre_attack" in event:
            mitre_techniques.update(event["mitre_attack"].get("technique_id", []))
            mitre_tactics.update(event["mitre_attack"].get("tactic", []))
    
    # Identify correlation factors
    correlation_factors = _identify_correlation_factors(events)
    
    # Assess correlation strength
    correlation_strength = _assess_correlation_strength(events, correlation_factors)
    
    return {
        "group_id": f"group_{start_time.strftime('%Y%m%d_%H%M%S')}",
        "start_time": _format_timestamp(start_time.isoformat()),
        "end_time": _format_timestamp(end_time.isoformat()),
        "duration_seconds": int(duration_seconds),
        "event_count": len(events),
        "entities_involved": list(entities),
        "entity_count": len(entities),
        "max_severity": max_severity,
        "avg_severity": round(avg_severity, 2),
        "mitre_techniques": list(mitre_techniques),
        "mitre_tactics": list(mitre_tactics),
        "correlation_factors": correlation_factors,
        "correlation_strength": correlation_strength,
        "events": events
    }


def _identify_correlation_factors(events: List[Dict[str, Any]]) -> List[str]:
    """Identify factors that correlate the events"""
    factors = []
    
    # Check for common entities
    entities = [e["agent_name"] for e in events if e["agent_name"]]
    if len(set(entities)) == 1:
        factors.append("Same entity/agent")
    elif len(set(entities)) < len(entities):
        factors.append("Multiple events on same entities")
    
    # Check for common IP addresses
    src_ips = [e["correlation_indicators"]["src_ip"] for e in events if e["correlation_indicators"]["src_ip"]]
    dst_ips = [e["correlation_indicators"]["dst_ip"] for e in events if e["correlation_indicators"]["dst_ip"]]
    
    if src_ips and len(set(src_ips)) == 1:
        factors.append("Common source IP")
    if dst_ips and len(set(dst_ips)) == 1:
        factors.append("Common destination IP")
    
    # Check for common users
    users = []
    for event in events:
        users.extend([
            event["correlation_indicators"]["src_user"],
            event["correlation_indicators"]["dst_user"]
        ])
    users = [u for u in users if u]
    if users and len(set(users)) == 1:
        factors.append("Common user")
    
    # Check for common processes or commands
    commands = [e["correlation_indicators"]["command"] for e in events if e["correlation_indicators"]["command"]]
    processes = [e["correlation_indicators"]["process"] for e in events if e["correlation_indicators"]["process"]]
    
    if commands and len(set(commands)) == 1:
        factors.append("Same command execution")
    if processes and len(set(processes)) == 1:
        factors.append("Same process")
    
    # Check for MITRE technique correlation
    mitre_techniques = set()
    for event in events:
        if "mitre_attack" in event:
            mitre_techniques.update(event["mitre_attack"].get("technique_id", []))
    
    if len(mitre_techniques) > 1:
        factors.append("Multiple MITRE techniques")
    elif len(mitre_techniques) == 1:
        factors.append("Same MITRE technique")
    
    return factors if factors else ["Temporal proximity"]


def _assess_correlation_strength(events: List[Dict[str, Any]], factors: List[str]) -> str:
    """Assess the strength of correlation between events"""
    
    score = 0
    
    # Temporal proximity (closer = stronger)
    if len(events) > 1:
        timestamps = [e["timestamp_dt"] for e in events if e["timestamp_dt"]]
        if len(timestamps) > 1:
            time_span = (max(timestamps) - min(timestamps)).total_seconds()
            if time_span <= 60:  # Within 1 minute
                score += 3
            elif time_span <= 300:  # Within 5 minutes
                score += 2
            else:
                score += 1
    
    # Entity correlation
    if "Same entity/agent" in factors:
        score += 3
    elif "Multiple events on same entities" in factors:
        score += 2
    
    # Network correlation
    if "Common source IP" in factors or "Common destination IP" in factors:
        score += 2
    
    # User correlation
    if "Common user" in factors:
        score += 2
    
    # Process/command correlation
    if "Same command execution" in factors or "Same process" in factors:
        score += 2
    
    # MITRE correlation
    if "Multiple MITRE techniques" in factors:
        score += 3
    elif "Same MITRE technique" in factors:
        score += 2
    
    # Severity correlation
    severities = [e["rule_level"] for e in events]
    if max(severities) >= 10:
        score += 2
    
    # Determine strength
    if score >= 8:
        return "Strong"
    elif score >= 5:
        return "Medium"
    elif score >= 3:
        return "Weak"
    else:
        return "Minimal"


def _identify_temporal_patterns(correlation_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify temporal patterns in correlation groups"""
    patterns = []
    
    # Pattern 1: Rapid sequence patterns (multiple groups in short time)
    if len(correlation_groups) >= 2:
        for i in range(len(correlation_groups) - 1):
            current_group = correlation_groups[i]
            next_group = correlation_groups[i + 1]
            
            try:
                current_end = datetime.fromisoformat(current_group["end_time"].replace(" UTC", "+00:00"))
                next_start = datetime.fromisoformat(next_group["start_time"].replace(" UTC", "+00:00"))
                gap_seconds = (next_start - current_end).total_seconds()
                
                if gap_seconds <= 600:  # Within 10 minutes
                    patterns.append({
                        "pattern_type": "rapid_sequence",
                        "description": f"Rapid sequence: {gap_seconds:.0f}s gap between correlation groups",
                        "groups": [current_group["group_id"], next_group["group_id"]],
                        "gap_seconds": gap_seconds
                    })
            except (ValueError, AttributeError):
                continue
    
    # Pattern 2: Recurring entity patterns
    entity_groups = defaultdict(list)
    for group in correlation_groups:
        for entity in group["entities_involved"]:
            entity_groups[entity].append(group)
    
    for entity, groups in entity_groups.items():
        if len(groups) >= 3:
            patterns.append({
                "pattern_type": "recurring_entity",
                "description": f"Entity {entity} involved in {len(groups)} correlation groups",
                "entity": entity,
                "group_count": len(groups),
                "groups": [g["group_id"] for g in groups]
            })
    
    return patterns


def _identify_cross_entity_correlations(correlation_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify correlations that span multiple entities"""
    cross_entity_correlations = []
    
    for group in correlation_groups:
        if group["entity_count"] > 1:
            cross_entity_correlations.append({
                "group_id": group["group_id"],
                "entities": group["entities_involved"],
                "entity_count": group["entity_count"],
                "correlation_strength": group["correlation_strength"],
                "correlation_factors": group["correlation_factors"],
                "max_severity": group["max_severity"],
                "mitre_techniques": group["mitre_techniques"]
            })
    
    return cross_entity_correlations


def _generate_correlation_recommendations(analysis: Dict[str, Any]) -> List[str]:
    """Generate recommendations based on correlation analysis"""
    recommendations = []
    
    correlation_groups = analysis.get("correlation_groups", [])
    strong_correlations = [g for g in correlation_groups if g.get("correlation_strength") == "Strong"]
    
    if strong_correlations:
        recommendations.append(f"Investigate {len(strong_correlations)} strong correlation groups for potential coordinated activity")
    
    # Cross-entity correlations
    cross_entity = analysis.get("cross_entity_correlations", [])
    if cross_entity:
        high_severity_cross = [c for c in cross_entity if c.get("max_severity", 0) >= 10]
        if high_severity_cross:
            recommendations.append(f"Priority investigation of {len(high_severity_cross)} high-severity cross-entity correlations")
    
    # Temporal patterns
    patterns = analysis.get("temporal_patterns", [])
    rapid_sequences = [p for p in patterns if p.get("pattern_type") == "rapid_sequence"]
    if rapid_sequences:
        recommendations.append(f"Analyze {len(rapid_sequences)} rapid sequence patterns for automated attack indicators")
    
    # MITRE technique correlations
    mitre_groups = [g for g in correlation_groups if g.get("mitre_techniques")]
    if mitre_groups:
        recommendations.append(f"Correlate MITRE techniques across {len(mitre_groups)} groups for attack chain analysis")
    
    if not recommendations:
        recommendations.append("Temporal correlation analysis shows normal activity patterns")
    
    return recommendations


def _parse_timestamp(timestamp: str) -> Optional[datetime]:
    """Parse timestamp string to datetime object"""
    try:
        return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return None


def _format_timestamp(timestamp: str) -> str:
    """Format timestamp for display"""
    try:
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            dt = timestamp
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return str(timestamp)