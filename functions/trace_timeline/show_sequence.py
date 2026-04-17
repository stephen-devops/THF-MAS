"""
Display events in chronological order for timeline reconstruction
"""
from typing import Dict, Any, List, Optional
import structlog
from datetime import datetime
import re
from ._shared.event_type_mapper import build_smart_event_filters
from functions._shared.time_parser import build_time_range_filter

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Display events in chronological sequence for timeline reconstruction
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including start_time, end_time, entity, event_types
        
    Returns:
        Chronological sequence of events with timeline structure
    """
    try:
        # Extract parameters
        start_time = params.get("start_time")
        end_time = params.get("end_time")
        entity = params.get("entity")
        event_types = params.get("event_types", [])
        limit = params.get("limit", 1000)
        
        logger.info("Executing timeline sequence display", 
                   start_time=start_time,
                   end_time=end_time,
                   entity=entity,
                   event_types=event_types)
        
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
                {"@timestamp": {"order": "asc"}}  # Chronological order
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
            logger.info("Building smart event filters", event_types=event_types)
            event_type_filters = _build_smart_event_filters(event_types)
            logger.info("Generated event filters", filter_count=len(event_type_filters))
            if event_type_filters:
                query["query"]["bool"]["should"] = event_type_filters
                query["query"]["bool"]["minimum_should_match"] = 1
                logger.info("Applied event type filters to query")
        
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
        
        logger.info("Retrieved events for timeline sequence", count=len(events), total=total_events)
        
        # Process events into timeline structure
        timeline_events = []
        event_summary = {
            "total_events": len(events),
            "time_span_minutes": _calculate_time_span(events),
            "unique_agents": set(),
            "unique_rules": set(),
            "severity_distribution": {},
            "mitre_techniques": set()
        }
        
        for hit in events:
            source = hit.get("_source", {})
            timestamp = source.get("@timestamp", "")
            
            # Extract event details
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
                "decoder": source.get("decoder", {}).get("name", ""),
                "rule_groups": source.get("rule", {}).get("groups", [])
            }
            
            # Extract data fields
            data = source.get("data", {})
            win_eventdata = data.get("win", {}).get("eventdata", {})
            
            event_data["event_details"] = {
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
                
                # Add to summary
                for tech_id in mitre.get("id", []):
                    event_summary["mitre_techniques"].add(tech_id)
            
            # Add to summary statistics
            event_summary["unique_agents"].add(event_data["agent_name"])
            event_summary["unique_rules"].add(event_data["rule_id"])
            
            severity = event_data["rule_level"]
            event_summary["severity_distribution"][severity] = event_summary["severity_distribution"].get(severity, 0) + 1
            
            timeline_events.append(event_data)
        
        # Convert sets to lists for JSON serialization
        event_summary["unique_agents"] = list(event_summary["unique_agents"])
        event_summary["unique_rules"] = list(event_summary["unique_rules"])
        event_summary["mitre_techniques"] = list(event_summary["mitre_techniques"])
        
        # Generate sequence analysis
        sequence_analysis = _analyze_event_sequence(timeline_events)
        
        # Build result
        result = {
            "search_parameters": {
                "start_time": start_time,
                "end_time": end_time,
                "entity": entity,
                "event_types": event_types,
                "view_type": "sequence",
                "data_source": "opensearch_alerts"
            },
            "timeline_summary": event_summary,
            "sequence_analysis": sequence_analysis,
            "timeline_events": timeline_events,
            "recommendations": _generate_sequence_recommendations(timeline_events, sequence_analysis)
        }
        
        logger.info("Timeline sequence display completed", 
                   total_events=len(timeline_events),
                   time_span=event_summary["time_span_minutes"],
                   unique_agents=len(event_summary["unique_agents"]))
        
        return result
        
    except Exception as e:
        logger.error("Timeline sequence display failed", error=str(e))
        raise Exception(f"Failed to display timeline sequence: {str(e)}")



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
    elif "@" in entity:
        # Email/username
        return {
            "bool": {
                "should": [
                    {"wildcard": {"data.srcuser": f"*{entity}*"}},
                    {"wildcard": {"data.dstuser": f"*{entity}*"}},
                    {"wildcard": {"data.win.eventdata.targetUserName": f"*{entity}*"}},
                    {"wildcard": {"data.win.eventdata.subjectUserName": f"*{entity}*"}}
                ]
            }
        }
    else:
        # Hostname or general entity
        return {
            "bool": {
                "should": [
                    {"wildcard": {"agent.name": f"*{entity}*"}},
                    {"wildcard": {"data.srcuser": f"*{entity}*"}},
                    {"wildcard": {"data.dstuser": f"*{entity}*"}},
                    {"wildcard": {"data.path": f"*{entity}*"}},
                    {"wildcard": {"data.process": f"*{entity}*"}},
                    {"wildcard": {"data.win.eventdata.commandLine": f"*{entity}*"}},
                    {"wildcard": {"data.win.eventdata.image": f"*{entity}*"}},
                    {"wildcard": {"data.win.eventdata.targetFilename": f"*{entity}*"}}
                ]
            }
        }


def _build_smart_event_filters(event_types: List[str]) -> List[Dict[str, Any]]:
    """Build smart event filters based on keywords instead of hardcoded mappings"""
    # Use the smart mapper to build filters
    return build_smart_event_filters("", event_types)


def _calculate_time_span(events: List[Dict]) -> int:
    """Calculate time span of events in minutes"""
    if len(events) < 2:
        return 0
    
    try:
        first_event = events[0].get("_source", {}).get("@timestamp", "")
        last_event = events[-1].get("_source", {}).get("@timestamp", "")
        
        first_time = datetime.fromisoformat(first_event.replace('Z', '+00:00'))
        last_time = datetime.fromisoformat(last_event.replace('Z', '+00:00'))
        
        return int((last_time - first_time).total_seconds() / 60)
    except (ValueError, AttributeError):
        return 0


def _format_timestamp(timestamp: str) -> str:
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return timestamp


def _analyze_event_sequence(events: List[Dict]) -> Dict[str, Any]:
    """Analyze the sequence of events for patterns"""
    if not events:
        return {"analysis": "No events to analyze"}
    
    analysis = {
        "event_frequency": len(events),
        "event_clusters": [],
        "peak_activity_periods": [],
        "attack_patterns": [],
        "escalation_indicators": []
    }
    
    # Analyze event clustering (events within 5-minute windows)
    clusters = []
    current_cluster = []
    
    for i, event in enumerate(events):
        if not current_cluster:
            current_cluster.append(event)
        else:
            try:
                current_time = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
                last_time = datetime.fromisoformat(current_cluster[-1]["timestamp"].replace('Z', '+00:00'))
                
                if (current_time - last_time).total_seconds() <= 300:  # 5 minutes
                    current_cluster.append(event)
                else:
                    if len(current_cluster) > 1:
                        clusters.append({
                            "start_time": current_cluster[0]["formatted_time"],
                            "end_time": current_cluster[-1]["formatted_time"],
                            "event_count": len(current_cluster),
                            "severity_max": max([e["rule_level"] for e in current_cluster])
                        })
                    current_cluster = [event]
            except (ValueError, AttributeError):
                continue
    
    # Add final cluster
    if len(current_cluster) > 1:
        clusters.append({
            "start_time": current_cluster[0]["formatted_time"],
            "end_time": current_cluster[-1]["formatted_time"],
            "event_count": len(current_cluster),
            "severity_max": max([e["rule_level"] for e in current_cluster])
        })
    
    analysis["event_clusters"] = clusters
    
    # Identify escalation patterns (increasing severity over time)
    escalation_patterns = []
    for i in range(1, len(events)):
        if events[i]["rule_level"] > events[i-1]["rule_level"] and events[i]["rule_level"] >= 8:
            escalation_patterns.append({
                "from_severity": events[i-1]["rule_level"],
                "to_severity": events[i]["rule_level"],
                "time": events[i]["formatted_time"],
                "rule": events[i]["rule_description"]
            })
    
    analysis["escalation_indicators"] = escalation_patterns
    
    return analysis


def _generate_sequence_recommendations(events: List[Dict], analysis: Dict[str, Any]) -> List[str]:
    """Generate recommendations based on sequence analysis"""
    recommendations = []
    
    if not events:
        return ["No events found in the specified timeframe"]
    
    # Check for high-severity clusters
    high_severity_clusters = [c for c in analysis.get("event_clusters", []) if c.get("severity_max", 0) >= 10]
    if high_severity_clusters:
        recommendations.append(f"Investigate {len(high_severity_clusters)} high-severity event clusters for potential security incidents")
    
    # Check for escalation patterns
    escalation_count = len(analysis.get("escalation_indicators", []))
    if escalation_count > 0:
        recommendations.append(f"Review {escalation_count} severity escalation patterns that may indicate attack progression")
    
    # Check for rapid event sequences
    rapid_clusters = [c for c in analysis.get("event_clusters", []) if c.get("event_count", 0) > 10]
    if rapid_clusters:
        recommendations.append(f"Analyze {len(rapid_clusters)} rapid event sequences for automated attack indicators")
    
    # MITRE ATT&CK recommendations
    mitre_techniques = set()
    for event in events:
        if "mitre_attack" in event:
            mitre_techniques.update(event["mitre_attack"].get("technique_id", []))
    
    if mitre_techniques:
        recommendations.append(f"Correlate {len(mitre_techniques)} MITRE ATT&CK techniques for attack chain analysis")
    
    if not recommendations:
        recommendations.append("Timeline appears normal with no significant security patterns identified")
    
    return recommendations