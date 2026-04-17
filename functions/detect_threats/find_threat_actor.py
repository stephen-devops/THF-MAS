"""
Find threat actor activity in Wazuh alerts
"""
from typing import Dict, Any, List
import structlog
from datetime import datetime, timedelta

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Find threat actor activity in alerts
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including actor_name, timeframe, filters
        
    Returns:
        Threat actor activity results with techniques, affected hosts, and timeline
    """
    try:
        # Extract parameters
        actor_name = params.get("actor_name")
        timeframe = params.get("timeframe", "7d")
        host_filter = params.get("host_filter")
        limit = params.get("limit", 50)
        
        logger.info("Finding threat actor activity", 
                   actor_name=actor_name,
                   timeframe=timeframe,
                   host_filter=host_filter)
        
        # Build base query
        must_conditions = [
            opensearch_client.build_single_time_filter(timeframe)
        ]
        
        # Known threat actor patterns and aliases
        threat_actors = {
            "APT29": ["APT29", "Cozy Bear", "The Dukes", "CozyDuke", "Minidionis", "SeaDuke", "Hammertoss"],
            "APT28": ["APT28", "Fancy Bear", "Sofacy", "Sednit", "Strontium", "Tsar Team"],
            "APT1": ["APT1", "Comment Crew", "Comment Group", "Comment Panda"],
            "Lazarus": ["Lazarus", "Hidden Cobra", "Guardians of Peace", "Whois Team"],
            "Carbanak": ["Carbanak", "FIN7", "Cobalt Group"],
            "Turla": ["Turla", "Waterbug", "Venomous Bear", "Snake", "Krypton"],
            "Equation": ["Equation Group", "Equation", "EQUATIONGROUP"],
            "Winnti": ["Winnti", "APT41", "Barium", "Wicked Panda"],
            "Cobalt Strike": ["Cobalt Strike", "CobaltStrike", "Beacon"],
            "Metasploit": ["Metasploit", "MSF", "Meterpreter"]
        }
        
        # Add threat actor-specific filters
        if actor_name:
            # Get aliases for the actor
            actor_aliases = []
            for key, aliases in threat_actors.items():
                if actor_name.upper() in key.upper() or any(actor_name.upper() in alias.upper() for alias in aliases):
                    actor_aliases.extend(aliases)
            
            if not actor_aliases:
                actor_aliases = [actor_name]  # Use provided name if no known aliases
            
            # Build search conditions for actor
            actor_conditions = []
            for alias in actor_aliases:
                actor_conditions.extend([
                    {"wildcard": {"rule.description": f"*{alias}*"}},
                    {"wildcard": {"rule.groups": f"*{alias.lower().replace(' ', '_')}*"}},
                    {"wildcard": {"data.win.eventdata.commandLine": f"*{alias}*"}},
                    {"wildcard": {"data.win.eventdata.parentCommandLine": f"*{alias}*"}},
                    {"wildcard": {"data.win.eventdata.image": f"*{alias.lower().replace(' ', '_')}*"}},
                    {"wildcard": {"syscheck.path": f"*{alias.lower().replace(' ', '_')}*"}}
                ])
            
            must_conditions.append({
                "bool": {
                    "should": actor_conditions,
                    "minimum_should_match": 1
                }
            })
        else:
            # Search for any threat actor indicators
            general_conditions = []
            all_aliases = []
            for aliases in threat_actors.values():
                all_aliases.extend(aliases)
            
            for alias in all_aliases:
                general_conditions.extend([
                    {"wildcard": {"rule.description": f"*{alias}*"}},
                    {"wildcard": {"rule.groups": f"*{alias.lower().replace(' ', '_')}*"}}
                ])
            
            must_conditions.append({
                "bool": {
                    "should": general_conditions,
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
                "techniques_used": {
                    "terms": {
                        "field": "rule.mitre.technique",
                        "size": 20,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "tactic_mapping": {
                            "terms": {
                                "field": "rule.mitre.tactic",
                                "size": 5
                            }
                        }
                    }
                },
                "affected_hosts": {
                    "terms": {
                        "field": "agent.name",
                        "size": 20,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "host_techniques": {
                            "terms": {
                                "field": "rule.mitre.technique",
                                "size": 10
                            }
                        }
                    }
                },
                "attack_timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "2h",
                        "order": {"_key": "desc"}
                    },
                    "aggs": {
                        "technique_progression": {
                            "terms": {
                                "field": "rule.mitre.technique",
                                "size": 5
                            }
                        }
                    }
                },
                "rule_patterns": {
                    "terms": {
                        "field": "rule.description",
                        "size": 15,
                        "order": {"_count": "desc"}
                    }
                },
                "file_activities": {
                    "terms": {
                        "field": "syscheck.path",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                },
                "process_activities": {
                    "terms": {
                        "field": "data.win.eventdata.image",
                        "size": 10,
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
        techniques_agg = response.get("aggregations", {}).get("techniques_used", {})
        hosts_agg = response.get("aggregations", {}).get("affected_hosts", {})
        timeline_agg = response.get("aggregations", {}).get("attack_timeline", {})
        rules_agg = response.get("aggregations", {}).get("rule_patterns", {})
        files_agg = response.get("aggregations", {}).get("file_activities", {})
        processes_agg = response.get("aggregations", {}).get("process_activities", {})
        
        # Process techniques used
        techniques_used = []
        for bucket in techniques_agg.get("buckets", []):
            technique = bucket["key"]
            count = bucket["doc_count"]
            
            # Get associated tactics
            tactics = []
            for tactic_bucket in bucket.get("tactic_mapping", {}).get("buckets", []):
                tactics.append({
                    "tactic": tactic_bucket["key"],
                    "count": tactic_bucket["doc_count"]
                })
            
            techniques_used.append({
                "technique": technique,
                "alert_count": count,
                "tactics": tactics
            })
        
        # Process affected hosts
        affected_hosts = []
        for bucket in hosts_agg.get("buckets", []):
            host = bucket["key"]
            count = bucket["doc_count"]
            
            # Get techniques used on this host
            host_techniques = []
            for tech_bucket in bucket.get("host_techniques", {}).get("buckets", []):
                host_techniques.append({
                    "technique": tech_bucket["key"],
                    "count": tech_bucket["doc_count"]
                })
            
            affected_hosts.append({
                "host": host,
                "alert_count": count,
                "techniques_used": host_techniques
            })
        
        # Process attack timeline
        attack_timeline = []
        for bucket in timeline_agg.get("buckets", []):
            timestamp = bucket["key_as_string"]
            count = bucket["doc_count"]
            
            # Get techniques in this time period
            techniques_in_period = []
            for tech_bucket in bucket.get("technique_progression", {}).get("buckets", []):
                techniques_in_period.append({
                    "technique": tech_bucket["key"],
                    "count": tech_bucket["doc_count"]
                })
            
            attack_timeline.append({
                "timestamp": timestamp,
                "alert_count": count,
                "techniques": techniques_in_period
            })
        
        # Process rule patterns
        rule_patterns = []
        for bucket in rules_agg.get("buckets", []):
            rule_patterns.append({
                "rule": bucket["key"],
                "count": bucket["doc_count"]
            })
        
        # Process file activities
        file_activities = []
        for bucket in files_agg.get("buckets", []):
            file_activities.append({
                "file_path": bucket["key"],
                "count": bucket["doc_count"]
            })
        
        # Process process activities
        process_activities = []
        for bucket in processes_agg.get("buckets", []):
            process_activities.append({
                "process": bucket["key"],
                "count": bucket["doc_count"]
            })
        
        # Process recent alerts
        recent_alerts = []
        for hit in alert_hits[:15]:  # Top 15 most recent
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
                "host_ip": agent.get("ip"),
                "file_path": source.get("syscheck", {}).get("path"),
                "process": source.get("data", {}).get("win", {}).get("eventdata", {}).get("image")
            })
        
        # Build result
        result = {
            "total_alerts": total_alerts,
            "search_criteria": {
                "actor_name": actor_name,
                "timeframe": timeframe,
                "host_filter": host_filter
            },
            "techniques_used": techniques_used,
            "affected_hosts": affected_hosts,
            "attack_timeline": attack_timeline[:84],  # Last 84 periods (7 days * 12 2-hour periods)
            "rule_patterns": rule_patterns,
            "file_activities": file_activities,
            "process_activities": process_activities,
            "recent_alerts": recent_alerts,
            "threat_assessment": {
                "actor_identified": actor_name,
                "techniques_count": len(techniques_used),
                "hosts_compromised": len(affected_hosts),
                "attack_duration": len([t for t in attack_timeline if t["alert_count"] > 0]),
                "most_used_technique": techniques_used[0]["technique"] if techniques_used else None,
                "primary_target": affected_hosts[0]["host"] if affected_hosts else None,
                "attack_complexity": "High" if len(techniques_used) > 5 else "Medium" if len(techniques_used) > 2 else "Low"
            }
        }
        
        logger.info("Threat actor detection completed", 
                   total_alerts=total_alerts,
                   techniques_found=len(techniques_used),
                   hosts_affected=len(affected_hosts))
        
        return result
        
    except Exception as e:
        logger.error("Threat actor detection failed", error=str(e))
        raise Exception(f"Failed to find threat actor activity: {str(e)}")