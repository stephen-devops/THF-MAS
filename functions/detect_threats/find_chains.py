"""
Find attack chains and technique sequences in Wazuh alerts
"""
from typing import Dict, Any, List
import structlog
from datetime import datetime, timedelta
from collections import defaultdict

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Find attack chains and technique sequences in alerts
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including timeframe, host_filter, chain_window
        
    Returns:
        Attack chain analysis with technique sequences, affected hosts, and progression
    """
    try:
        # Extract parameters
        timeframe = params.get("timeframe", "24h")
        host_filter = params.get("host_filter")
        chain_window = params.get("chain_window", "2h")  # Time window for chain correlation
        limit = params.get("limit", 100)
        
        logger.info("Finding attack chains and technique sequences", 
                   timeframe=timeframe,
                   host_filter=host_filter,
                   chain_window=chain_window)
        
        # Build base query
        must_conditions = [
            opensearch_client.build_single_time_filter(timeframe)
        ]
        
        # Add MITRE technique filters
        must_conditions.append({
            "bool": {
                "should": [
                    {"exists": {"field": "rule.mitre.technique"}},
                    {"exists": {"field": "rule.mitre.id"}},
                    {"wildcard": {"rule.description": "*T[0-9]*"}},
                    {"terms": {"rule.groups": ["mitre", "attack", "technique"]}}
                ],
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
        
        # Build main query to get technique events
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "sort": [
                {"@timestamp": {"order": "asc"}}  # Chronological order for chain analysis
            ],
            "size": limit,
            "aggs": {
                "total_count": {
                    "value_count": {
                        "field": "_id"
                    }
                },
                "technique_pairs": {
                    "terms": {
                        "field": "rule.mitre.technique",
                        "size": 30
                    },
                    "aggs": {
                        "hosts_affected": {
                            "terms": {
                                "field": "agent.name",
                                "size": 10
                            }
                        },
                        "time_distribution": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "30m"
                            }
                        }
                    }
                },
                "tactic_progression": {
                    "terms": {
                        "field": "rule.mitre.tactic",
                        "size": 15
                    },
                    "aggs": {
                        "associated_techniques": {
                            "terms": {
                                "field": "rule.mitre.technique",
                                "size": 10
                            }
                        }
                    }
                },
                "host_activity": {
                    "terms": {
                        "field": "agent.name",
                        "size": 20
                    },
                    "aggs": {
                        "technique_sequence": {
                            "terms": {
                                "field": "rule.mitre.technique",
                                "size": 15
                            }
                        },
                        "tactic_coverage": {
                            "terms": {
                                "field": "rule.mitre.tactic",
                                "size": 10
                            }
                        }
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
        techniques_agg = response.get("aggregations", {}).get("technique_pairs", {})
        tactics_agg = response.get("aggregations", {}).get("tactic_progression", {})
        hosts_agg = response.get("aggregations", {}).get("host_activity", {})
        
        # Process chronological events for chain analysis
        events_by_host = defaultdict(list)
        for hit in alert_hits:
            source = hit.get("_source", {})
            rule = source.get("rule", {})
            agent = source.get("agent", {})
            
            technique = rule.get("mitre", {}).get("technique")
            tactic = rule.get("mitre", {}).get("tactic")
            
            # Handle technique and tactic as lists or strings
            if isinstance(technique, list):
                technique = technique[0] if technique else None
            if isinstance(tactic, list):
                tactic = tactic[0] if tactic else None
            
            if technique and agent.get("name"):
                events_by_host[agent["name"]].append({
                    "timestamp": source.get("@timestamp"),
                    "technique": technique,
                    "tactic": tactic,
                    "rule_id": rule.get("id"),
                    "rule_description": rule.get("description"),
                    "rule_level": rule.get("level")
                })
        
        # Analyze attack chains by host
        attack_chains = []
        for host, events in events_by_host.items():
            if len(events) < 2:  # Need at least 2 events for a chain
                continue
                
            # Sort events by timestamp
            events.sort(key=lambda x: x["timestamp"])
            
            # Find technique sequences within time windows
            chains = []
            current_chain = [events[0]]
            
            for i in range(1, len(events)):
                prev_event = events[i-1]
                curr_event = events[i]
                
                # Parse timestamps
                prev_time = datetime.fromisoformat(prev_event["timestamp"].replace('Z', '+00:00'))
                curr_time = datetime.fromisoformat(curr_event["timestamp"].replace('Z', '+00:00'))
                
                # Check if within chain window
                time_diff = curr_time - prev_time
                if time_diff <= timedelta(hours=2):  # Within 2-hour window
                    current_chain.append(curr_event)
                else:
                    # Chain break, save current chain if it has multiple techniques
                    if len(current_chain) > 1:
                        chains.append(current_chain)
                    current_chain = [curr_event]
            
            # Add final chain
            if len(current_chain) > 1:
                chains.append(current_chain)
            
            # Process chains for this host
            for chain in chains:
                techniques_in_chain = [event["technique"] for event in chain]
                tactics_in_chain = list(set([event["tactic"] for event in chain if event["tactic"]]))
                
                # Calculate chain metrics
                chain_duration = None
                if len(chain) > 1:
                    start_time = datetime.fromisoformat(chain[0]["timestamp"].replace('Z', '+00:00'))
                    end_time = datetime.fromisoformat(chain[-1]["timestamp"].replace('Z', '+00:00'))
                    chain_duration = str(end_time - start_time)
                
                # Determine attack phase progression
                tactic_phases = {
                    "reconnaissance": 1,
                    "resource_development": 2,
                    "initial_access": 3,
                    "execution": 4,
                    "persistence": 5,
                    "privilege_escalation": 6,
                    "defense_evasion": 7,
                    "credential_access": 8,
                    "discovery": 9,
                    "lateral_movement": 10,
                    "collection": 11,
                    "command_and_control": 12,
                    "exfiltration": 13,
                    "impact": 14
                }
                
                phase_progression = []
                for tactic in tactics_in_chain:
                    tactic_key = tactic.lower().replace(" ", "_")
                    if tactic_key in tactic_phases:
                        phase_progression.append({
                            "tactic": tactic,
                            "phase": tactic_phases[tactic_key]
                        })
                
                phase_progression.sort(key=lambda x: x["phase"])
                
                attack_chains.append({
                    "host": host,
                    "chain_id": f"{host}_{chain[0]['timestamp'][:19]}",
                    "techniques": techniques_in_chain,
                    "tactics": tactics_in_chain,
                    "phase_progression": phase_progression,
                    "events": chain,
                    "chain_length": len(chain),
                    "duration": chain_duration,
                    "severity": max([event["rule_level"] for event in chain]),
                    "start_time": chain[0]["timestamp"],
                    "end_time": chain[-1]["timestamp"]
                })
        
        # Process technique co-occurrence
        technique_cooccurrence = []
        for bucket in techniques_agg.get("buckets", []):
            technique = bucket["key"]
            count = bucket["doc_count"]
            
            # Get hosts affected by this technique
            affected_hosts = []
            for host_bucket in bucket.get("hosts_affected", {}).get("buckets", []):
                affected_hosts.append({
                    "host": host_bucket["key"],
                    "count": host_bucket["doc_count"]
                })
            
            # Get time distribution
            time_distribution = []
            for time_bucket in bucket.get("time_distribution", {}).get("buckets", []):
                time_distribution.append({
                    "timestamp": time_bucket["key_as_string"],
                    "count": time_bucket["doc_count"]
                })
            
            technique_cooccurrence.append({
                "technique": technique,
                "frequency": count,
                "affected_hosts": affected_hosts,
                "time_distribution": time_distribution
            })
        
        # Process tactic progression patterns
        tactic_patterns = []
        for bucket in tactics_agg.get("buckets", []):
            tactic = bucket["key"]
            count = bucket["doc_count"]
            
            # Get associated techniques
            associated_techniques = []
            for tech_bucket in bucket.get("associated_techniques", {}).get("buckets", []):
                associated_techniques.append({
                    "technique": tech_bucket["key"],
                    "count": tech_bucket["doc_count"]
                })
            
            tactic_patterns.append({
                "tactic": tactic,
                "frequency": count,
                "associated_techniques": associated_techniques
            })
        
        # Process host activity patterns
        host_patterns = []
        for bucket in hosts_agg.get("buckets", []):
            host = bucket["key"]
            count = bucket["doc_count"]
            
            # Get technique sequence for this host
            technique_sequence = []
            for tech_bucket in bucket.get("technique_sequence", {}).get("buckets", []):
                technique_sequence.append({
                    "technique": tech_bucket["key"],
                    "count": tech_bucket["doc_count"]
                })
            
            # Get tactic coverage for this host
            tactic_coverage = []
            for tactic_bucket in bucket.get("tactic_coverage", {}).get("buckets", []):
                tactic_coverage.append({
                    "tactic": tactic_bucket["key"],
                    "count": tactic_bucket["doc_count"]
                })
            
            host_patterns.append({
                "host": host,
                "total_events": count,
                "technique_sequence": technique_sequence,
                "tactic_coverage": tactic_coverage,
                "chain_count": len([chain for chain in attack_chains if chain["host"] == host])
            })
        
        # Sort attack chains by severity and length
        attack_chains.sort(key=lambda x: (x["severity"], x["chain_length"]), reverse=True)
        
        # Build result
        result = {
            "total_alerts": total_alerts,
            "search_criteria": {
                "timeframe": timeframe,
                "host_filter": host_filter,
                "chain_window": chain_window
            },
            "attack_chains": attack_chains[:20],  # Top 20 chains
            "technique_cooccurrence": technique_cooccurrence,
            "tactic_patterns": tactic_patterns,
            "host_patterns": host_patterns,
            "chain_analysis": {
                "total_chains_found": len(attack_chains),
                "hosts_with_chains": len(set([chain["host"] for chain in attack_chains])),
                "longest_chain": max([chain["chain_length"] for chain in attack_chains]) if attack_chains else 0,
                "most_severe_chain": max([chain["severity"] for chain in attack_chains]) if attack_chains else 0,
                "most_active_host": max(host_patterns, key=lambda x: x["total_events"])["host"] if host_patterns else None,
                "unique_techniques": len(set([t["technique"] for t in technique_cooccurrence])),
                "unique_tactics": len(set([t["tactic"] for t in tactic_patterns])),
                "attack_complexity": "High" if len(attack_chains) > 5 else "Medium" if len(attack_chains) > 1 else "Low"
            }
        }
        
        logger.info("Attack chain detection completed", 
                   total_alerts=total_alerts,
                   chains_found=len(attack_chains),
                   hosts_analyzed=len(host_patterns))
        
        return result
        
    except Exception as e:
        logger.error("Attack chain detection failed", error=str(e))
        raise Exception(f"Failed to find attack chains: {str(e)}")