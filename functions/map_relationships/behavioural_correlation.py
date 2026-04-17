"""
Analyze behavioral patterns, access activities, and correlations across entities using OpenSearch aggregations
Combines activity correlation analysis with access pattern detection for comprehensive behavioral insights
"""
from typing import Dict, Any, List, Optional
import structlog
from datetime import datetime

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze behavioral patterns and correlations using comprehensive aggregation-based approach
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including source_type, source_id, target_type, timeframe
        
    Returns:
        Comprehensive behavioral analysis including activity correlations, access patterns,
        temporal clustering, authentication analysis, and network behavior insights
    """
    try:
        # Extract parameters
        source_type = params.get("source_type")
        source_id = params.get("source_id")
        target_type = params.get("target_type")
        timeframe = params.get("timeframe", "24h")
        
        logger.info("Executing comprehensive behavioral correlation analysis", 
                   source_type=source_type,
                   source_id=source_id,
                   target_type=target_type,
                   timeframe=timeframe)
        
        # Build time range filter
        time_filter = opensearch_client.build_single_time_filter(timeframe)
        
        # Build comprehensive aggregation-based query
        query = _build_behavioral_correlation_query(source_type, source_id, target_type, time_filter)
        
        # Execute search with aggregations
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query,
            size=0  # Only aggregations needed
        )
        
        # Process aggregation results
        total_alerts = response["aggregations"]["total_count"]["value"]
        aggregations = response.get("aggregations", {})
        
        logger.info("Retrieved comprehensive behavioral data", total_alerts=total_alerts)
        
        # Process all behavioral analysis components
        correlation_events = []
        access_events = []
        network_patterns = []
        auth_patterns = []
        file_access_patterns = []
        
        # Initialize comprehensive summary
        behavioral_summary = {
            "source_entity": {"type": source_type, "id": source_id},
            "total_behavioral_events": total_alerts,
            "timeframe": timeframe,
            "activity_types": set(),
            "correlated_entities": set(),
            "access_methods": set(),
            "unique_access_targets": set(),
            "temporal_clusters": {},
            "behavioral_patterns": {}
        }
        
        # Process temporal correlation data (enhanced granularity)
        if "temporal_correlation" in aggregations:
            for time_bucket in aggregations["temporal_correlation"]["buckets"]:
                timestamp = time_bucket["key_as_string"]
                activity_count = time_bucket["doc_count"]
                
                behavioral_summary["temporal_clusters"][timestamp] = activity_count
                
                # Process entities active in this time window
                if "active_entities" in time_bucket:
                    for entity_bucket in time_bucket["active_entities"]["buckets"]:
                        entity_name = entity_bucket["key"]
                        entity_activity = entity_bucket["doc_count"]
                        
                        # Get activity types for this entity in this time window
                        activity_types = [b["key"] for b in entity_bucket.get("activity_types", {}).get("buckets", [])]
                        
                        # Get correlation significance
                        significance_score = entity_bucket.get("correlation_significance", {}).get("value") or 0
                        
                        # Check for unusual activity patterns
                        unusual_activities = []
                        if "unusual_activities" in entity_bucket:
                            unusual_activities = [
                                {"activity": b["key"], "score": b["score"]} 
                                for b in entity_bucket["unusual_activities"]["buckets"]
                            ]
                        
                        # Enhanced risk assessment combining correlation and access patterns
                        access_diversity = entity_bucket.get("access_diversity", {}).get("value") or 0
                        failure_rate = entity_bucket.get("failure_rate", {}).get("value") or 0
                        
                        risk_assessment = _assess_comprehensive_risk(
                            entity_activity, activity_types, unusual_activities,
                            access_diversity, failure_rate
                        )
                        
                        correlation_event = {
                            "timestamp": timestamp,
                            "entity": entity_name,
                            "entity_type": _infer_entity_type(entity_name),
                            "activity_count": entity_activity,
                            "activity_types": activity_types,
                            "correlation_significance": round(significance_score, 3),
                            "unusual_activities": unusual_activities,
                            "access_diversity": access_diversity,
                            "risk_assessment": risk_assessment
                        }
                        
                        correlation_events.append(correlation_event)
                        behavioral_summary["activity_types"].update(activity_types)
                        behavioral_summary["correlated_entities"].add(entity_name)
        
        # Process access pattern analysis
        if "access_pattern_analysis" in aggregations:
            for source_bucket in aggregations["access_pattern_analysis"]["buckets"]:
                source_entity = source_bucket["key"]
                
                # Process temporal access patterns with enhanced metrics
                if "access_timeline" in source_bucket:
                    for time_bucket in source_bucket["access_timeline"]["buckets"]:
                        timestamp = time_bucket["key_as_string"]
                        access_count = time_bucket["doc_count"]
                        
                        # Get access methods and target diversity
                        access_methods = [b["key"] for b in time_bucket.get("access_methods", {}).get("buckets", [])]
                        target_diversity = time_bucket.get("target_diversity", {}).get("value") or 0
                        
                        # Enhanced access event with behavioral context
                        access_event = {
                            "timestamp": timestamp,
                            "source_entity": source_entity,
                            "access_count": access_count,
                            "access_methods": access_methods,
                            "target_diversity": target_diversity,
                            "access_density": access_count / max(1, target_diversity),
                            "severity_profile": time_bucket.get("severity_profile", {}),
                            "risk_indicators": _assess_access_risk(access_count, access_methods, target_diversity)
                        }
                        
                        access_events.append(access_event)
                        behavioral_summary["access_methods"].update(access_methods)
                
                # Process enhanced behavioral patterns
                if "behavioral_patterns" in source_bucket:
                    total_patterns = 0
                    avg_severity = 0
                    unique_targets = 0
                    
                    for pattern_bucket in source_bucket["behavioral_patterns"]["buckets"]:
                        total_patterns += pattern_bucket["doc_count"]
                        if "avg_severity" in pattern_bucket:
                            severity_value = pattern_bucket["avg_severity"].get("value")
                            if severity_value is not None:
                                avg_severity += severity_value
                        if "unique_targets" in pattern_bucket:
                            targets_value = pattern_bucket["unique_targets"].get("value")
                            if targets_value is not None:
                                unique_targets = max(unique_targets, targets_value)
                    
                    behavioral_summary["behavioral_patterns"][source_entity] = {
                        "total_behavioral_events": total_patterns,
                        "avg_severity": avg_severity / len(source_bucket["behavioral_patterns"]["buckets"]) if source_bucket["behavioral_patterns"]["buckets"] else 0,
                        "unique_targets": unique_targets,
                        "time_periods": len(source_bucket["behavioral_patterns"]["buckets"])
                    }
        
        # Process enhanced network access patterns
        if "network_access_analysis" in aggregations:
            for ip_bucket in aggregations["network_access_analysis"]["buckets"]:
                source_ip = ip_bucket["key"]
                connection_count = ip_bucket["doc_count"]
                
                # Enhanced network pattern analysis
                dest_diversity = ip_bucket.get("destination_diversity", {}).get("value") or 0
                connection_types = [b["key"] for b in ip_bucket.get("connection_types", {}).get("buckets", [])]
                
                # Process temporal distribution
                temporal_pattern = []
                if "temporal_distribution" in ip_bucket:
                    temporal_pattern = [
                        {"hour": b["key"], "connections": b["doc_count"]}
                        for b in ip_bucket["temporal_distribution"]["buckets"]
                    ]
                
                # Enhanced network risk calculation
                network_pattern = {
                    "source_ip": source_ip,
                    "connection_count": connection_count,
                    "destination_diversity": dest_diversity,
                    "connection_types": connection_types,
                    "temporal_pattern": temporal_pattern,
                    "network_risk_score": _calculate_enhanced_network_risk(
                        connection_count, dest_diversity, connection_types, temporal_pattern
                    ),
                    "behavioral_indicators": _analyze_network_behavior(temporal_pattern)
                }
                
                network_patterns.append(network_pattern)
        
        # Process comprehensive authentication analysis
        if "authentication_analysis" in aggregations:
            for user_bucket in aggregations["authentication_analysis"]["buckets"]:
                username = user_bucket["key"]
                if not username:  # Skip empty usernames
                    continue
                    
                auth_count = user_bucket["doc_count"]
                host_diversity = user_bucket.get("host_diversity", {}).get("value") or 0
                geographic_diversity = user_bucket.get("geographic_diversity", {}).get("value") or 0
                
                # Enhanced success/failure analysis
                success_count = user_bucket.get("auth_success", {}).get("doc_count", 0)
                failure_count = user_bucket.get("auth_failures", {}).get("doc_count", 0)
                
                # Process temporal authentication patterns
                temporal_pattern = []
                if "temporal_pattern" in user_bucket:
                    temporal_pattern = [
                        {"timestamp": b["key_as_string"], "attempts": b["doc_count"]}
                        for b in user_bucket["temporal_pattern"]["buckets"]
                    ]
                
                # Comprehensive authentication risk assessment
                auth_pattern = {
                    "username": username,
                    "auth_attempts": auth_count,
                    "host_diversity": host_diversity,
                    "geographic_diversity": geographic_diversity,
                    "success_count": success_count,
                    "failure_count": failure_count,
                    "failure_rate": (failure_count / max(1, auth_count)) * 100,
                    "temporal_pattern": temporal_pattern,
                    "behavioral_risk": _assess_comprehensive_auth_risk(
                        failure_count, host_diversity, geographic_diversity, temporal_pattern
                    )
                }
                
                auth_patterns.append(auth_pattern)
        
        # Process file access analysis
        if "file_access_analysis" in aggregations:
            for file_bucket in aggregations["file_access_analysis"]["buckets"]:
                filename = file_bucket["key"]
                if not filename:  # Skip empty filenames
                    continue
                    
                access_frequency = file_bucket.get("access_frequency", {}).get("value") or 0
                accessing_users = file_bucket.get("accessing_users", {}).get("value") or 0
                
                # Get access types and recent access details
                access_types = [b["key"] for b in file_bucket.get("access_types", {}).get("buckets", [])]
                
                recent_access = None
                if file_bucket.get("recent_access", {}).get("hits", {}).get("hits"):
                    recent_hit = file_bucket["recent_access"]["hits"]["hits"][0]["_source"]
                    recent_access = {
                        "timestamp": recent_hit.get("@timestamp", ""),
                        "user": recent_hit.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName", ""),
                        "description": recent_hit.get("rule", {}).get("description", "")
                    }
                
                file_pattern = {
                    "filename": filename,
                    "access_frequency": access_frequency,
                    "accessing_users": accessing_users,
                    "access_types": access_types,
                    "recent_access": recent_access,
                    "risk_level": _assess_file_access_risk(access_frequency, accessing_users, access_types)
                }
                
                file_access_patterns.append(file_pattern)
                behavioral_summary["unique_access_targets"].add(filename)
        
        # Process cross-entity correlation analysis (enhanced)
        cross_entity_correlations = []
        if "cross_entity_correlation" in aggregations:
            for composite_bucket in aggregations["cross_entity_correlation"]["buckets"]:
                entity1 = composite_bucket["key"]["entity1"]
                entity2 = composite_bucket["key"]["entity2"]
                correlation_strength = composite_bucket["doc_count"]
                
                # Enhanced temporal and activity correlation
                temporal_pattern = []
                if "correlation_timeline" in composite_bucket:
                    temporal_pattern = [
                        {"timestamp": b["key_as_string"], "activity": b["doc_count"]}
                        for b in composite_bucket["correlation_timeline"]["buckets"]
                    ]
                
                shared_activities = []
                if "shared_activities" in composite_bucket:
                    shared_activities = [
                        {"activity_type": b["key"], "frequency": b["doc_count"]}
                        for b in composite_bucket["shared_activities"]["buckets"]
                    ]
                
                # Enhanced correlation analysis
                cross_correlation = {
                    "entity1": entity1,
                    "entity2": entity2,
                    "correlation_strength": correlation_strength,
                    "temporal_pattern": temporal_pattern,
                    "shared_activities": shared_activities,
                    "correlation_score": min(100, correlation_strength * 2),
                    "relationship_type": _determine_relationship_type(shared_activities),
                    "behavioral_significance": _calculate_behavioral_significance(
                        correlation_strength, temporal_pattern, shared_activities
                    )
                }
                
                cross_entity_correlations.append(cross_correlation)
        
        # Convert sets to lists and finalize summary
        behavioral_summary["activity_types"] = list(behavioral_summary["activity_types"])
        behavioral_summary["access_methods"] = list(behavioral_summary["access_methods"])
        behavioral_summary["unique_access_targets"] = list(behavioral_summary["unique_access_targets"])
        behavioral_summary["correlated_entities"] = list(behavioral_summary["correlated_entities"])
        behavioral_summary["unique_entities_count"] = len(behavioral_summary["correlated_entities"])
        behavioral_summary["unique_activity_types"] = len(behavioral_summary["activity_types"])
        behavioral_summary["cross_entity_correlations"] = len(cross_entity_correlations)
        behavioral_summary["unique_access_methods"] = len(behavioral_summary["access_methods"])
        behavioral_summary["unique_target_count"] = len(behavioral_summary["unique_access_targets"])
        
        # Generate comprehensive behavioral analysis
        behavioral_analysis = _analyze_comprehensive_behavioral_patterns(
            correlation_events, access_events, network_patterns, auth_patterns, 
            file_access_patterns, cross_entity_correlations, aggregations
        )
        
        # Build comprehensive result
        result = {
            "relationship_type": "behavioral_correlation",
            "search_parameters": {
                "source_type": source_type,
                "source_id": source_id,
                "target_type": target_type,
                "timeframe": timeframe,
                "data_source": "opensearch_alerts"
            },
            "behavioral_summary": behavioral_summary,
            "correlation_events": correlation_events,
            "access_events": access_events,
            "network_patterns": network_patterns,
            "authentication_patterns": auth_patterns,
            "file_access_patterns": file_access_patterns,
            "cross_entity_correlations": cross_entity_correlations,
            "behavioral_analysis": behavioral_analysis,
            "behavioral_insights": _generate_comprehensive_insights(
                correlation_events, access_events, network_patterns, behavioral_analysis
            ),
            "recommendations": _generate_comprehensive_recommendations(behavioral_analysis)
        }
        
        logger.info("Comprehensive behavioral correlation analysis completed", 
                   correlation_events=len(correlation_events),
                   access_events=len(access_events),
                   network_patterns=len(network_patterns),
                   auth_patterns=len(auth_patterns),
                   file_patterns=len(file_access_patterns),
                   cross_correlations=len(cross_entity_correlations))
        
        return result
        
    except Exception as e:
        logger.error("Comprehensive behavioral correlation analysis failed", error=str(e))
        raise Exception(f"Failed to analyze behavioral correlations: {str(e)}")


def _build_behavioral_correlation_query(source_type: str, source_id: str, target_type: Optional[str], time_filter: Dict[str, Any]) -> Dict[str, Any]:
    """Build comprehensive aggregation query for behavioral correlation analysis"""
    
    # Build source entity filter if specified
    must_conditions = [time_filter]
    if source_id:
        source_filters = _get_entity_filters(source_type, source_id)
        must_conditions.extend(source_filters)
    
    query = {
        "query": {
            "bool": {
                "must": must_conditions,
                "should": [
                    {"terms": {"rule.groups": ["audit", "system", "process", "network"]}},
                    {"terms": {"rule.groups": ["authentication", "pam", "ssh", "login", "logon"]}},
                    {"terms": {"rule.groups": ["syscheck", "file_integrity", "fim"]}},
                    {"bool": {"must": [
                        {"terms": {"rule.groups": ["windows", "security"]}},
                        {"exists": {"field": "data.win.eventdata"}}
                    ]}},
                    {"bool": {"must": [
                        {"exists": {"field": "data.srcip"}},
                        {"range": {"rule.level": {"gte": 2}}}
                    ]}}
                ],
                "minimum_should_match": 1
            }
        },
        "aggs": {
            "total_count": {
                "value_count": {
                    "field": "_id"
                }
            },
            # Enhanced temporal correlation with finer granularity
            "temporal_correlation": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "15m",
                    "min_doc_count": 1
                },
                "aggs": {
                    "active_entities": {
                        "terms": {
                            "field": "agent.name",
                            "size": 50
                        },
                        "aggs": {
                            "activity_types": {
                                "terms": {"field": "rule.groups", "size": 15}
                            },
                            "correlation_significance": {
                                "bucket_script": {
                                    "buckets_path": {"doc_count": "_count"},
                                    "script": {
                                        "source": "Math.log(params.doc_count + 1)"
                                    }
                                }
                            },
                            "unusual_activities": {
                                "significant_terms": {
                                    "field": "rule.groups",
                                    "background_filter": {
                                        "range": {"@timestamp": {"gte": "now-7d/d"}}
                                    },
                                    "min_doc_count": 3
                                }
                            },
                            "access_diversity": {
                                "cardinality": {"field": "data.win.eventdata.targetUserName"}
                            },
                            "failure_rate": {
                                "bucket_script": {
                                    "buckets_path": {
                                        "total": "_count",
                                        "failures": "failures>_count"
                                    },
                                    "script": {
                                        "source": "params.failures / Math.max(params.total, 1) * 100"
                                    }
                                }
                            },
                            "failures": {
                                "filter": {
                                    "bool": {
                                        "should": [
                                            {"wildcard": {"rule.description": "*failed*"}},
                                            {"wildcard": {"rule.description": "*denied*"}},
                                            {"wildcard": {"rule.description": "*invalid*"}}
                                        ]
                                    }
                                }
                            },
                            "severity_profile": {
                                "stats": {"field": "rule.level"}
                            }
                        }
                    },
                    "activity_burst_detection": {
                        "bucket_script": {
                            "buckets_path": {"doc_count": "_count"},
                            "script": {
                                "source": "params.doc_count > 50 ? params.doc_count : 0"
                            }
                        }
                    }
                }
            },
            
            # Enhanced access pattern analysis
            "access_pattern_analysis": {
                "terms": {
                    "field": "agent.name",
                    "size": 100
                },
                "aggs": {
                    "access_timeline": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "1h",
                            "min_doc_count": 1
                        },
                        "aggs": {
                            "access_methods": {
                                "terms": {"field": "rule.groups", "size": 15}
                            },
                            "target_diversity": {
                                "cardinality": {"field": "data.win.eventdata.targetUserName"}
                            },
                            "severity_profile": {
                                "stats": {"field": "rule.level"}
                            }
                        }
                    },
                    "behavioral_patterns": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "4h"
                        },
                        "aggs": {
                            "access_frequency": {"value_count": {"field": "_id"}},
                            "unique_targets": {
                                "cardinality": {"field": "data.win.eventdata.targetUserName"}
                            },
                            "avg_severity": {
                                "avg": {"field": "rule.level"}
                            }
                        }
                    }
                }
            },
            
            # Enhanced cross-entity correlation
            "cross_entity_correlation": {
                "composite": {
                    "sources": [
                        {"entity1": {"terms": {"field": "agent.name"}}},
                        {"entity2": {"terms": {"field": "data.win.eventdata.targetUserName"}}}
                    ],
                    "size": 100
                },
                "aggs": {
                    "correlation_timeline": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "30m"
                        }
                    },
                    "shared_activities": {
                        "terms": {"field": "rule.groups", "size": 15}
                    },
                    "correlation_strength": {
                        "bucket_script": {
                            "buckets_path": {"doc_count": "_count"},
                            "script": {
                                "source": "Math.sqrt(params.doc_count)"
                            }
                        }
                    }
                }
            },
            
            # Enhanced network access analysis
            "network_access_analysis": {
                "terms": {
                    "field": "data.srcip",
                    "size": 50
                },
                "aggs": {
                    "destination_diversity": {
                        "cardinality": {"field": "data.dstip"}
                    },
                    "connection_types": {
                        "terms": {"field": "data.protocol", "size": 15}
                    },
                    "temporal_distribution": {
                        "histogram": {
                            "script": {
                                "source": "doc['@timestamp'].value.getHour()"
                            },
                            "interval": 1
                        }
                    },
                    "geographic_indicators": {
                        "terms": {"field": "agent.ip", "size": 20}
                    },
                    "connection_burst_detection": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "5m"
                        },
                        "aggs": {
                            "burst_threshold": {
                                "bucket_script": {
                                    "buckets_path": {"connections": "_count"},
                                    "script": {
                                        "source": "params.connections > 100 ? params.connections : 0"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            
            # Enhanced authentication analysis
            "authentication_analysis": {
                "terms": {
                    "field": "data.win.eventdata.targetUserName",
                    "size": 50
                },
                "aggs": {
                    "host_diversity": {
                        "cardinality": {"field": "agent.name"}
                    },
                    "geographic_diversity": {
                        "cardinality": {"field": "agent.ip"}
                    },
                    "auth_success": {
                        "filter": {
                            "bool": {
                                "must_not": [
                                    {"wildcard": {"rule.description": "*failed*"}},
                                    {"wildcard": {"rule.description": "*denied*"}},
                                    {"wildcard": {"rule.description": "*invalid*"}}
                                ]
                            }
                        }
                    },
                    "auth_failures": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"wildcard": {"rule.description": "*failed*"}},
                                    {"wildcard": {"rule.description": "*denied*"}},
                                    {"wildcard": {"rule.description": "*invalid*"}}
                                ]
                            }
                        }
                    },
                    "temporal_pattern": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "2h"
                        }
                    },
                    "brute_force_detection": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "1m"
                        },
                        "aggs": {
                            "rapid_attempts": {
                                "bucket_script": {
                                    "buckets_path": {"attempts": "_count"},
                                    "script": {
                                        "source": "params.attempts > 10 ? params.attempts : 0"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            
            # Enhanced file access analysis
            "file_access_analysis": {
                "terms": {
                    "field": "data.win.eventdata.targetFilename",
                    "size": 50
                },
                "aggs": {
                    "access_frequency": {"value_count": {"field": "_id"}},
                    "accessing_users": {
                        "cardinality": {"field": "data.win.eventdata.targetUserName"}
                    },
                    "access_types": {
                        "terms": {"field": "rule.groups", "size": 10}
                    },
                    "recent_access": {
                        "top_hits": {
                            "size": 1,
                            "sort": [{"@timestamp": {"order": "desc"}}],
                            "_source": ["@timestamp", "data.win.eventdata.targetUserName", "rule.description"]
                        }
                    },
                    "access_patterns": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "6h"
                        }
                    }
                }
            }
        }
    }
    
    return query


def _get_entity_filters(entity_type: str, entity_id: str) -> List[Dict[str, Any]]:
    """Get filters for specific entity type"""
    filters = []
    
    if entity_type.lower() == "host":
        filters.append({
            "bool": {
                "should": [
                    {"term": {"agent.name": entity_id}},
                    {"term": {"agent.ip": entity_id}},
                    {"wildcard": {"agent.name": f"*{entity_id}*"}}
                ]
            }
        })
    elif entity_type.lower() == "user":
        filters.append({
            "bool": {
                "should": [
                    {"wildcard": {"data.srcuser": f"*{entity_id}*"}},
                    {"wildcard": {"data.dstuser": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.targetUserName": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.subjectUserName": f"*{entity_id}*"}}
                ]
            }
        })
    
    return filters


def _infer_entity_type(entity_name: str) -> str:
    """Infer entity type from name patterns"""
    if "." in entity_name and len(entity_name.split(".")) > 1:
        return "user"
    elif "-" in entity_name or "server" in entity_name.lower() or "host" in entity_name.lower():
        return "host"
    else:
        return "unknown"


def _assess_comprehensive_risk(activity_count: int, activity_types: List[str], unusual_activities: List[Dict], 
                              access_diversity: int, failure_rate: float) -> Dict[str, Any]:
    """Assess comprehensive risk level combining correlation and access patterns"""
    risk_score = 0
    risk_indicators = []
    
    # Activity volume risk
    if activity_count > 200:
        risk_score += 35
        risk_indicators.append("Very high activity volume")
    elif activity_count > 100:
        risk_score += 25
        risk_indicators.append("High activity volume")
    elif activity_count > 50:
        risk_score += 15
        risk_indicators.append("Elevated activity volume")
    
    # Access diversity risk (potential lateral movement)
    if access_diversity > 50:
        risk_score += 30
        risk_indicators.append("Very high access diversity - potential lateral movement")
    elif access_diversity > 20:
        risk_score += 20
        risk_indicators.append("High access diversity")
    
    # Failure rate risk
    if failure_rate > 50:
        risk_score += 25
        risk_indicators.append("High failure rate - potential brute force")
    elif failure_rate > 20:
        risk_score += 15
        risk_indicators.append("Elevated failure rate")
    
    # Unusual activities
    if unusual_activities:
        risk_score += len(unusual_activities) * 10
        risk_indicators.append(f"Unusual activities detected: {len(unusual_activities)}")
    
    # High-risk activity types
    high_risk_activities = ["authentication_failed", "privilege_escalation", "malware", "attack", "exploit"]
    if any(risk_activity in " ".join(activity_types).lower() for risk_activity in high_risk_activities):
        risk_score += 40
        risk_indicators.append("High-risk activity types detected")
    
    # Determine risk level
    if risk_score > 80:
        risk_level = "Critical"
    elif risk_score > 50:
        risk_level = "High"
    elif risk_score > 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_indicators": risk_indicators
    }


def _assess_access_risk(access_count: int, access_methods: List[str], target_diversity: int) -> Dict[str, Any]:
    """Assess risk level of access patterns"""
    risk_score = 0
    risk_indicators = []
    
    # High access volume
    if access_count > 200:
        risk_score += 40
        risk_indicators.append("Very high access volume")
    elif access_count > 100:
        risk_score += 25
        risk_indicators.append("High access volume")
    elif access_count > 50:
        risk_score += 15
        risk_indicators.append("Elevated access volume")
    
    # High target diversity (potential lateral movement)
    if target_diversity > 50:
        risk_score += 35
        risk_indicators.append("Very high target diversity - potential scanning")
    elif target_diversity > 20:
        risk_score += 20
        risk_indicators.append("High target diversity")
    
    # Access concentration (high volume, low diversity = focused attack)
    if access_count > 50 and target_diversity < 5:
        risk_score += 30
        risk_indicators.append("High access concentration - potential brute force")
    
    # High-risk access methods
    high_risk_methods = ["authentication_failed", "privilege_escalation", "file_integrity"]
    if any(risk_method in " ".join(access_methods).lower() for risk_method in high_risk_methods):
        risk_score += 25
        risk_indicators.append("High-risk access methods detected")
    
    # Determine risk level
    if risk_score > 70:
        risk_level = "Critical"
    elif risk_score > 40:
        risk_level = "High"
    elif risk_score > 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_indicators": risk_indicators
    }


def _calculate_enhanced_network_risk(connection_count: int, dest_diversity: int, connection_types: List[str], temporal_pattern: List[Dict]) -> int:
    """Calculate enhanced network access risk score"""
    risk_score = 0
    
    # Connection volume risk
    if connection_count > 1000:
        risk_score += 40
    elif connection_count > 500:
        risk_score += 25
    elif connection_count > 100:
        risk_score += 15
    
    # Destination diversity risk
    if dest_diversity > 100:
        risk_score += 35
    elif dest_diversity > 50:
        risk_score += 20
    
    # Temporal pattern analysis (night activity)
    if temporal_pattern:
        night_connections = sum(p["connections"] for p in temporal_pattern if p["hour"] < 6 or p["hour"] > 22)
        total_connections = sum(p["connections"] for p in temporal_pattern)
        if total_connections > 0 and (night_connections / total_connections) > 0.3:
            risk_score += 20
    
    # Suspicious protocols
    suspicious_protocols = ["tor", "proxy", "tunnel"]
    if any(proto in " ".join(connection_types).lower() for proto in suspicious_protocols):
        risk_score += 30
    
    return min(100, risk_score)


def _analyze_network_behavior(temporal_pattern: List[Dict]) -> List[str]:
    """Analyze network behavior patterns"""
    indicators = []
    
    if not temporal_pattern:
        return indicators
    
    # Check for night activity
    night_activity = sum(p["connections"] for p in temporal_pattern if p["hour"] < 6 or p["hour"] > 22)
    total_activity = sum(p["connections"] for p in temporal_pattern)
    
    if total_activity > 0:
        night_ratio = night_activity / total_activity
        if night_ratio > 0.5:
            indicators.append("Predominantly night-time network activity")
        elif night_ratio > 0.3:
            indicators.append("Significant after-hours network activity")
    
    # Check for activity bursts
    max_hourly = max(p["connections"] for p in temporal_pattern) if temporal_pattern else 0
    avg_hourly = total_activity / len(temporal_pattern) if temporal_pattern else 0
    
    if max_hourly > avg_hourly * 5:
        indicators.append("Network activity bursts detected")
    
    return indicators


def _assess_comprehensive_auth_risk(failure_count: int, host_diversity: int, geographic_diversity: int, temporal_pattern: List[Dict]) -> Dict[str, Any]:
    """Assess comprehensive authentication risk level"""
    risk_score = 0
    risk_indicators = []
    
    # High failure count
    if failure_count > 100:
        risk_score += 40
        risk_indicators.append("Very high authentication failure count")
    elif failure_count > 50:
        risk_score += 25
        risk_indicators.append("High authentication failure count")
    elif failure_count > 20:
        risk_score += 15
        risk_indicators.append("Elevated authentication failures")
    
    # Host diversity (lateral movement indicator)
    if host_diversity > 20:
        risk_score += 30
        risk_indicators.append("Authentication attempts across many hosts")
    elif host_diversity > 10:
        risk_score += 20
        risk_indicators.append("Multi-host authentication activity")
    
    # Geographic diversity (potential account compromise)
    if geographic_diversity > 5:
        risk_score += 35
        risk_indicators.append("Authentication from multiple locations")
    elif geographic_diversity > 2:
        risk_score += 20
        risk_indicators.append("Multi-location authentication activity")
    
    # Temporal pattern analysis
    if temporal_pattern:
        # Check for rapid authentication bursts
        max_attempts = max(p["attempts"] for p in temporal_pattern) if temporal_pattern else 0
        if max_attempts > 50:
            risk_score += 25
            risk_indicators.append("Rapid authentication burst detected")
    
    # Determine risk level
    if risk_score > 80:
        risk_level = "Critical"
    elif risk_score > 50:
        risk_level = "High"
    elif risk_score > 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_indicators": risk_indicators
    }


def _assess_file_access_risk(access_frequency: int, accessing_users: int, access_types: List[str]) -> str:
    """Assess file access risk level"""
    risk_score = 0
    
    # High access frequency
    if access_frequency > 1000:
        risk_score += 30
    elif access_frequency > 500:
        risk_score += 20
    elif access_frequency > 100:
        risk_score += 10
    
    # Many users accessing same file
    if accessing_users > 20:
        risk_score += 25
    elif accessing_users > 10:
        risk_score += 15
    
    # Sensitive access types
    sensitive_types = ["file_integrity", "syscheck", "audit"]
    if any(sensitive in " ".join(access_types).lower() for sensitive in sensitive_types):
        risk_score += 20
    
    if risk_score > 50:
        return "High"
    elif risk_score > 25:
        return "Medium"
    else:
        return "Low"


def _determine_relationship_type(shared_activities: List[Dict]) -> str:
    """Determine the type of relationship based on shared activities"""
    if not shared_activities:
        return "unknown"
    
    activity_names = [activity["activity_type"] for activity in shared_activities]
    activity_text = " ".join(activity_names).lower()
    
    if any(term in activity_text for term in ["authentication", "login", "logon"]):
        return "authentication_relationship"
    elif any(term in activity_text for term in ["file", "syscheck", "integrity"]):
        return "file_relationship"
    elif any(term in activity_text for term in ["process", "execution", "command"]):
        return "process_relationship"
    elif any(term in activity_text for term in ["network", "connection", "communication"]):
        return "network_relationship"
    else:
        return "general_activity_relationship"


def _calculate_behavioral_significance(correlation_strength: int, temporal_pattern: List[Dict], shared_activities: List[Dict]) -> float:
    """Calculate behavioral significance of correlation"""
    significance = 0.0
    
    # Correlation strength factor
    significance += min(50, correlation_strength * 0.5)
    
    # Temporal consistency factor
    if temporal_pattern:
        non_zero_periods = len([p for p in temporal_pattern if p["activity"] > 0])
        temporal_consistency = non_zero_periods / len(temporal_pattern) if temporal_pattern else 0
        significance += temporal_consistency * 30
    
    # Activity diversity factor
    if shared_activities:
        unique_activities = len(set(a["activity_type"] for a in shared_activities))
        significance += min(20, unique_activities * 5)
    
    return min(100.0, significance)


def _analyze_comprehensive_behavioral_patterns(correlation_events: List[Dict], access_events: List[Dict], 
                                             network_patterns: List[Dict], auth_patterns: List[Dict], 
                                             file_patterns: List[Dict], cross_correlations: List[Dict], 
                                             aggregations: Dict) -> Dict[str, Any]:
    """Analyze comprehensive behavioral patterns from all data sources"""
    analysis = {
        "temporal_patterns": {},
        "correlation_analysis": {},
        "access_behavior_analysis": {},
        "network_behavior_analysis": {},
        "authentication_analysis": {},
        "file_access_analysis": {},
        "risk_assessment": {},
        "behavioral_anomalies": {}
    }
    
    if not any([correlation_events, access_events, network_patterns, auth_patterns, file_patterns]):
        return {"message": "No behavioral data found for comprehensive analysis"}
    
    # Temporal analysis across all events
    all_events = correlation_events + access_events
    if all_events:
        hourly_distribution = {}
        for event in all_events:
            try:
                hour = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00')).hour
                hourly_distribution[hour] = hourly_distribution.get(hour, 0) + event.get("activity_count", event.get("access_count", 1))
            except:
                continue
        
        analysis["temporal_patterns"] = {
            "peak_activity_hour": max(hourly_distribution.items(), key=lambda x: x[1]) if hourly_distribution else (0, 0),
            "total_time_periods": len(hourly_distribution),
            "night_activity_percentage": sum(hourly_distribution.get(h, 0) for h in list(range(0, 6)) + list(range(22, 24))) / sum(hourly_distribution.values()) * 100 if hourly_distribution else 0,
            "activity_distribution": hourly_distribution
        }
    
    # Correlation strength analysis
    if cross_correlations:
        strength_values = [c["correlation_strength"] for c in cross_correlations]
        analysis["correlation_analysis"] = {
            "max_correlation": max(strength_values),
            "avg_correlation": sum(strength_values) / len(strength_values),
            "strong_correlations": len([s for s in strength_values if s > 50]),
            "total_correlations": len(cross_correlations)
        }
    
    # Access behavior analysis
    if access_events:
        total_access = sum(e["access_count"] for e in access_events)
        avg_diversity = sum(e["target_diversity"] for e in access_events) / len(access_events)
        
        analysis["access_behavior_analysis"] = {
            "total_access_events": total_access,
            "avg_target_diversity": round(avg_diversity, 2),
            "high_risk_access_events": len([e for e in access_events if e["risk_indicators"]["risk_level"] in ["Critical", "High"]])
        }
    
    # Network behavior analysis
    if network_patterns:
        total_connections = sum(p["connection_count"] for p in network_patterns)
        avg_dest_diversity = sum(p["destination_diversity"] for p in network_patterns) / len(network_patterns)
        
        analysis["network_behavior_analysis"] = {
            "total_network_connections": total_connections,
            "avg_destination_diversity": round(avg_dest_diversity, 2),
            "high_risk_network_patterns": len([p for p in network_patterns if p["network_risk_score"] > 60])
        }
    
    # Authentication analysis
    if auth_patterns:
        total_failures = sum(p["failure_count"] for p in auth_patterns)
        avg_failure_rate = sum(p["failure_rate"] for p in auth_patterns) / len(auth_patterns)
        
        analysis["authentication_analysis"] = {
            "total_auth_failures": total_failures,
            "avg_failure_rate": round(avg_failure_rate, 2),
            "users_with_high_failures": len([p for p in auth_patterns if p["failure_rate"] > 50]),
            "multi_location_users": len([p for p in auth_patterns if p["geographic_diversity"] > 2])
        }
    
    # File access analysis
    if file_patterns:
        total_file_access = sum(p["access_frequency"] for p in file_patterns)
        high_risk_files = len([p for p in file_patterns if p["risk_level"] == "High"])
        
        analysis["file_access_analysis"] = {
            "total_file_access_events": total_file_access,
            "unique_files_accessed": len(file_patterns),
            "high_risk_file_access": high_risk_files
        }
    
    # Overall risk assessment
    high_risk_events = 0
    total_events = 0
    
    for event_list in [correlation_events, access_events]:
        for event in event_list:
            if "risk_assessment" in event or "risk_indicators" in event:
                risk_data = event.get("risk_assessment", event.get("risk_indicators", {}))
                if risk_data.get("risk_level") in ["Critical", "High"]:
                    high_risk_events += 1
            total_events += 1
    
    analysis["risk_assessment"] = {
        "high_risk_behavioral_events": high_risk_events,
        "total_behavioral_events": total_events,
        "risk_percentage": (high_risk_events / max(1, total_events)) * 100,
        "overall_behavioral_risk": "High" if high_risk_events > total_events * 0.3 else "Medium" if high_risk_events > 0 else "Low"
    }
    
    return analysis


def _generate_comprehensive_insights(correlation_events: List[Dict], access_events: List[Dict], 
                                   network_patterns: List[Dict], analysis: Dict) -> List[str]:
    """Generate comprehensive behavioral insights"""
    insights = []
    
    if not any([correlation_events, access_events, network_patterns]):
        return ["No behavioral events available for comprehensive analysis"]
    
    # Temporal insights
    peak_hour, peak_count = analysis.get("temporal_patterns", {}).get("peak_activity_hour", (0, 0))
    if peak_count > 0:
        insights.append(f"Peak behavioral activity at hour {peak_hour} with {peak_count} total events")
    
    night_activity_pct = analysis.get("temporal_patterns", {}).get("night_activity_percentage", 0)
    if night_activity_pct > 20:
        insights.append(f"Significant after-hours behavioral activity: {night_activity_pct:.1f}% of total activity")
    
    # Correlation insights
    strong_correlations = analysis.get("correlation_analysis", {}).get("strong_correlations", 0)
    if strong_correlations > 5:
        insights.append(f"Detected {strong_correlations} strong entity correlations - potential coordinated behavior")
    
    # Access behavior insights
    high_risk_access = analysis.get("access_behavior_analysis", {}).get("high_risk_access_events", 0)
    if high_risk_access > 0:
        insights.append(f"Identified {high_risk_access} high-risk access patterns requiring investigation")
    
    # Network behavior insights
    high_risk_network = analysis.get("network_behavior_analysis", {}).get("high_risk_network_patterns", 0)
    if high_risk_network > 0:
        insights.append(f"Detected {high_risk_network} high-risk network behavioral patterns")
    
    # Authentication insights
    multi_location_users = analysis.get("authentication_analysis", {}).get("multi_location_users", 0)
    if multi_location_users > 0:
        insights.append(f"Found {multi_location_users} users authenticating from multiple locations")
    
    return insights


def _generate_comprehensive_recommendations(analysis: Dict) -> List[str]:
    """Generate comprehensive recommendations based on behavioral analysis"""
    recommendations = []
    
    # Risk-based recommendations
    overall_risk = analysis.get("risk_assessment", {}).get("overall_behavioral_risk", "Low")
    if overall_risk == "High":
        recommendations.append("Critical: High-risk behavioral patterns detected - immediate comprehensive security review required")
    elif overall_risk == "Medium":
        recommendations.append("Warning: Some risky behavioral patterns detected - enhanced monitoring and investigation recommended")
    
    # Night activity recommendations
    night_activity_pct = analysis.get("temporal_patterns", {}).get("night_activity_percentage", 0)
    if night_activity_pct > 30:
        recommendations.append("High after-hours behavioral activity detected - review business justification and implement additional controls")
    
    # Correlation recommendations
    strong_correlations = analysis.get("correlation_analysis", {}).get("strong_correlations", 0)
    if strong_correlations > 10:
        recommendations.append("Strong behavioral correlations detected - analyze for potential coordinated attacks or automation")
    
    # Authentication recommendations
    high_failure_users = analysis.get("authentication_analysis", {}).get("users_with_high_failures", 0)
    multi_location_users = analysis.get("authentication_analysis", {}).get("multi_location_users", 0)
    
    if high_failure_users > 5:
        recommendations.append(f"Multiple users with high failure rates - investigate potential brute force attacks")
    
    if multi_location_users > 3:
        recommendations.append(f"Users authenticating from multiple locations - review for potential account compromise")
    
    # Network recommendations
    high_risk_network = analysis.get("network_behavior_analysis", {}).get("high_risk_network_patterns", 0)
    if high_risk_network > 3:
        recommendations.append("Multiple high-risk network patterns - review network access policies and monitoring")
    
    # File access recommendations
    high_risk_files = analysis.get("file_access_analysis", {}).get("high_risk_file_access", 0)
    if high_risk_files > 5:
        recommendations.append("High-risk file access patterns detected - review file access controls and monitoring")
    
    if not recommendations:
        recommendations.append("Behavioral patterns appear normal based on comprehensive analysis")
    
    return recommendations