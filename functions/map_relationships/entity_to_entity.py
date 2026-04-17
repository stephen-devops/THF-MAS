"""
Map direct relationships between entities using OpenSearch aggregations
"""
from typing import Dict, Any, List, Optional
import structlog
from .relationship_types import infer_relationship_type, get_relationship_description, get_reverse_relationship

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map direct relationships between entities using aggregation-based approach
    Supports BIDIRECTIONAL relationship queries (both outbound and inbound)

    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including source_type, source_id, target_type, timeframe, bidirectional

    Returns:
        Direct entity relationships with connection strength and analysis
    """
    try:
        # Extract parameters
        source_type = params.get("source_type")
        source_id = params.get("source_id")
        target_type = params.get("target_type")
        filters = params.get("filters")
        timeframe = params.get("timeframe", "24h")
        bidirectional = params.get("bidirectional", True)  # Default to bidirectional

        # Ensure filters is a dict or None
        if filters is None:
            filters = {}
        elif not isinstance(filters, dict):
            logger.warning("filters parameter is not a dict, converting", filters=filters, type=type(filters))
            filters = {}

        logger.info("Executing aggregated entity-to-entity relationship mapping",
                   source_type=source_type,
                   source_id=source_id,
                   target_type=target_type,
                   filters=filters,
                   timeframe=timeframe,
                   bidirectional=bidirectional)

        # Build time range filter
        time_filter = opensearch_client.build_single_time_filter(timeframe)

        # Execute OUTBOUND query (source_entity → target_entities)
        outbound_query = _build_relationship_aggregation_query(source_type, source_id, target_type, time_filter, filters)

        outbound_response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=outbound_query,
            size=0  # Only aggregations needed
        )

        # Process outbound results
        total_alerts_outbound = outbound_response["aggregations"]["total_count"]["value"]
        outbound_aggregations = outbound_response.get("aggregations", {})

        logger.info("Retrieved outbound relationship data", total_alerts=total_alerts_outbound)

        # Execute INBOUND query (target_entities → source_entity) if bidirectional and source_id provided
        inbound_aggregations = None
        total_alerts_inbound = 0

        if bidirectional and source_id:
            logger.info("Executing inbound relationship query for bidirectional mapping")

            inbound_query = _build_reverse_relationship_aggregation_query(source_type, source_id, target_type, time_filter, filters)

            inbound_response = await opensearch_client.search(
                index=opensearch_client.alerts_index,
                query=inbound_query,
                size=0
            )

            total_alerts_inbound = inbound_response["aggregations"]["total_count"]["value"]
            inbound_aggregations = inbound_response.get("aggregations", {})

            logger.info("Retrieved inbound relationship data", total_alerts=total_alerts_inbound)

        # Combine total alerts
        total_alerts = total_alerts_outbound + total_alerts_inbound
        
        # Process relationship network from aggregations
        relationships = []
        relationship_summary = {
            "source_entity": {"type": source_type, "id": source_id},
            "target_entity": {"type": target_type, "id": "multiple" if not target_type else "specified"},
            "total_connections": 0,
            "timeframe": timeframe,
            "connection_types": set(),
            "unique_targets": set(),
            "relationship_strength_distribution": {},
            "temporal_patterns": {},
            "bidirectional": bidirectional
        }

        # Process OUTBOUND relationships (source_entity → target_entities)
        if "source_entities" in outbound_aggregations:
            outbound_relationships = _process_aggregation_buckets(
                aggregations=outbound_aggregations,
                source_type=source_type,
                is_reverse=False
            )
            relationships.extend(outbound_relationships)

        # Process INBOUND relationships (target_entities → source_entity)
        if inbound_aggregations and "source_entities" in inbound_aggregations:
            inbound_relationships = _process_aggregation_buckets(
                aggregations=inbound_aggregations,
                source_type=source_type,
                is_reverse=True
            )
            relationships.extend(inbound_relationships)

        # Update relationship summary
        for rel in relationships:
            relationship_summary["connection_types"].update(rel["connection_types"])
            relationship_summary["unique_targets"].add(rel["target_entity"]["id"])
            relationship_summary["total_connections"] += rel["connection_strength"]

        # Convert sets to lists and add summary statistics
        relationship_summary["connection_types"] = list(relationship_summary["connection_types"])
        relationship_summary["unique_targets"] = list(relationship_summary["unique_targets"])
        relationship_summary["unique_target_count"] = len(relationship_summary["unique_targets"])
        relationship_summary["avg_connection_strength"] = (
            relationship_summary["total_connections"] / len(relationships) if relationships else 0
        )

        # Generate enhanced analysis (combine both aggregation sources)
        combined_aggregations = outbound_aggregations if not inbound_aggregations else {
            **outbound_aggregations,
            "inbound": inbound_aggregations
        }
        analysis = _analyze_aggregated_relationships(relationships, combined_aggregations)
        
        # Build result
        result = {
            "relationship_type": "entity_to_entity",
            "search_parameters": {
                "source_type": source_type,
                "source_id": source_id,
                "target_type": target_type,
                "timeframe": timeframe,
                "bidirectional": bidirectional,
                "data_source": "opensearch_alerts"
            },
            "relationship_summary": relationship_summary,
            "relationships": relationships,
            "analysis": analysis,
            "recommendations": _generate_aggregated_recommendations(relationships, analysis)
        }
        
        logger.info("Aggregated entity-to-entity relationship mapping completed", 
                   total_relationships=len(relationships),
                   unique_targets=len(relationship_summary["unique_targets"]),
                   total_connections=relationship_summary["total_connections"])
        
        return result
        
    except Exception as e:
        logger.error("Aggregated entity-to-entity relationship mapping failed", error=str(e))
        raise Exception(f"Failed to map entity relationships: {str(e)}")


def _get_flexible_aggregation_terms(source_type: str, target_type: Optional[str]) -> Dict[str, Any]:
    """
    Get flexible aggregation terms that handle multiple process field types

    For process-to-process queries, Event ID 8 (injection) uses sourceImage,
    while Event ID 1 (process create) uses image. This function returns
    aggregation terms that coalesce these fields.

    Args:
        source_type: Source entity type
        target_type: Target entity type

    Returns:
        Dict with either standard "field" or script-based "script" aggregation
    """
    if source_type.lower() == "process" and target_type and target_type.lower() == "process":
        # Use script to coalesce process fields: prefer image, fallback to sourceImage
        # This captures both Event ID 1 (image) and Event ID 8 (sourceImage)
        return {
            "script": {
                "source": """
                    if (doc.containsKey('data.win.eventdata.image.keyword') &&
                        doc['data.win.eventdata.image.keyword'].size() > 0) {
                        return doc['data.win.eventdata.image.keyword'].value;
                    } else if (doc.containsKey('data.win.eventdata.sourceImage.keyword') &&
                               doc['data.win.eventdata.sourceImage.keyword'].size() > 0) {
                        return doc['data.win.eventdata.sourceImage.keyword'].value;
                    } else {
                        return 'unknown';
                    }
                """,
                "lang": "painless"
            },
            "size": 100
        }
    else:
        # Standard field-based aggregation for other entity types
        return {
            "field": _get_entity_field(source_type),
            "size": 100
        }


def _build_relationship_aggregation_query(source_type: str, source_id: Optional[str], target_type: Optional[str], time_filter: Dict[str, Any], filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build aggregation query for relationship mapping"""

    # Build source entity filter (only if source_id is provided)
    source_filters = _get_entity_filters(source_type, source_id) if source_id else []

    # Build additional filters (e.g., host filter)
    additional_filters = []
    if filters:
        if "host" in filters:
            additional_filters.append({
                "bool": {
                    "should": [
                        {"term": {"agent.name": filters["host"]}},
                        {"wildcard": {"agent.name": f"*{filters['host']}*"}}
                    ]
                }
            })
        if "user" in filters:
            additional_filters.append({
                "bool": {
                    "should": [
                        {"wildcard": {"data.srcuser": f"*{filters['user']}*"}},
                        {"wildcard": {"data.dstuser": f"*{filters['user']}*"}},
                        {"wildcard": {"data.win.eventdata.user": f"*{filters['user']}*"}},  # ADDED: Sysmon process execution user
                        {"wildcard": {"data.win.eventdata.targetUserName": f"*{filters['user']}*"}},
                        {"wildcard": {"data.win.eventdata.subjectUserName": f"*{filters['user']}*"}}
                    ]
                }
            })

    # Add exists filter for the entity field we're aggregating on
    # For process-to-process queries, we need to be flexible to capture all process events:
    # - Event ID 1 (Process Create): has "image" and "parentImage"
    # - Event ID 8 (CreateRemoteThread/Injection): has "sourceImage" and "targetImage" (NO "image")
    # - Event ID 10 (Process Access): has "sourceImage" and "targetImage"
    # Solution: For process queries, accept events with ANY process field
    entity_field = _get_entity_field(source_type)

    if source_type.lower() == "process" and target_type and target_type.lower() == "process":
        # Process-to-process: accept events with ANY process-related field
        # This captures Event ID 8 (sourceImage/targetImage), Event ID 1 (image/parentImage), etc.
        field_exists_filter = {
            "bool": {
                "should": [
                    {"exists": {"field": "data.win.eventdata.image"}},           # Event ID 1 (main process)
                    {"exists": {"field": "data.win.eventdata.sourceImage"}},     # Event ID 8, 10 (injector/accessor)
                    {"exists": {"field": "data.win.eventdata.targetImage"}},     # Event ID 8, 10 (victim/target)
                    {"exists": {"field": "data.win.eventdata.parentImage"}}      # Event ID 1 (parent process)
                ],
                "minimum_should_match": 1
            }
        }
    else:
        # Other entity types: use standard exists filter
        field_exists_filter = {"exists": {"field": entity_field}}

    query = {
        "query": {
            "bool": {
                "must": [time_filter, field_exists_filter] + source_filters + additional_filters
            }
        },
        "aggs": {
            "total_count": {
                "value_count": {
                    "field": "_id"
                }
            },
            "source_entities": {
                # For process-to-process: use script to coalesce process fields
                # This handles Event ID 8 (sourceImage) and Event ID 1 (image)
                "terms": _get_flexible_aggregation_terms(source_type, target_type),
                "aggs": {
                    # Multiple user aggregations to capture different event types
                    "connected_users_auth": {
                        "terms": {
                            "field": "data.win.eventdata.targetUserName",
                            "size": 50
                        },
                        "aggs": _get_connection_sub_aggregations()
                    },
                    "connected_users_sysmon": {
                        "terms": {
                            "field": "data.win.eventdata.user",
                            "size": 50
                        },
                        "aggs": _get_connection_sub_aggregations()
                    },
                    "connected_users_subject": {
                        "terms": {
                            "field": "data.win.eventdata.subjectUserName",
                            "size": 50
                        },
                        "aggs": _get_connection_sub_aggregations()
                    },
                    "connected_hosts": {
                        "terms": {
                            "field": "agent.name",
                            "size": 50
                        },
                        "aggs": _get_connection_sub_aggregations()
                    },
                    "connected_processes": {
                        "terms": {
                            "field": "data.win.eventdata.image",
                            "size": 30
                        },
                        "aggs": _get_connection_sub_aggregations()
                    },
                    "connected_processes_parent": {
                        "terms": {
                            "field": "data.win.eventdata.parentImage",  # Parent processes (spawners)
                            "size": 30
                        },
                        "aggs": _get_connection_sub_aggregations()
                    },
                    "connected_processes_source": {
                        "terms": {
                            "field": "data.win.eventdata.sourceImage",  # Source processes (injectors, accessors)
                            "size": 30
                        },
                        "aggs": _get_connection_sub_aggregations()
                    },
                    "connected_files": {
                        "terms": {
                            "field": "data.win.eventdata.targetFilename",
                            "size": 30
                        },
                        "aggs": _get_connection_sub_aggregations()
                    },
                    "connected_files_loaded": {
                        "terms": {
                            "field": "data.win.eventdata.imageLoaded",  # DLL/Image load events (Event ID 7)
                            "size": 30
                        },
                        "aggs": _get_connection_sub_aggregations()
                    }
                }
            }
        }
    }
    
    return query


def _process_aggregation_buckets(
    aggregations: Dict[str, Any],
    source_type: str,
    is_reverse: bool
) -> List[Dict[str, Any]]:
    """
    Process aggregation buckets and extract relationships

    Args:
        aggregations: OpenSearch aggregation results
        source_type: The original source entity type from the query
        is_reverse: True if processing inbound relationships (reversed direction)

    Returns:
        List of relationship dictionaries
    """
    relationships = []

    # Map aggregation names to entity types
    # Multiple user aggregations to capture different event types
    target_mappings = {
        "connected_users_auth": "user",      # Authentication events (targetUserName)
        "connected_users_sysmon": "user",    # Sysmon events (user)
        "connected_users_subject": "user",   # Subject user (subjectUserName)
        "connected_hosts": "host",
        "connected_processes": "process",           # Child processes (image)
        "connected_processes_parent": "process",    # Parent processes (parentImage)
        "connected_processes_source": "process",    # Source processes (injectors, accessors)
        "connected_files": "file",                  # File operations (targetFilename)
        "connected_files_loaded": "file"            # DLL/Image loads (imageLoaded)
    }

    if "source_entities" not in aggregations:
        return relationships

    for source_bucket in aggregations["source_entities"]["buckets"]:
        source_entity_name = source_bucket["key"]

        # Process each target type
        for agg_name, target_entity_type in target_mappings.items():
            if agg_name in source_bucket:
                for target_bucket in source_bucket[agg_name]["buckets"]:
                    target_entity_name = target_bucket["key"]
                    connection_strength = target_bucket["doc_count"]

                    # Extract connection types from rule groups
                    connection_types = [b["key"] for b in target_bucket.get("connection_types", {}).get("buckets", [])]

                    # Get temporal pattern
                    temporal_pattern = []
                    if "temporal_distribution" in target_bucket:
                        temporal_pattern = [
                            {"timestamp": b["key_as_string"], "count": b["doc_count"]}
                            for b in target_bucket["temporal_distribution"]["buckets"]
                        ]

                    # Get latest connection example and infer relationship type
                    latest_connection = None
                    relationship_type_label = "connected_to"  # default

                    if target_bucket.get("latest_connection", {}).get("hits", {}).get("hits"):
                        latest_hit = target_bucket["latest_connection"]["hits"]["hits"][0]["_source"]
                        latest_connection = {
                            "timestamp": latest_hit.get("@timestamp", ""),
                            "rule_description": latest_hit.get("rule", {}).get("description", ""),
                            "rule_level": latest_hit.get("rule", {}).get("level", 0),
                            "rule_id": latest_hit.get("rule", {}).get("id", "")
                        }

                        # Infer relationship type based on direction
                        if is_reverse:
                            # For inbound: infer from target_entity → source_entity perspective
                            # Then get the REVERSE label for correct semantics
                            forward_relationship = infer_relationship_type(
                                source_type=target_entity_type,
                                target_type=source_type,
                                event_data=latest_hit
                            )
                            # Get reverse relationship (e.g., "spawned" → "spawned_by")
                            relationship_type_label = get_reverse_relationship(forward_relationship)
                        else:
                            # For outbound: use direct inference
                            relationship_type_label = infer_relationship_type(
                                source_type=source_type,
                                target_type=target_entity_type,
                                event_data=latest_hit
                            )

                    # Calculate relationship metrics
                    avg_severity = target_bucket.get("avg_severity", {}).get("value", 0)
                    relationship_score = min(100, (connection_strength * avg_severity) / 10)

                    # Build relationship data with correct direction
                    if is_reverse:
                        # Inbound: target_entity → source_entity
                        relationship_data = {
                            "source_entity": {"type": target_entity_type, "id": target_entity_name},
                            "target_entity": {"type": source_type, "id": source_entity_name},
                            "relationship_type": relationship_type_label,
                            "relationship_description": get_relationship_description(relationship_type_label),
                            "connection_strength": connection_strength,
                            "connection_types": connection_types,
                            "temporal_pattern": temporal_pattern,
                            "latest_connection": latest_connection,
                            "avg_severity": round(avg_severity, 2),
                            "relationship_score": round(relationship_score, 2),
                            "risk_assessment": _assess_relationship_risk(connection_strength, avg_severity, connection_types),
                            "direction": "inbound"
                        }
                    else:
                        # Outbound: source_entity → target_entity
                        relationship_data = {
                            "source_entity": {"type": source_type, "id": source_entity_name},
                            "target_entity": {"type": target_entity_type, "id": target_entity_name},
                            "relationship_type": relationship_type_label,
                            "relationship_description": get_relationship_description(relationship_type_label),
                            "connection_strength": connection_strength,
                            "connection_types": connection_types,
                            "temporal_pattern": temporal_pattern,
                            "latest_connection": latest_connection,
                            "avg_severity": round(avg_severity, 2),
                            "relationship_score": round(relationship_score, 2),
                            "risk_assessment": _assess_relationship_risk(connection_strength, avg_severity, connection_types),
                            "direction": "outbound"
                        }

                    # Filter out self-referential relationships
                    if source_entity_name == target_entity_name:
                        logger.debug("Skipping self-referential relationship",
                                   entity=source_entity_name)
                        continue

                    relationships.append(relationship_data)

    return relationships


def _build_reverse_relationship_aggregation_query(
    source_type: str,
    source_id: str,
    target_type: Optional[str],
    time_filter: Dict[str, Any],
    filters: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Build aggregation query for INBOUND relationships (target_entities → source_entity)

    This searches for events WHERE the source_entity appears as a TARGET in the data
    """
    # Build target entity filters (source_entity appears as target in events)
    target_filters = _get_reverse_entity_filters(source_type, source_id)

    # Build additional filters (e.g., host filter)
    additional_filters = []
    if filters:
        if "host" in filters:
            additional_filters.append({
                "bool": {
                    "should": [
                        {"term": {"agent.name": filters["host"]}},
                        {"wildcard": {"agent.name": f"*{filters['host']}*"}}
                    ]
                }
            })
        if "user" in filters:
            additional_filters.append({
                "bool": {
                    "should": [
                        {"wildcard": {"data.srcuser": f"*{filters['user']}*"}},
                        {"wildcard": {"data.dstuser": f"*{filters['user']}*"}},
                        {"wildcard": {"data.win.eventdata.user": f"*{filters['user']}*"}},  # ADDED: Sysmon process execution user
                        {"wildcard": {"data.win.eventdata.targetUserName": f"*{filters['user']}*"}},
                        {"wildcard": {"data.win.eventdata.subjectUserName": f"*{filters['user']}*"}}
                    ]
                }
            })

    # Build entity-specific aggregations based on source_type
    entity_aggregations = _get_reverse_entity_aggregations(source_type)

    # Add exists filter for the field we're aggregating on
    # For process-to-process queries (inbound), we need the same flexibility as outbound
    # to capture Event ID 8 (sourceImage/targetImage) and other process events
    reverse_field = _get_reverse_aggregation_field(source_type)

    if source_type.lower() == "process" and target_type and target_type.lower() == "process":
        # Process-to-process (inbound): accept events with ANY process-related field
        reverse_field_exists_filter = {
            "bool": {
                "should": [
                    {"exists": {"field": "data.win.eventdata.image"}},           # Event ID 1
                    {"exists": {"field": "data.win.eventdata.sourceImage"}},     # Event ID 8, 10
                    {"exists": {"field": "data.win.eventdata.targetImage"}},     # Event ID 8, 10
                    {"exists": {"field": "data.win.eventdata.parentImage"}}      # Event ID 1
                ],
                "minimum_should_match": 1
            }
        }
    else:
        # Other entity types: use standard exists filter
        reverse_field_exists_filter = {"exists": {"field": reverse_field}}

    # Build query - aggregate on SOURCE entities (those that point TO our target)
    query = {
        "query": {
            "bool": {
                "must": [time_filter, reverse_field_exists_filter] + target_filters + additional_filters
            }
        },
        "aggs": {
            "total_count": {
                "value_count": {
                    "field": "_id"
                }
            },
            "source_entities": {
                # For process-to-process inbound: use script to handle targetImage (Event ID 8 victims)
                "terms": _get_flexible_reverse_aggregation_terms(source_type, target_type),
                "aggs": entity_aggregations
            }
        }
    }

    return query


def _get_flexible_reverse_aggregation_terms(source_type: str, target_type: Optional[str]) -> Dict[str, Any]:
    """
    Get flexible aggregation terms for reverse (inbound) queries

    For process-to-process inbound queries, we aggregate on the SOURCE of the relationship
    (the entity pointing TO our target). Event ID 8 uses targetImage field.

    Args:
        source_type: Source entity type
        target_type: Target entity type

    Returns:
        Dict with either standard "field" or script-based "script" aggregation
    """
    if source_type.lower() == "process" and target_type and target_type.lower() == "process":
        # For inbound process queries, aggregate on whatever process field exists
        # Event ID 8: targetImage (the victim process) appears in our filter
        # We aggregate on parentImage or image (the sources pointing to our target)
        return {
            "script": {
                "source": """
                    if (doc.containsKey('data.win.eventdata.parentImage.keyword') &&
                        doc['data.win.eventdata.parentImage.keyword'].size() > 0) {
                        return doc['data.win.eventdata.parentImage.keyword'].value;
                    } else if (doc.containsKey('data.win.eventdata.image.keyword') &&
                               doc['data.win.eventdata.image.keyword'].size() > 0) {
                        return doc['data.win.eventdata.image.keyword'].value;
                    } else if (doc.containsKey('data.win.eventdata.sourceImage.keyword') &&
                               doc['data.win.eventdata.sourceImage.keyword'].size() > 0) {
                        return doc['data.win.eventdata.sourceImage.keyword'].value;
                    } else {
                        return 'unknown';
                    }
                """,
                "lang": "painless"
            },
            "size": 100
        }
    else:
        # Standard field-based aggregation for other entity types
        return {
            "field": _get_reverse_aggregation_field(source_type),
            "size": 100
        }


def _get_reverse_entity_aggregations(source_type: str) -> Dict[str, Any]:
    """
    Get entity-specific aggregations for reverse (inbound) queries

    Args:
        source_type: The entity type we're querying (e.g., 'process', 'file')

    Returns:
        Dictionary of aggregations appropriate for this entity type's inbound relationships
    """
    # Common aggregations for all entity types
    # Multiple user aggregations to capture different event types
    common_aggs = {
        "connected_users_auth": {
            "terms": {
                "field": "data.win.eventdata.targetUserName",
                "size": 50
            },
            "aggs": _get_connection_sub_aggregations()
        },
        "connected_users_sysmon": {
            "terms": {
                "field": "data.win.eventdata.user",
                "size": 50
            },
            "aggs": _get_connection_sub_aggregations()
        },
        "connected_users_subject": {
            "terms": {
                "field": "data.win.eventdata.subjectUserName",
                "size": 50
            },
            "aggs": _get_connection_sub_aggregations()
        },
        "connected_hosts": {
            "terms": {
                "field": "agent.name",
                "size": 50
            },
            "aggs": _get_connection_sub_aggregations()
        },
    }

    # Entity-specific aggregations
    if source_type.lower() == "process":
        # For Process inbound: find parent processes and files involved in events
        return {
            **common_aggs,
            "connected_processes": {
                "terms": {
                    "field": "data.win.eventdata.parentImage",  # Parent processes
                    "size": 30
                },
                "aggs": _get_connection_sub_aggregations()
            },
            "connected_processes_parent": {
                "terms": {
                    "field": "data.win.eventdata.image",  # Child processes (for reverse query)
                    "size": 30
                },
                "aggs": _get_connection_sub_aggregations()
            },
            "connected_files": {
                "terms": {
                    "field": "data.win.eventdata.targetFilename",  # Files involved in the events
                    "size": 30
                },
                "aggs": _get_connection_sub_aggregations()
            },
            "connected_files_loaded": {
                "terms": {
                    "field": "data.win.eventdata.imageLoaded",  # DLL/Image loads
                    "size": 30
                },
                "aggs": _get_connection_sub_aggregations()
            }
        }
    elif source_type.lower() == "file":
        # For File inbound: find processes and users that operated on the file
        return {
            **common_aggs,
            "connected_processes": {
                "terms": {
                    "field": "data.win.eventdata.image",  # Processes operating on file
                    "size": 30
                },
                "aggs": _get_connection_sub_aggregations()
            }
        }
    elif source_type.lower() == "user":
        # For User inbound: find processes and hosts involved
        return {
            **common_aggs,
            "connected_processes": {
                "terms": {
                    "field": "data.win.eventdata.image",  # Processes in user context
                    "size": 30
                },
                "aggs": _get_connection_sub_aggregations()
            }
        }
    elif source_type.lower() == "host":
        # For Host inbound: find users and processes
        return {
            **common_aggs,
            "connected_processes": {
                "terms": {
                    "field": "data.win.eventdata.image",  # Processes on host
                    "size": 30
                },
                "aggs": _get_connection_sub_aggregations()
            }
        }
    else:
        # Default: return common aggregations only
        return common_aggs


def _get_connection_sub_aggregations() -> Dict[str, Any]:
    """Get common sub-aggregations for connection analysis"""
    return {
        "connection_types": {
            "terms": {"field": "rule.groups", "size": 10}
        },
        "avg_severity": {
            "avg": {"field": "rule.level"}
        },
        "temporal_distribution": {
            "date_histogram": {
                "field": "@timestamp",
                "fixed_interval": "1h"
            }
        },
        "latest_connection": {
            "top_hits": {
                "size": 1,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": [
                    "@timestamp", "rule.description", "rule.level", "rule.id",
                    "rule.groups", "data.win.system.eventID",
                    "data.win.eventdata", "data"
                ]
            }
        }
    }


def _get_reverse_entity_filters(entity_type: str, entity_id: str) -> List[Dict[str, Any]]:
    """
    Get filters for finding events WHERE entity appears as a TARGET
    (for inbound relationship queries)
    """
    filters = []

    if entity_type.lower() == "process":
        # Find events where this process is the TARGET
        filters.append({
            "bool": {
                "should": [
                    # Process as child/target (parent created this process)
                    {"wildcard": {"data.win.eventdata.image": f"*{entity_id}*"}},
                    # Process as target in operations
                    {"wildcard": {"data.win.eventdata.targetImage": f"*{entity_id}*"}},
                    {"wildcard": {"data.process": f"*{entity_id}*"}}
                ]
            }
        })
    elif entity_type.lower() == "file":
        # Find events where this file is the TARGET
        filters.append({
            "bool": {
                "should": [
                    {"wildcard": {"data.win.eventdata.targetFilename": f"*{entity_id}*"}},
                    {"wildcard": {"data.file": f"*{entity_id}*"}}
                ]
            }
        })
    elif entity_type.lower() == "user":
        # Find events where this user is the TARGET
        filters.append({
            "bool": {
                "should": [
                    {"wildcard": {"data.win.eventdata.targetUserName": f"*{entity_id}*"}},
                    {"wildcard": {"data.dstuser": f"*{entity_id}*"}}
                ]
            }
        })
    elif entity_type.lower() == "host":
        # Find events where this host is the TARGET
        filters.append({
            "bool": {
                "should": [
                    {"term": {"agent.name": entity_id}},
                    {"wildcard": {"agent.name": f"*{entity_id}*"}}
                ]
            }
        })

    return filters


def _get_reverse_aggregation_field(entity_type: str) -> str:
    """
    Get the field to aggregate on for reverse queries
    (find SOURCE entities that point TO the target)
    """
    field_mapping = {
        "process": "data.win.eventdata.parentImage",  # Parent processes
        "file": "data.win.eventdata.image",            # Processes operating on file
        "user": "data.win.eventdata.subjectUserName",  # Users acting on target user
        "host": "data.win.eventdata.image"             # Processes/entities on host
    }
    return field_mapping.get(entity_type.lower(), "agent.name")


def _get_entity_filters(entity_type: str, entity_id: Optional[str]) -> List[Dict[str, Any]]:
    """Get filters for specific entity type"""
    filters = []

    # If no entity_id provided, return empty filters
    if not entity_id:
        return filters

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
                    {"wildcard": {"data.win.eventdata.user": f"*{entity_id}*"}},  # ADDED: Sysmon process execution user
                    {"wildcard": {"data.win.eventdata.targetUserName": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.subjectUserName": f"*{entity_id}*"}}
                ]
            }
        })
    elif entity_type.lower() == "process":
        filters.append({
            "bool": {
                "should": [
                    {"wildcard": {"data.process": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.image": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.commandLine": f"*{entity_id}*"}}
                ]
            }
        })
    
    return filters


def _get_entity_field(entity_type: str) -> str:
    """Get the primary field for entity type used in aggregation grouping"""
    field_mapping = {
        "host": "agent.name",
        "user": "data.win.eventdata.user",  # FIXED: Use Sysmon process execution user field (was targetUserName)
        "process": "data.win.eventdata.image",
        "file": "data.win.eventdata.targetFilename"
    }
    return field_mapping.get(entity_type.lower(), "agent.name")


def _assess_relationship_risk(connection_strength: int, avg_severity: float, connection_types: List[str]) -> str:
    """Assess risk level of relationship"""
    risk_score = 0
    
    # Factor in connection strength
    if connection_strength > 100:
        risk_score += 30
    elif connection_strength > 50:
        risk_score += 20
    elif connection_strength > 10:
        risk_score += 10
    
    # Factor in average severity
    if avg_severity > 8:
        risk_score += 40
    elif avg_severity > 5:
        risk_score += 25
    elif avg_severity > 3:
        risk_score += 10
    
    # Factor in connection types
    high_risk_types = ["authentication_failed", "privilege_escalation", "malware", "attack"]
    if any(risk_type in " ".join(connection_types).lower() for risk_type in high_risk_types):
        risk_score += 30
    
    if risk_score > 70:
        return "Critical"
    elif risk_score > 40:
        return "High"
    elif risk_score > 20:
        return "Medium"
    else:
        return "Low"


def _analyze_aggregated_relationships(relationships: List[Dict[str, Any]], aggregations: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze relationships using aggregation data"""
    if not relationships:
        return {"message": "No relationships found"}
    
    analysis = {
        "relationship_patterns": {},
        "strength_distribution": {},
        "risk_assessment": {},
        "temporal_analysis": {}
    }
    
    # Analyze relationship strength distribution
    strength_values = [r["connection_strength"] for r in relationships]
    analysis["strength_distribution"] = {
        "min_strength": min(strength_values),
        "max_strength": max(strength_values),
        "avg_strength": sum(strength_values) / len(strength_values),
        "total_connections": sum(strength_values)
    }
    
    # Risk assessment
    risk_counts = {}
    for r in relationships:
        risk_level = r["risk_assessment"]
        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
    
    analysis["risk_assessment"] = {
        "risk_distribution": risk_counts,
        "high_risk_relationships": len([r for r in relationships if r["risk_assessment"] in ["Critical", "High"]]),
        "risk_percentage": (len([r for r in relationships if r["risk_assessment"] in ["Critical", "High"]]) / len(relationships)) * 100
    }
    
    return analysis


def _generate_aggregated_recommendations(relationships: List[Dict[str, Any]], analysis: Dict[str, Any]) -> List[str]:
    """Generate recommendations based on aggregated relationship analysis"""
    recommendations = []
    
    if not relationships:
        return ["No entity relationships found in the specified timeframe"]
    
    # High-risk relationship recommendations
    high_risk_count = analysis.get("risk_assessment", {}).get("high_risk_relationships", 0)
    if high_risk_count > 5:
        recommendations.append(f"Critical: {high_risk_count} high-risk relationships detected - immediate investigation required")
    elif high_risk_count > 0:
        recommendations.append(f"Warning: {high_risk_count} high-risk relationships found - review recommended")
    
    # Connection strength recommendations
    max_strength = analysis.get("strength_distribution", {}).get("max_strength", 0)
    if max_strength > 200:
        recommendations.append("Very high connection strength detected - investigate for potential automation or compromise")
    
    # General recommendations
    if len(relationships) > 100:
        recommendations.append("High relationship volume detected - consider narrowing timeframe for detailed analysis")
    
    if not recommendations:
        recommendations.append("Entity relationships appear normal based on aggregated analysis")
    
    return recommendations