"""
Analyze alert distribution patterns across various dimensions with multi-criteria grouping support
"""
from typing import Dict, Any, List, Union
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient, normalize_wazuh_array_fields

logger = structlog.get_logger()

async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze distribution patterns of alerts across multiple dimensions with dynamic grouping
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including time_range, filters, group_by, dimensions
        
    Returns:
        Multi-dimensional distribution analysis with cross-correlations
    """
    try:
        # Extract parameters
        time_range = params.get("time_range", "7d")
        filters = params.get("filters", {})

        # Handle case where filters is None FIRST
        if filters is None:
            filters = {}

        # Apply field mapping to convert user-friendly names to Wazuh field names
        field_mapping = get_field_mapping()
        mapped_filters = {}
        for key, value in filters.items():
            mapped_key = field_mapping.get(key, key)  # Use mapping if available, otherwise keep original
            mapped_filters[mapped_key] = value
        filters = mapped_filters

        # Handle intelligent process name filtering
        process_fields = ["data.win.eventdata.originalFileName", "data.win.eventdata.image"]
        for field in process_fields:
            if field in filters and isinstance(filters[field], str):
                process_value = filters[field]
                # Auto-append .exe if not present and not a full path
                if not process_value.endswith('.exe') and '\\' not in process_value and '/' not in process_value:
                    filters[field] = process_value + '.exe'
                    logger.info("Auto-corrected process name",
                               original=process_value, corrected=filters[field])

        # Handle intelligent rule filtering - redirect text searches to rule.description
        if "rule.id" in filters and isinstance(filters["rule.id"], str):
            rule_value = filters["rule.id"]
            # If rule value is not numeric, likely searching for rule content
            if not rule_value.isdigit():
                # Move to rule.description for text-based searches
                filters["rule.description"] = rule_value
                del filters["rule.id"]
                logger.info("Redirected text rule search to description",
                           search_term=rule_value)

        # Convert string values to arrays for known Wazuh array fields
        filters = normalize_wazuh_array_fields(filters)
        group_by = params.get("group_by", "severity")  # Can be string or list for multi-criteria
        dimensions = params.get("dimensions", "all")  # Selective dimension calculation
        
        # Handle separate time_start and time_end parameters from LLM
        time_start = filters.pop("time_start", None)
        time_end = filters.pop("time_end", None)
        
        # If we have separate start/end times, construct a time range
        if time_start and time_end:
            from datetime import date
            today = date.today().strftime("%Y-%m-%d")
            time_range = f"{time_start} until {time_end}"
            logger.info("Converting separate time parameters to range", 
                       time_start=time_start, time_end=time_end, time_range=time_range)
        
        # Handle time_range in filters (LLM sometimes puts it there instead of main params)
        filter_time_range = filters.pop("time_range", None)
        if filter_time_range:
            time_range = filter_time_range
            logger.info("Using time_range from filters", time_range=time_range)
        
        logger.info("Parameter extraction", group_by=group_by, group_by_type=type(group_by))
        
        # Enhanced parsing with temporal keyword detection
        def detect_temporal_keywords(text_input):
            """Detect temporal keywords in the input and add temporal dimension if found"""
            temporal_keywords = [
                "today", "hours", "hourly", "periods", "histogram", "temporal", 
                "timeline", "time", "hour", "minute", "daily", "bucket", "distribution over time"
            ]
            if isinstance(text_input, str):
                text_lower = text_input.lower()
                return any(keyword in text_lower for keyword in temporal_keywords)
            return False
        
        # Parse group_by parameter for multi-criteria support with temporal detection
        original_input = str(group_by) if group_by else ""
        has_temporal_keywords = detect_temporal_keywords(original_input)
        
        if isinstance(group_by, str):
            if "," in group_by:
                split_result = group_by.split(",")
                group_by_list = [dim.strip() for dim in split_result]
            else:
                group_by_list = [group_by]
        elif isinstance(group_by, list):
            group_by_list = group_by
        else:
            group_by_list = [str(group_by)] if group_by else ["severity"]
        
        # Auto-add temporal dimension if temporal keywords detected but not explicitly included
        temporal_aliases = ["time", "temporal", "timeline", "hourly", "hours", "today", "periods", "histogram"]
        has_explicit_temporal = any(dim.lower() in temporal_aliases for dim in group_by_list)
        
        if has_temporal_keywords and not has_explicit_temporal:
            group_by_list.append("time")
            logger.info("Auto-added temporal dimension based on keywords", 
                       original_input=original_input, group_by_list=group_by_list)
        
        logger.info("Analyzing alert distribution", 
                   time_range=time_range, 
                   filters=bool(filters),
                   group_by=group_by_list,
                   dimensions=dimensions)
        
        # Build dynamic aggregation query based on group_by and dimensions
        query = {
            "query": {
                "bool": {
                    "must": [
                        opensearch_client.build_single_time_filter(time_range)
                    ]
                }
            },
            "aggs": {
                "total_count": {
                    "value_count": {
                        "field": "_id"
                    }
                }
            }
        }
        
        # Enhanced multi-dimensional logic with better temporal handling
        logger.info("Enhanced distribution analysis", group_by_list=group_by_list, 
                   has_temporal=has_temporal_keywords, dimensions=dimensions)
        
        # Normalize dimension names for consistent matching
        normalized_dimensions = []
        for dim in group_by_list:
            dim_lower = dim.lower()
            if dim_lower in ["time", "temporal", "timeline", "hourly", "hours", "today", "periods", "histogram"]:
                normalized_dimensions.append("time")
            elif dim_lower in ["severity", "sev", "level"]:
                normalized_dimensions.append("severity")
            elif dim_lower in ["host", "hosts", "hostname"]:
                normalized_dimensions.append("host")
            elif dim_lower in ["rule", "rules", "rule_id"]:
                normalized_dimensions.append("rule")
            elif dim_lower in ["user", "users", "username"]:
                normalized_dimensions.append("user")
            elif dim_lower in ["rule_groups", "groups", "categories"]:
                normalized_dimensions.append("rule_groups")
            elif dim_lower in ["geographic", "geo", "ip", "location"]:
                normalized_dimensions.append("geographic")
            elif dim_lower in ["process", "processes", "proc"]:
                normalized_dimensions.append("process")
            else:
                normalized_dimensions.append("severity")  # Default fallback
        
        # Remove duplicates while preserving order
        seen = set()
        normalized_dimensions = [x for x in normalized_dimensions if not (x in seen or seen.add(x))]
        
        # Determine if this is a temporal query
        is_temporal = "time" in normalized_dimensions or has_temporal_keywords
        
        logger.info("Normalized dimensions", normalized_dimensions=normalized_dimensions, is_temporal=is_temporal)
        
        # Handle multi-dimensional analysis (2 or more dimensions)
        if len(normalized_dimensions) > 1:
            logger.info("Multi-dimensional analysis detected", dimensions_count=len(normalized_dimensions))
            
            # For temporal + another dimension, create both separate aggregations and composite if possible
            has_time_dim = "time" in normalized_dimensions
            other_dims = [dim for dim in normalized_dimensions if dim != "time"]
            
            if has_time_dim and other_dims:
                # Always include temporal distribution for histogram output
                query["aggs"]["time_distribution"] = build_enhanced_time_distribution(other_dims[0])
                logger.info("Added enhanced time distribution with breakdown", breakdown_dim=other_dims[0])
            
            # Try composite aggregation for multi-dimensional cross-analysis
            try:
                composite_agg = build_composite_aggregation(normalized_dimensions)
                query["aggs"]["multi_dimensional_distribution"] = composite_agg
                logger.info("Successfully built composite aggregation")
            except Exception as e:
                logger.warning("Composite aggregation failed, using separate aggregations", error=str(e))
            
            # Add individual dimension aggregations for completeness
            for dim in normalized_dimensions:
                if dim != "time":  # Time already handled above
                    agg_name = f"{dim}_distribution"
                    if dim == "severity":
                        query["aggs"][agg_name] = build_severity_distribution()
                    elif dim == "host":
                        query["aggs"][agg_name] = build_host_distribution()
                    elif dim == "rule":
                        query["aggs"][agg_name] = build_rule_distribution()
                    elif dim == "user":
                        query["aggs"][agg_name] = build_user_distribution()
                    elif dim == "rule_groups":
                        query["aggs"][agg_name] = build_rule_groups_distribution()
                    elif dim == "geographic":
                        query["aggs"][agg_name] = build_geographic_distribution()
                    elif dim == "process":
                        query["aggs"][agg_name] = build_process_distribution()
        
        # Single dimension analysis
        else:
            if not normalized_dimensions:
                normalized_dimensions = ["severity"]  # Default fallback
            
            primary_dim = normalized_dimensions[0]
            logger.info("Single dimension analysis", primary_dim=primary_dim)
            
            # Always check for 'all' dimensions or specific matches
            if dimensions == "all" or primary_dim == "severity":
                query["aggs"]["severity_distribution"] = build_severity_distribution()
            
            if dimensions == "all" or primary_dim == "host":
                query["aggs"]["host_distribution"] = build_host_distribution()
            
            if dimensions == "all" or primary_dim == "rule":
                query["aggs"]["rule_distribution"] = build_rule_distribution()
            
            if dimensions == "all" or primary_dim == "user":
                query["aggs"]["user_distribution"] = build_user_distribution()
            
            if dimensions == "all" or primary_dim == "time":
                query["aggs"]["time_distribution"] = build_time_distribution()
            
            if dimensions == "all" or primary_dim == "rule_groups":
                query["aggs"]["rule_groups_distribution"] = build_rule_groups_distribution()
            
            if dimensions == "all" or primary_dim == "geographic":
                query["aggs"]["geographic_distribution"] = build_geographic_distribution()
            
            if dimensions == "all" or primary_dim == "process":
                query["aggs"]["process_distribution"] = build_process_distribution()
        
        # Add filters if provided
        if filters:
            filter_queries = opensearch_client.build_filters_query(filters)
            query["query"]["bool"]["must"].extend(filter_queries)
        
        # Execute query
        response = await opensearch_client.search(
            opensearch_client.alerts_index, 
            query, 
            size=0  # We only want aggregations
        )
        
        # Format results
        total_alerts = response["aggregations"]["total_count"]["value"]
        
        # Process results based on aggregation type
        result_data = {}
        
        if "multi_dimensional_distribution" in response["aggregations"]:
            # Process composite aggregation results
            try:
                logger.info("Processing composite aggregation response", 
                           group_by_list=group_by_list,
                           aggregation_type=type(response["aggregations"]["multi_dimensional_distribution"]))
                result_data = process_composite_results(response["aggregations"]["multi_dimensional_distribution"], total_alerts, group_by_list)
                logger.info("Successfully processed composite results")
            except Exception as e:
                import traceback
                logger.error("Error processing composite results", 
                           error=str(e), 
                           group_by_list=group_by_list,
                           traceback=traceback.format_exc())
                # Fallback to empty result
                result_data = {
                    "multi_dimensional": [],
                    "grouping_criteria": group_by_list,
                    "total_combinations": 0,
                    "error": f"Multi-dimensional processing failed: {str(e)}"
                }
            
            # ALSO process individual distributions for enhanced output (especially temporal)
            logger.info("Processing individual distributions alongside composite results")
            
        # Process individual dimension results (both for single and multi-dimensional queries)
        if "severity_distribution" in response["aggregations"]:
            result_data["severity"] = process_severity_distribution(response["aggregations"]["severity_distribution"], total_alerts)
        
        if "host_distribution" in response["aggregations"]:
            result_data["hosts"] = process_host_distribution(response["aggregations"]["host_distribution"], total_alerts)
        
        if "rule_distribution" in response["aggregations"]:
            result_data["rules"] = process_rule_distribution(response["aggregations"]["rule_distribution"], total_alerts)
        
        if "user_distribution" in response["aggregations"]:
            result_data["users"] = process_user_distribution(response["aggregations"]["user_distribution"], total_alerts)
        
        if "time_distribution" in response["aggregations"]:
            result_data["time"] = process_time_distribution(response["aggregations"]["time_distribution"], total_alerts)
            logger.info("Added histogram-style temporal distribution to results")
        
        if "rule_groups_distribution" in response["aggregations"]:
            result_data["rule_groups"] = process_rule_groups_distribution(response["aggregations"]["rule_groups_distribution"], total_alerts)
        
        if "geographic_distribution" in response["aggregations"]:
            result_data["geographic"] = process_geographic_distribution(response["aggregations"]["geographic_distribution"], total_alerts)
        
        if "process_distribution" in response["aggregations"]:
            result_data["processes"] = process_process_distribution(response["aggregations"]["process_distribution"], total_alerts)
        
        summary_stats = calculate_summary_stats(result_data)
        
        # Prioritize histogram outputs for temporal queries
        primary_result = result_data.copy()
        if is_temporal and "time" in result_data:
            # For temporal queries, make histogram the primary result
            temporal_histogram = primary_result.pop("time")
            # Move multi-dimensional to supplementary data if it exists
            if "multi_dimensional" in primary_result:
                supplementary_data = {"multi_dimensional_breakdown": primary_result.pop("multi_dimensional")}
            else:
                supplementary_data = {}
            
            # Restructure with temporal histogram as primary
            primary_result = {
                "temporal_histogram": temporal_histogram,
                "supplementary_analysis": supplementary_data
            }
            # Add other distributions back
            primary_result.update(result_data)
            # Remove duplicated temporal data
            if "time" in primary_result:
                del primary_result["time"]
        
        result = {
            "total_alerts": total_alerts,
            "time_range": time_range,
            "analysis_type": "temporal_histogram" if is_temporal and "time" in result_data else ("multi_dimensional" if len(group_by_list) > 1 else "distribution"),
            "group_by_criteria": group_by_list,
            "dimensions_analyzed": list(primary_result.keys()),
            "distributions": primary_result,
            "summary": summary_stats,
            "query_info": {
                "filters_applied": bool(filters),
                "group_by": group_by_list,
                "dimensions": dimensions,
                "filters": filters,
                "multi_dimensional": len(group_by_list) > 1,
                "temporal_analysis": is_temporal
            }
        }
        
        logger.info("Alert distribution analysis completed", 
                   total_alerts=total_alerts,
                   group_by_criteria=group_by_list,
                   dimensions_count=len(result_data),
                   multi_dimensional=len(group_by_list) > 1,
                   time_range=time_range)
        
        return result
        
    except Exception as e:
        logger.error("Alert distribution analysis failed", 
                    error=str(e), 
                    params=params)
        raise Exception(f"Failed to analyze alert distribution: {str(e)}")


# Dynamic Aggregation Builders
def build_composite_aggregation(group_by_list: List[str]) -> Dict[str, Any]:
    """Build composite aggregation for multi-dimensional grouping"""
    field_map = get_field_mapping()
    sources = []
    
    for dimension in group_by_list:
        dim_key = dimension.lower()
        if dim_key in field_map:
            field_name = field_map[dim_key]
            # logger.info("Found field mapping", dim_key=dim_key, field_name=field_name)
            
            # Handle timestamp fields differently for composite aggregations
            if field_name == "@timestamp":
                sources.append({
                    dim_key: {
                        "date_histogram": {
                            "field": field_name,
                            "calendar_interval": "1h",
                            "format": "yyyy-MM-dd HH:mm"
                        }
                    }
                })
            else:
                sources.append({
                    dim_key: {
                        "terms": {"field": field_name}
                    }
                })
        else:
            logger.warning("No field mapping found for dimension", dim_key=dim_key)
    
    if not sources:
        logger.error("No valid sources created for composite aggregation")
        # Fallback to simple terms aggregation
        return {
            "terms": {
                "field": "rule.level",
                "size": 10
            }
        }
    
    logger.info("Created composite aggregation", sources_count=len(sources))
    return {
        "composite": {
            "sources": sources,
            "size": 100
        },
        "aggs": {
            "correlation_metrics": {
                "stats": {"field": "rule.level"}
            }
        }
    }

def build_severity_distribution() -> Dict[str, Any]:
    """Build severity distribution aggregation"""
    return {
        "terms": {
            "field": "rule.level",
            "size": 15,
            "order": {"_key": "desc"}
        },
        "aggs": {
            "severity_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "4h",
                    "format": "yyyy-MM-dd HH:mm"
                }
            }
        }
    }

def build_host_distribution() -> Dict[str, Any]:
    """Build host distribution aggregation"""
    return {
        "terms": {
            "field": "agent.name",
            "size": 15,
            "order": {"_count": "desc"}
        },
        "aggs": {
            "host_severity_breakdown": {
                "terms": {
                    "field": "rule.level",
                    "size": 10
                }
            }
        }
    }

def build_rule_distribution() -> Dict[str, Any]:
    """Build rule distribution aggregation"""
    return {
        "terms": {
            "field": "rule.id",
            "size": 15,
            "order": {"_count": "desc"}
        },
        "aggs": {
            "rule_details": {
                "top_hits": {
                    "size": 1,
                    "_source": ["rule.description", "rule.level", "rule.groups"]
                }
            },
            "rule_hosts": {
                "terms": {
                    "field": "agent.name",
                    "size": 5
                }
            }
        }
    }

def build_user_distribution() -> Dict[str, Any]:
    """Build user distribution aggregation"""
    return {
        "terms": {
            "field": "data.win.eventdata.targetUserName",
            "size": 10,
            "order": {"_count": "desc"}
        },
        "aggs": {
            "user_activity_timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "2h",
                    "format": "yyyy-MM-dd HH:mm"
                }
            }
        }
    }

def build_time_distribution() -> Dict[str, Any]:
    """Build time distribution aggregation"""
    return {
        "date_histogram": {
            "field": "@timestamp",
            "fixed_interval": "1h",
            "format": "yyyy-MM-dd HH:mm"
        },
        "aggs": {
            "hourly_severity": {
                "terms": {
                    "field": "rule.level",
                    "size": 5
                }
            }
        }
    }

def build_enhanced_time_distribution(breakdown_dimension: str) -> Dict[str, Any]:
    """Build enhanced time distribution with breakdown by another dimension for histogram output"""
    
    # Define field mappings for different breakdown dimensions
    field_mapping = {
        "severity": "rule.level",
        "host": "agent.name", 
        "rule": "rule.id",
        "user": "data.win.eventdata.targetUserName",
        "rule_groups": "rule.groups",
        "geographic": "agent.ip",
        "process": "data.win.eventdata.image"
    }
    
    breakdown_field = field_mapping.get(breakdown_dimension, "rule.level")
    breakdown_name = f"hourly_{breakdown_dimension}"
    
    return {
        "date_histogram": {
            "field": "@timestamp",
            "fixed_interval": "1h",
            "format": "yyyy-MM-dd HH:mm",
            "min_doc_count": 0  # Include empty buckets for complete histogram
        },
        "aggs": {
            breakdown_name: {
                "terms": {
                    "field": breakdown_field,
                    "size": 10
                },
                "aggs": {
                    "alert_count": {
                        "value_count": {"field": "_id"}
                    },
                    "avg_severity": {
                        "avg": {"field": "rule.level"}
                    }
                }
            },
            "total_alerts": {
                "value_count": {"field": "_id"}
            },
            "unique_entities": {
                "cardinality": {"field": breakdown_field}
            }
        }
    }

def build_rule_groups_distribution() -> Dict[str, Any]:
    """Build rule groups distribution aggregation"""
    return {
        "terms": {
            "field": "rule.groups",
            "size": 10,
            "order": {"_count": "desc"}
        }
    }

def build_geographic_distribution() -> Dict[str, Any]:
    """Build geographic distribution aggregation"""
    return {
        "terms": {
            "field": "agent.ip",
            "size": 10,
            "order": {"_count": "desc"}
        },
        "aggs": {
            "geo_hosts": {
                "terms": {
                    "field": "agent.name",
                    "size": 3
                }
            }
        }
    }

def build_process_distribution() -> Dict[str, Any]:
    """Build process distribution aggregation"""
    return {
        "terms": {
            "field": "data.win.eventdata.originalFileName",
            "size": 10,
            "order": {"_count": "desc"}
        },
        "aggs": {
            "process_severity": {
                "terms": {
                    "field": "rule.level",
                    "size": 5
                }
            }
        }
    }

def get_field_mapping() -> Dict[str, str]:
    """Get field mapping for composite aggregations"""
    return {
        "severity": "rule.level",
        "host": "agent.name",
        "hosts": "agent.name",
        "rule": "rule.id",
        "rules": "rule.id",
        "rule_id": "rule.id",
        "rule_description": "rule.description",
        "description": "rule.description",
        "user": "data.win.eventdata.user",
        "users": "data.win.eventdata.user",
        "target_user": "data.win.eventdata.targetUserName",
        "time": "@timestamp",
        "temporal": "@timestamp",
        "rule_groups": "rule.groups",
        "groups": "rule.groups",
        "rule_group": "rule.groups",
        "geographic": "agent.ip",
        "geo": "agent.ip",
        "location": "agent.ip",
        "locations": "agent.ip",
        "ip": "agent.ip",
        "process": "data.win.eventdata.originalFileName",
        "processes": "data.win.eventdata.originalFileName",
        "process_name": "data.win.eventdata.originalFileName",
        "command": "data.win.eventdata.commandLine",
        "command_line": "data.win.eventdata.commandLine",
        "parent_command": "data.win.eventdata.parentCommandLine",
        "parent_command_line": "data.win.eventdata.parentCommandLine",
        "image": "data.win.eventdata.image",
        "process_image": "data.win.eventdata.image",
        "executable": "data.win.eventdata.image",
        "process_id": "data.win.eventdata.processId",
        "pid": "data.win.eventdata.processId",
        "parent_process_id": "data.win.eventdata.parentProcessId",
        "parent_pid": "data.win.eventdata.parentProcessId",
        "integrity_level": "data.win.eventdata.integrityLevel",
        "logon_id": "data.win.eventdata.logonId"
    }

# Result Processors
def process_composite_results(composite_agg: Dict[str, Any], total_alerts: int, group_by_list: List[str]) -> Dict[str, Any]:
    """Process composite aggregation results"""
    logger.info("Processing composite results", buckets_count=len(composite_agg.get("buckets", [])))
    composite_data = []
    
    for i, bucket in enumerate(composite_agg["buckets"]):
        try:
            # In composite aggregations, key is a dict with multiple dimensions
            composite_key = bucket["key"]
            logger.info("Processing bucket", key_type=type(composite_key), key_value=composite_key)
            
            bucket_data = {
                "composite_key": composite_key,  # Keep the full composite key
                "dimensions": {},  # Break down individual dimensions
                "count": bucket["doc_count"],
                "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0
            }
            
            # Extract individual dimension values from composite key
            if isinstance(composite_key, dict):
                for dim_name, dim_value in composite_key.items():
                    bucket_data["dimensions"][dim_name] = dim_value
            
            # Add correlation metrics if available
            if "correlation_metrics" in bucket:
                bucket_data["correlation_metrics"] = bucket["correlation_metrics"]
            
            composite_data.append(bucket_data)
            
        except Exception as e:
            logger.error("Error processing individual bucket", error=str(e), bucket=bucket)
            continue
    
    return {
        "multi_dimensional": composite_data,
        "grouping_criteria": group_by_list,
        "total_combinations": len(composite_data)
    }

def process_severity_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process severity distribution results"""
    severity_distribution = []
    for bucket in agg_data["buckets"]:
        severity_data = {
            "severity_level": bucket["key"],
            "severity_name": get_severity_name(bucket["key"]),
            "count": bucket["doc_count"],
            "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0,
            "time_series": []
        }
        
        # Add time series data
        for time_bucket in bucket["severity_over_time"]["buckets"]:
            severity_data["time_series"].append({
                "timestamp": time_bucket["key_as_string"],
                "count": time_bucket["doc_count"]
            })
        
        severity_distribution.append(severity_data)
    
    return severity_distribution

def process_host_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process host distribution results"""
    host_distribution = []
    for bucket in agg_data["buckets"]:
        host_data = {
            "host_name": bucket["key"],
            "count": bucket["doc_count"],
            "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0,
            "severity_breakdown": {}
        }
        
        # Add severity breakdown for each host
        for severity_bucket in bucket["host_severity_breakdown"]["buckets"]:
            host_data["severity_breakdown"][str(severity_bucket["key"])] = {
                "count": severity_bucket["doc_count"],
                "severity_name": get_severity_name(severity_bucket["key"])
            }
        
        host_distribution.append(host_data)
    
    return host_distribution

def process_rule_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process rule distribution results"""
    rule_distribution = []
    for bucket in agg_data["buckets"]:
        rule_data = {
            "rule_id": bucket["key"],
            "count": bucket["doc_count"],
            "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0,
            "affected_hosts": []
        }
        
        # Add rule details
        if bucket["rule_details"]["hits"]["hits"]:
            rule_source = bucket["rule_details"]["hits"]["hits"][0]["_source"]
            rule_data["description"] = rule_source.get("rule", {}).get("description", "")
            rule_data["level"] = rule_source.get("rule", {}).get("level", 0)
            rule_data["groups"] = rule_source.get("rule", {}).get("groups", [])
        
        # Add affected hosts
        for host_bucket in bucket["rule_hosts"]["buckets"]:
            rule_data["affected_hosts"].append({
                "host_name": host_bucket["key"],
                "count": host_bucket["doc_count"]
            })
        
        rule_distribution.append(rule_data)
    
    return rule_distribution

def process_user_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process user distribution results"""
    user_distribution = []
    for bucket in agg_data["buckets"]:
        if bucket["key"]:  # Skip empty usernames
            user_data = {
                "username": bucket["key"],
                "count": bucket["doc_count"],
                "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0,
                "activity_timeline": []
            }
            
            # Add activity timeline
            for time_bucket in bucket["user_activity_timeline"]["buckets"]:
                user_data["activity_timeline"].append({
                    "timestamp": time_bucket["key_as_string"],
                    "count": time_bucket["doc_count"]
                })
            
            user_distribution.append(user_data)
    
    return user_distribution

def process_time_distribution(agg_data: Dict[str, Any], total_alerts: int) -> Dict[str, Any]:
    """Process time distribution results with enhanced histogram output"""
    time_buckets = []
    histogram_data = {
        "buckets": [],
        "statistics": {
            "total_time_periods": 0,
            "peak_hour": None,
            "peak_count": 0,
            "average_per_hour": 0,
            "zero_activity_periods": 0
        },
        "breakdown_summary": {}
    }
    
    total_period_alerts = 0
    breakdown_totals = {}
    
    for bucket in agg_data["buckets"]:
        bucket_count = bucket["doc_count"]
        total_period_alerts += bucket_count
        
        # Enhanced time bucket data
        time_data = {
            "timestamp": bucket["key_as_string"],
            "time_label": bucket["key_as_string"],
            "count": bucket_count,
            "percentage": round((bucket_count / total_alerts) * 100, 2) if total_alerts > 0 else 0,
            "breakdown": {}
        }
        
        # Track zero activity periods
        if bucket_count == 0:
            histogram_data["statistics"]["zero_activity_periods"] += 1
        
        # Track peak activity
        if bucket_count > histogram_data["statistics"]["peak_count"]:
            histogram_data["statistics"]["peak_count"] = bucket_count
            histogram_data["statistics"]["peak_hour"] = bucket["key_as_string"]
        
        # Process breakdown (severity or other dimension)
        breakdown_key = None
        for key in bucket.keys():
            if key.startswith("hourly_"):
                breakdown_key = key
                break
        
        if breakdown_key and breakdown_key in bucket:
            for sub_bucket in bucket[breakdown_key]["buckets"]:
                breakdown_value = str(sub_bucket["key"])
                sub_count = sub_bucket["doc_count"]
                
                # Add to time bucket breakdown
                time_data["breakdown"][breakdown_value] = {
                    "count": sub_count,
                    "name": get_severity_name(sub_bucket["key"]) if breakdown_key == "hourly_severity" else breakdown_value,
                    "percentage": round((sub_count / bucket_count) * 100, 2) if bucket_count > 0 else 0
                }
                
                # Track totals for breakdown summary
                breakdown_totals[breakdown_value] = breakdown_totals.get(breakdown_value, 0) + sub_count
        
        # Add enhanced metadata
        if "total_alerts" in bucket:
            time_data["total_alerts"] = bucket["total_alerts"]["value"]
        if "unique_entities" in bucket:
            time_data["unique_entities"] = bucket["unique_entities"]["value"]
            
        time_buckets.append(time_data)
    
    # Calculate statistics
    num_periods = len(time_buckets)
    histogram_data["statistics"]["total_time_periods"] = num_periods
    histogram_data["statistics"]["average_per_hour"] = round(total_period_alerts / num_periods, 2) if num_periods > 0 else 0
    
    # Create breakdown summary
    for breakdown_value, total_count in breakdown_totals.items():
        histogram_data["breakdown_summary"][breakdown_value] = {
            "total_count": total_count,
            "percentage": round((total_count / total_period_alerts) * 100, 2) if total_period_alerts > 0 else 0,
            "name": get_severity_name(int(breakdown_value)) if breakdown_value.isdigit() else breakdown_value
        }
    
    histogram_data["buckets"] = time_buckets
    histogram_data["histogram_type"] = "temporal_distribution"
    histogram_data["interval"] = "1 hour"
    histogram_data["total_alerts_in_period"] = total_period_alerts
    
    return histogram_data

def process_rule_groups_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process rule groups distribution results"""
    rule_groups_distribution = []
    for bucket in agg_data["buckets"]:
        rule_groups_distribution.append({
            "rule_group": bucket["key"],
            "count": bucket["doc_count"],
            "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0
        })
    
    return rule_groups_distribution

def process_geographic_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process geographic distribution results"""
    geographic_distribution = []
    for bucket in agg_data["buckets"]:
        geo_data = {
            "ip_address": bucket["key"],
            "count": bucket["doc_count"],
            "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0,
            "hosts": []
        }
        
        # Add hosts for each IP
        for host_bucket in bucket["geo_hosts"]["buckets"]:
            geo_data["hosts"].append({
                "host_name": host_bucket["key"],
                "count": host_bucket["doc_count"]
            })
        
        geographic_distribution.append(geo_data)
    
    return geographic_distribution

def process_process_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process process distribution results"""
    process_distribution = []
    for bucket in agg_data["buckets"]:
        if bucket["key"]:  # Skip empty process names
            process_data = {
                "process_name": bucket["key"],
                "count": bucket["doc_count"],
                "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0,
                "severity_breakdown": {}
            }
            
            # Add severity breakdown for each process
            for severity_bucket in bucket["process_severity"]["buckets"]:
                process_data["severity_breakdown"][str(severity_bucket["key"])] = {
                    "count": severity_bucket["doc_count"],
                    "severity_name": get_severity_name(severity_bucket["key"])
                }
            
            process_distribution.append(process_data)
    
    return process_distribution

def calculate_summary_stats(result_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate summary statistics from result data"""
    summary = {}
    
    # Handle single-dimensional distributions
    if "hosts" in result_data:
        summary["unique_hosts"] = len(result_data["hosts"])
    if "rules" in result_data:
        summary["unique_rules"] = len(result_data["rules"])
    if "users" in result_data:
        summary["unique_users"] = len(result_data["users"])
    if "processes" in result_data:
        summary["unique_processes"] = len(result_data["processes"])
    if "time" in result_data:
        summary["time_span_hours"] = len(result_data["time"])
    
    # Handle multi-dimensional distributions
    if "multi_dimensional" in result_data:
        multi_data = result_data["multi_dimensional"]
        if isinstance(multi_data, list):
            # Multi-dimensional data is a list of bucket combinations
            summary["total_combinations"] = len(multi_data)
            
            # Extract unique hosts and severity levels from combinations
            unique_hosts = set()
            unique_severities = set()
            total_alerts = 0
            max_alerts = 0
            max_combination = None
            
            for bucket in multi_data:
                if "dimensions" in bucket:
                    dims = bucket["dimensions"]
                    if "host" in dims:
                        unique_hosts.add(dims["host"])
                    if "severity" in dims:
                        unique_severities.add(dims["severity"])
                
                if "count" in bucket:
                    alerts_count = bucket["count"]
                    total_alerts += alerts_count
                    if alerts_count > max_alerts:
                        max_alerts = alerts_count
                        max_combination = bucket.get("composite_key", {})
            
            summary["unique_hosts"] = len(unique_hosts)
            summary["unique_severity_levels"] = len(unique_severities)
            summary["total_distributed_alerts"] = total_alerts
            summary["max_alerts_in_combination"] = max_alerts
            summary["most_active_combination"] = max_combination
            
            # Calculate average alerts per combination
            if len(multi_data) > 0:
                summary["average_alerts_per_combination"] = round(total_alerts / len(multi_data), 2)
        
        elif isinstance(multi_data, dict) and "total_combinations" in multi_data:
            # Legacy format support
            summary["total_combinations"] = multi_data["total_combinations"]
    
    # Handle total_combinations at root level (current format)
    if "total_combinations" in result_data:
        summary["total_combinations"] = result_data["total_combinations"]
    
    return summary

def get_severity_name(level: int) -> str:
    """
    Convert Wazuh alert level to severity name
    
    Args:
        level: Alert level number
        
    Returns:
        Severity name string
    """
    if level >= 12:
        return "Critical"
    elif level >= 8:
        return "High"
    elif level >= 5:
        return "Medium"
    elif level >= 3:
        return "Low"
    else:
        return "Informational"