"""
Find indicators of compromise (IoCs) in Wazuh alerts
"""
from typing import Dict, Any, List
import structlog

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Find indicators of compromise in alerts
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including timeframe, filters, and IoC types
        
    Returns:
        IoC detection results with affected hosts, timeline, and threat context
    """
    try:
        # Extract parameters
        timeframe = params.get("timeframe", "7d")
        host_filter = params.get("host_filter")
        ioc_type = params.get("ioc_type", "all")  # ip, domain, hash, file, registry, all
        limit = params.get("limit", 50)
        
        logger.info("Finding indicators of compromise", 
                   timeframe=timeframe,
                   host_filter=host_filter,
                   ioc_type=ioc_type)
        
        # Build base query
        must_conditions = [
            opensearch_client.build_single_time_filter(timeframe)
        ]
        
        # IoC detection patterns
        ioc_patterns = {
            "ip": [
                {"exists": {"field": "data.srcip"}},
                {"exists": {"field": "data.dstip"}},
                {"wildcard": {"rule.description": "*IP*"}},
                {"wildcard": {"rule.description": "*address*"}},
                {"terms": {"rule.groups": ["network", "firewall", "intrusion_detection"]}}
            ],
            "domain": [
                {"exists": {"field": "data.url"}},
                {"exists": {"field": "data.hostname"}},
                {"wildcard": {"rule.description": "*domain*"}},
                {"wildcard": {"rule.description": "*DNS*"}},
                {"wildcard": {"rule.description": "*URL*"}},
                {"terms": {"rule.groups": ["web", "dns", "network"]}}
            ],
            "hash": [
                {"exists": {"field": "syscheck.md5_after"}},
                {"exists": {"field": "syscheck.sha1_after"}},
                {"exists": {"field": "syscheck.sha256_after"}},
                {"exists": {"field": "data.win.eventdata.hashes"}},
                {"wildcard": {"rule.description": "*hash*"}},
                {"wildcard": {"rule.description": "*checksum*"}},
                {"terms": {"rule.groups": ["syscheck", "integrity", "malware"]}}
            ],
            "file": [
                {"exists": {"field": "syscheck.path"}},
                {"exists": {"field": "data.win.eventdata.targetFilename"}},
                {"exists": {"field": "data.win.eventdata.image"}},
                {"wildcard": {"rule.description": "*file*"}},
                {"wildcard": {"rule.description": "*executable*"}},
                {"terms": {"rule.groups": ["syscheck", "sysmon", "windows"]}}
            ],
            "registry": [
                {"exists": {"field": "data.win.eventdata.targetObject"}},
                {"wildcard": {"rule.description": "*registry*"}},
                {"wildcard": {"rule.description": "*HKEY*"}},
                {"terms": {"rule.groups": ["windows", "sysmon", "registry"]}}
            ],
            "process": [
                {"exists": {"field": "data.win.eventdata.commandLine"}},
                {"exists": {"field": "data.win.eventdata.parentCommandLine"}},
                {"exists": {"field": "data.win.eventdata.processId"}},
                {"wildcard": {"rule.description": "*process*"}},
                {"wildcard": {"rule.description": "*execution*"}},
                {"terms": {"rule.groups": ["sysmon", "windows", "process_creation"]}}
            ]
        }
        
        # Add IoC type-specific filters
        if ioc_type != "all" and ioc_type in ioc_patterns:
            must_conditions.append({
                "bool": {
                    "should": ioc_patterns[ioc_type],
                    "minimum_should_match": 1
                }
            })
        else:
            # Search for any IoC indicators
            all_conditions = []
            for patterns in ioc_patterns.values():
                all_conditions.extend(patterns)
            
            must_conditions.append({
                "bool": {
                    "should": all_conditions,
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
                "ip_indicators": {
                    "terms": {
                        "field": "data.srcip",
                        "size": 20,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "affected_hosts": {
                            "terms": {
                                "field": "agent.name",
                                "size": 5
                            }
                        }
                    }
                },
                "domain_indicators": {
                    "terms": {
                        "field": "data.url",
                        "size": 15,
                        "order": {"_count": "desc"}
                    }
                },
                "file_indicators": {
                    "terms": {
                        "field": "syscheck.path",
                        "size": 20,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "file_hashes": {
                            "terms": {
                                "field": "syscheck.md5_after",
                                "size": 3
                            }
                        }
                    }
                },
                "process_indicators": {
                    "terms": {
                        "field": "data.win.eventdata.image",
                        "size": 15,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "command_lines": {
                            "terms": {
                                "field": "data.win.eventdata.commandLine",
                                "size": 3
                            }
                        }
                    }
                },
                "registry_indicators": {
                    "terms": {
                        "field": "data.win.eventdata.targetObject",
                        "size": 15,
                        "order": {"_count": "desc"}
                    }
                },
                "affected_hosts": {
                    "terms": {
                        "field": "agent.name",
                        "size": 20,
                        "order": {"_count": "desc"}
                    }
                },
                "ioc_timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "order": {"_key": "desc"}
                    }
                },
                "rule_categories": {
                    "terms": {
                        "field": "rule.groups",
                        "size": 15,
                        "order": {"_count": "desc"}
                    }
                },
                "severity_distribution": {
                    "terms": {
                        "field": "rule.level",
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
        ip_agg = response.get("aggregations", {}).get("ip_indicators", {})
        domain_agg = response.get("aggregations", {}).get("domain_indicators", {})
        file_agg = response.get("aggregations", {}).get("file_indicators", {})
        process_agg = response.get("aggregations", {}).get("process_indicators", {})
        registry_agg = response.get("aggregations", {}).get("registry_indicators", {})
        hosts_agg = response.get("aggregations", {}).get("affected_hosts", {})
        timeline_agg = response.get("aggregations", {}).get("ioc_timeline", {})
        rules_agg = response.get("aggregations", {}).get("rule_categories", {})
        severity_agg = response.get("aggregations", {}).get("severity_distribution", {})
        
        # Process IP indicators
        ip_indicators = []
        for bucket in ip_agg.get("buckets", []):
            ip = bucket["key"]
            count = bucket["doc_count"]
            
            # Get affected hosts for this IP
            affected_hosts = []
            for host_bucket in bucket.get("affected_hosts", {}).get("buckets", []):
                affected_hosts.append({
                    "host": host_bucket["key"],
                    "count": host_bucket["doc_count"]
                })
            
            # Simple IP classification
            ip_type = "external"
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                ip_type = "internal"
            elif ip.startswith("127."):
                ip_type = "localhost"
            
            ip_indicators.append({
                "ip": ip,
                "count": count,
                "type": ip_type,
                "affected_hosts": affected_hosts
            })
        
        # Process domain indicators
        domain_indicators = []
        for bucket in domain_agg.get("buckets", []):
            domain_indicators.append({
                "domain": bucket["key"],
                "count": bucket["doc_count"]
            })
        
        # Process file indicators
        file_indicators = []
        for bucket in file_agg.get("buckets", []):
            file_path = bucket["key"]
            count = bucket["doc_count"]
            
            # Get file hashes
            hashes = []
            for hash_bucket in bucket.get("file_hashes", {}).get("buckets", []):
                hashes.append({
                    "hash": hash_bucket["key"],
                    "count": hash_bucket["doc_count"]
                })
            
            # Classify file type
            file_type = "other"
            if file_path.endswith(('.exe', '.dll', '.bat', '.cmd', '.ps1')):
                file_type = "executable"
            elif file_path.endswith(('.doc', '.docx', '.pdf', '.xls', '.xlsx')):
                file_type = "document"
            elif file_path.endswith(('.jpg', '.png', '.gif', '.bmp')):
                file_type = "image"
            
            file_indicators.append({
                "file_path": file_path,
                "count": count,
                "type": file_type,
                "hashes": hashes
            })
        
        # Process process indicators
        process_indicators = []
        for bucket in process_agg.get("buckets", []):
            process = bucket["key"]
            count = bucket["doc_count"]
            
            # Get command lines
            command_lines = []
            for cmd_bucket in bucket.get("command_lines", {}).get("buckets", []):
                command_lines.append({
                    "command": cmd_bucket["key"],
                    "count": cmd_bucket["doc_count"]
                })
            
            process_indicators.append({
                "process": process,
                "count": count,
                "command_lines": command_lines
            })
        
        # Process registry indicators
        registry_indicators = []
        for bucket in registry_agg.get("buckets", []):
            registry_indicators.append({
                "registry_key": bucket["key"],
                "count": bucket["doc_count"]
            })
        
        # Process affected hosts
        affected_hosts = []
        for bucket in hosts_agg.get("buckets", []):
            affected_hosts.append({
                "host": bucket["key"],
                "ioc_count": bucket["doc_count"]
            })
        
        # Process timeline
        timeline = []
        for bucket in timeline_agg.get("buckets", []):
            timeline.append({
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })
        
        # Process rule categories
        rule_categories = []
        for bucket in rules_agg.get("buckets", []):
            rule_categories.append({
                "category": bucket["key"],
                "count": bucket["doc_count"]
            })
        
        # Process severity distribution
        severity_distribution = {}
        for bucket in severity_agg.get("buckets", []):
            severity_distribution[str(bucket["key"])] = bucket["doc_count"]
        
        # Process recent alerts
        recent_alerts = []
        for hit in alert_hits[:20]:  # Top 20 most recent
            source = hit.get("_source", {})
            rule = source.get("rule", {})
            agent = source.get("agent", {})
            data = source.get("data", {})
            syscheck = source.get("syscheck", {})
            
            recent_alerts.append({
                "timestamp": source.get("@timestamp"),
                "rule_id": rule.get("id"),
                "rule_description": rule.get("description"),
                "rule_level": rule.get("level"),
                "host": agent.get("name"),
                "host_ip": agent.get("ip"),
                "src_ip": data.get("srcip"),
                "dst_ip": data.get("dstip"),
                "url": data.get("url"),
                "file_path": syscheck.get("path"),
                "file_hash": syscheck.get("md5_after"),
                "process": data.get("win", {}).get("eventdata", {}).get("image"),
                "command_line": data.get("win", {}).get("eventdata", {}).get("commandLine")
            })
        
        # Build result
        result = {
            "total_alerts": total_alerts,
            "search_criteria": {
                "timeframe": timeframe,
                "host_filter": host_filter,
                "ioc_type": ioc_type
            },
            "ip_indicators": ip_indicators,
            "domain_indicators": domain_indicators,
            "file_indicators": file_indicators,
            "process_indicators": process_indicators,
            "registry_indicators": registry_indicators,
            "affected_hosts": affected_hosts,
            "timeline": timeline[:24],  # Last 24 hours
            "rule_categories": rule_categories,
            "severity_distribution": severity_distribution,
            "recent_alerts": recent_alerts,
            "ioc_summary": {
                "total_unique_ips": len(ip_indicators),
                "total_unique_domains": len(domain_indicators),
                "total_unique_files": len(file_indicators),
                "total_unique_processes": len(process_indicators),
                "total_unique_registry_keys": len(registry_indicators),
                "hosts_with_iocs": len(affected_hosts),
                "most_active_host": affected_hosts[0]["host"] if affected_hosts else None,
                "highest_severity": max(severity_distribution.keys()) if severity_distribution else None,
                "threat_level": "High" if any(int(k) >= 8 for k in severity_distribution.keys()) else "Medium" if any(int(k) >= 5 for k in severity_distribution.keys()) else "Low"
            }
        }
        
        logger.info("IoC detection completed", 
                   total_alerts=total_alerts,
                   ip_indicators=len(ip_indicators),
                   file_indicators=len(file_indicators),
                   hosts_affected=len(affected_hosts))
        
        return result
        
    except Exception as e:
        logger.error("IoC detection failed", error=str(e))
        raise Exception(f"Failed to find indicators of compromise: {str(e)}")