"""
Identify behavioural anomalies in entity activities (users, hosts, files, processes) by comparing 
current behaviour against RCF-learned behavioural baselines.
"""
from typing import Dict, Any
import structlog
from datetime import datetime, timedelta
import statistics
import os
import aiohttp

logger = structlog.get_logger()

# Load environment variables for RCF behavioral detector
BEHAVIOUR_DETECTOR_INDEX = os.getenv("BEHAVIOUR_DETECTOR_INDEX", "opensearch-ad-plugin-result-alert-behaviour-*")
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = os.getenv("OPENSEARCH_PORT", "9200")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")
OPENSEARCH_USE_SSL = os.getenv("OPENSEARCH_USE_SSL", "false").lower() == "true"
OPENSEARCH_VERIFY_CERTS = os.getenv("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true"


async def get_rcf_behavioral_baselines(timeframe: str) -> Dict[str, Any]:
    """
    Retrieve RCF-learned behavioral baselines from behavioral detector anomaly results index
    
    Args:
        timeframe: Time range for baseline retrieval
        
    Returns:
        RCF behavioral baseline data with learned thresholds and behavioral patterns
    """
    try:
        protocol = "https" if OPENSEARCH_USE_SSL else "http"
        base_url = f"{protocol}://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}"
        
        # Calculate time range for query
        import re
        time_match = re.match(r"(\d+)([dhm])", timeframe)
        if time_match:
            value, unit = int(time_match.group(1)), time_match.group(2)
            if unit == 'd':
                end_time = datetime.now()
                start_time = end_time - timedelta(days=value)
            elif unit == 'h':
                end_time = datetime.now()
                start_time = end_time - timedelta(hours=value)
            elif unit == 'm':
                end_time = datetime.now()
                start_time = end_time - timedelta(minutes=value)
            else:
                end_time = datetime.now()
                start_time = end_time - timedelta(days=7)
        else:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=7)
        
        # Query the behavioral detector anomaly results index
        url = f"{base_url}/{BEHAVIOUR_DETECTOR_INDEX}/_search"
        
        search_query = {
            "query": {
                "range": {
                    "data_end_time": {
                        "gte": int(start_time.timestamp() * 1000),
                        "lte": int(end_time.timestamp() * 1000)
                    }
                }
            },
            "sort": [{"data_end_time": {"order": "desc"}}],
            "size": 200,
            "_source": ["detector_id", "feature_data", "anomaly_grade", "anomaly_score", "confidence", "threshold", "data_end_time"]
        }
        
        auth = aiohttp.BasicAuth(OPENSEARCH_USER, OPENSEARCH_PASSWORD)
        connector = aiohttp.TCPConnector(verify_ssl=OPENSEARCH_VERIFY_CERTS)
        
        async with aiohttp.ClientSession(auth=auth, connector=connector) as session:
            async with session.post(url, json=search_query) as response:
                if response.status == 200:
                    results_data = await response.json()
                    hits = results_data.get("hits", {}).get("hits", [])
                    
                    if not hits:
                        logger.warning("No RCF behavioral results found", index=BEHAVIOUR_DETECTOR_INDEX)
                        return {}
                    
                    # Extract behavioral baselines from RCF results
                    user_activity_values = []
                    process_execution_values = []
                    host_behavior_values = []
                    file_access_values = []
                    authentication_behavior_values = []
                    anomaly_grades = []
                    anomaly_scores = []
                    confidence_scores = []
                    threshold_values = []
                    
                    for hit in hits:
                        source = hit.get("_source", {})
                        feature_data = source.get("feature_data", [])
                        
                        for feature in feature_data:
                            feature_name = feature.get("feature_name", "")
                            feature_value = feature.get("data", 0)
                            
                            if feature_name == "user_activity_patterns":
                                user_activity_values.append(feature_value)
                            elif feature_name == "process_execution_patterns":
                                process_execution_values.append(feature_value)
                            elif feature_name == "host_behavior_patterns":
                                host_behavior_values.append(feature_value)
                            elif feature_name == "file_access_patterns":
                                file_access_values.append(feature_value)
                            elif feature_name == "authentication_behavior_patterns":
                                authentication_behavior_values.append(feature_value)
                        
                        anomaly_grades.append(source.get("anomaly_grade", 0.0))
                        anomaly_scores.append(source.get("anomaly_score", 0.0))
                        confidence_scores.append(source.get("confidence", 0.0))
                        threshold_values.append(source.get("threshold", 0.0))
                    
                    # Calculate RCF-enhanced statistical baselines for behavioral patterns
                    def calculate_behavioral_stats(values, pattern_name):
                        if not values:
                            return {"mean": 0, "std": 0, "behavioral_threshold": 0, "anomaly_threshold": 0, "rcf_multiplier": 1.0}
                        
                        mean_val = statistics.mean(values)
                        std_val = statistics.stdev(values) if len(values) > 1 else 0
                        
                        # Use RCF data to determine dynamic multipliers for behavioral analysis
                        sorted_vals = sorted(values)
                        p75 = sorted_vals[int(0.75 * len(sorted_vals))] if len(sorted_vals) > 0 else mean_val
                        p95 = sorted_vals[int(0.95 * len(sorted_vals))] if len(sorted_vals) > 0 else mean_val
                        
                        # Dynamic multipliers based on RCF behavioral data distribution
                        behavioral_multiplier = (p75 - mean_val) / std_val if std_val > 0 else 1.5
                        anomaly_multiplier = (p95 - mean_val) / std_val if std_val > 0 else 2.5
                        
                        return {
                            "mean": mean_val,
                            "std": std_val,
                            "behavioral_threshold": mean_val + (behavioral_multiplier * std_val),
                            "anomaly_threshold": mean_val + (anomaly_multiplier * std_val),
                            "current_baseline": mean_val,
                            "rcf_behavioral_multiplier": behavioral_multiplier,
                            "rcf_anomaly_multiplier": anomaly_multiplier,
                            "pattern_name": pattern_name
                        }
                    
                    rcf_behavioral_baselines = {
                        "user_activity_patterns": calculate_behavioral_stats(user_activity_values, "user_activity"),
                        "process_execution_patterns": calculate_behavioral_stats(process_execution_values, "process_execution"),
                        "host_behavior_patterns": calculate_behavioral_stats(host_behavior_values, "host_behavior"),
                        "file_access_patterns": calculate_behavioral_stats(file_access_values, "file_access"),
                        "authentication_behavior_patterns": calculate_behavioral_stats(authentication_behavior_values, "authentication_behavior"),
                        "anomaly_grades": calculate_behavioral_stats(anomaly_grades, "anomaly_grades"),
                        "anomaly_scores": calculate_behavioral_stats(anomaly_scores, "anomaly_scores"),
                        "confidence_scores": calculate_behavioral_stats(confidence_scores, "confidence"),
                        "threshold_values": calculate_behavioral_stats(threshold_values, "thresholds"),
                        "results_count": len(hits),
                        "rcf_enhanced": True,
                        "index_name": BEHAVIOUR_DETECTOR_INDEX
                    }
                    
                    logger.info("Retrieved RCF behavioral baselines", 
                               index=BEHAVIOUR_DETECTOR_INDEX,
                               results_count=len(hits),
                               avg_confidence=rcf_behavioral_baselines["confidence_scores"]["mean"])
                    
                    return rcf_behavioral_baselines
                else:
                    logger.error("Failed to query behavioral detector index", 
                               status=response.status, index=BEHAVIOUR_DETECTOR_INDEX)
                    return {}
                    
    except Exception as e:
        logger.error("Failed to retrieve RCF behavioral baselines", error=str(e))
        return {}


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Identify behavioural anomalies in entity activities (users, hosts, files, processes) by comparing 
    current behaviour against RCF-learned behavioural baselines.
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including timeframe, baseline, sensitivity
        
    Returns:
        RCF-enhanced behavioral anomaly results with entity behavioral deviations and risk assessment
    """
    try:
        # Extract parameters
        timeframe = params.get("timeframe", "24h")
        baseline = params.get("baseline", "17d")  # Baseline period for RCF comparison
        sensitivity = params.get("sensitivity", "medium")  # low, medium, high
        limit = params.get("limit", 20)
        
        logger.info("Detecting RCF-enhanced behavioral anomalies", 
                   timeframe=timeframe,
                   baseline=baseline,
                   sensitivity=sensitivity)
        
        # Retrieve RCF-learned behavioral baselines
        rcf_behavioral_baselines = await get_rcf_behavioral_baselines(baseline)
        
        # Build RCF-aligned query matching behavioral detector's 5 features
        current_query = {
            "query": {
                "bool": {
                    "must": [opensearch_client.build_single_time_filter(timeframe)]
                }
            },
            "size": 0,
            "aggs": {
                "behavioral_time_series": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",  # Match behavioral detector 1-hour intervals
                        "order": {"_key": "asc"}
                    },
                    "aggs": {
                        "user_activity_patterns": {
                            "cardinality": {
                                "field": "data.win.eventdata.targetUserName"
                            }
                        },
                        "process_execution_patterns": {
                            "cardinality": {
                                "field": "data.win.eventdata.image"
                            }
                        },
                        "host_behavior_patterns": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "file_access_patterns": {
                            "value_count": {
                                "field": "syscheck.path"
                            }
                        },
                        "authentication_behavior_patterns": {
                            "filter": {
                                "bool": {
                                    "should": [
                                        {"match": {"rule.groups": "authentication"}},
                                        {"match": {"rule.groups": "authentication_success"}},
                                        {"match": {"rule.groups": "authentication_failed"}},
                                        {"match": {"rule.groups": "authentication_failures"}}
                                    ]
                                }
                            },
                            "aggs": {
                                "auth_count": {
                                    "value_count": {"field": "rule.id"}
                                }
                            }
                        }
                    }
                },
                "entity_analysis": {
                    "terms": {
                        "field": "agent.name",
                        "size": 100
                    },
                    "aggs": {
                        "user_activity_diversity": {
                            "cardinality": {
                                "field": "data.win.eventdata.targetUserName"
                            }
                        },
                        "process_execution_diversity": {
                            "cardinality": {
                                "field": "data.win.eventdata.image"
                            }
                        },
                        "file_access_count": {
                            "value_count": {
                                "field": "syscheck.path"
                            }
                        },
                        "authentication_activity": {
                            "filter": {
                                "bool": {
                                    "should": [
                                        {"match": {"rule.groups": "authentication"}},
                                        {"match": {"rule.groups": "authentication_success"}},
                                        {"match": {"rule.groups": "authentication_failed"}}
                                    ]
                                }
                            },
                            "aggs": {
                                "auth_count": {"value_count": {"field": "rule.id"}}
                            }
                        },
                        "temporal_activity": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "2h"
                            }
                        }
                    }
                },
                "user_analysis": {
                    "terms": {
                        "field": "data.win.eventdata.targetUserName",
                        "size": 50
                    },
                    "aggs": {
                        "host_diversity": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "process_diversity": {
                            "cardinality": {
                                "field": "data.win.eventdata.image"
                            }
                        },
                        "file_access_activity": {
                            "value_count": {
                                "field": "syscheck.path"
                            }
                        },
                        "authentication_activity": {
                            "filter": {
                                "bool": {
                                    "should": [
                                        {"match": {"rule.groups": "authentication"}},
                                        {"match": {"rule.groups": "authentication_success"}},
                                        {"match": {"rule.groups": "authentication_failed"}}
                                    ]
                                }
                            },
                            "aggs": {
                                "auth_count": {"value_count": {"field": "rule.id"}}
                            }
                        }
                    }
                },
                "process_analysis": {
                    "terms": {
                        "field": "data.win.eventdata.image",
                        "size": 50
                    },
                    "aggs": {
                        "host_spread": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "user_diversity": {
                            "cardinality": {
                                "field": "data.win.eventdata.targetUserName"
                            }
                        },
                        "execution_frequency": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "2h"
                            }
                        }
                    }
                },
                "file_analysis": {
                    "terms": {
                        "field": "syscheck.path",
                        "size": 30
                    },
                    "aggs": {
                        "access_frequency": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "4h"
                            }
                        },
                        "host_accessing": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        }
                    }
                }
            }
        }
        
        # Use RCF baselines for behavioral comparison instead of historical queries
        if rcf_behavioral_baselines and rcf_behavioral_baselines.get("results_count", 0) > 0:
            logger.info("Using RCF-learned behavioral thresholds",
                       confidence=rcf_behavioral_baselines.get("confidence_scores", {}).get("mean", 0),
                       results_count=rcf_behavioral_baselines.get("results_count", 0))
            
            # Use RCF confidence score to determine sensitivity multiplier
            rcf_confidence = rcf_behavioral_baselines.get("confidence_scores", {}).get("mean", 0.5)
            rcf_anomaly_grade_mean = rcf_behavioral_baselines.get("anomaly_grades", {}).get("mean", 0.1)
            
            # Adjust sensitivity based on RCF confidence and historical anomaly patterns
            grade_adjustment = max(0.5, 1.0 - rcf_anomaly_grade_mean * 0.4)
            
            sensitivity_multipliers = {
                "low": max(0.7, (1.0 - rcf_confidence * 0.2) * grade_adjustment),
                "medium": max(0.5, (1.0 - rcf_confidence * 0.4) * grade_adjustment),
                "high": max(0.3, (1.0 - rcf_confidence * 0.6) * grade_adjustment)
            }
            multiplier = sensitivity_multipliers.get(sensitivity, 0.6)
            
        else:
            # Minimal fallback when RCF data unavailable
            logger.info("No RCF data available - using minimal statistical thresholds")
            multiplier = 1.0
            rcf_confidence = 0.5
            rcf_anomaly_grade_mean = 0.1  # Default fallback value
        
        # Execute current period query
        current_response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=current_query
        )
        
        # Extract results
        current_total = current_response.get("hits", {}).get("total", {}).get("value", 0)
        
        # Process RCF-aligned behavioral time series data
        behavioral_time_series_agg = current_response.get("aggregations", {}).get("behavioral_time_series", {})
        entity_agg = current_response.get("aggregations", {}).get("entity_analysis", {})
        user_agg = current_response.get("aggregations", {}).get("user_analysis", {})
        process_agg = current_response.get("aggregations", {}).get("process_analysis", {})
        file_agg = current_response.get("aggregations", {}).get("file_analysis", {})
        
        # Analyze RCF behavioral time series for anomaly detection
        behavioral_anomalies = []
        time_series_data = []
        
        # Extract behavioral feature time series
        for bucket in behavioral_time_series_agg.get("buckets", []):
            timestamp = bucket["key_as_string"]
            
            # Extract current behavioral feature values
            user_activity = bucket.get("user_activity_patterns", {}).get("value", 0)
            process_execution = bucket.get("process_execution_patterns", {}).get("value", 0)
            host_behavior = bucket.get("host_behavior_patterns", {}).get("value", 0)
            file_access = bucket.get("file_access_patterns", {}).get("value", 0)

            # Extract authentication behavior (nested in filter aggregation)
            auth_behavior = bucket.get("authentication_behavior_patterns", {}).get("auth_count", {}).get("value", 0)

            time_series_data.append({
                "timestamp": timestamp,
                "user_activity_patterns": user_activity,
                "process_execution_patterns": process_execution,
                "host_behavior_patterns": host_behavior,
                "file_access_patterns": file_access,
                "authentication_behavior_patterns": auth_behavior
            })
            
            # Compare against RCF baselines for each behavioral feature
            if rcf_behavioral_baselines:
                behavioral_features = {
                    "user_activity_patterns": user_activity,
                    "process_execution_patterns": process_execution,
                    "host_behavior_patterns": host_behavior,
                    "file_access_patterns": file_access,
                    "authentication_behavior_patterns": auth_behavior
                }
                
                for feature_name, current_value in behavioral_features.items():
                    if feature_name in rcf_behavioral_baselines and current_value > 0:
                        rcf_baseline = rcf_behavioral_baselines[feature_name]
                        baseline_mean = rcf_baseline.get("current_baseline", 0)
                        
                        # Use RCF-learned thresholds directly (already calculated with proper multipliers)
                        behavioral_threshold = rcf_baseline.get("behavioral_threshold", baseline_mean)
                        anomaly_threshold = rcf_baseline.get("anomaly_threshold", baseline_mean)
                        
                        # Apply sensitivity adjustment only if needed
                        if multiplier != 1.0:
                            behavioral_threshold *= multiplier
                            anomaly_threshold *= multiplier
                        
                        # Detect behavioral anomalies using RCF thresholds
                        deviation = abs(current_value - baseline_mean)
                        is_behavioral_anomaly = current_value > behavioral_threshold
                        is_critical_anomaly = current_value > anomaly_threshold
                        
                        if is_behavioral_anomaly or is_critical_anomaly:
                            anomaly_score = min(100, (current_value / baseline_mean * 50) if baseline_mean > 0 else 75)
                            
                            behavioral_anomalies.append({
                                "timestamp": timestamp,
                                "feature": feature_name,
                                "pattern_type": rcf_baseline.get("pattern_name", feature_name),
                                "anomaly_type": "critical_behavioral_shift" if is_critical_anomaly else "behavioral_deviation",
                                "current_value": current_value,
                                "baseline_value": round(baseline_mean, 2),
                                "deviation": round(deviation, 2),
                                "anomaly_score": round(anomaly_score, 2),
                                "rcf_enhanced": True,
                                "risk_level": "Critical" if is_critical_anomaly else "High" if anomaly_score > 60 else "Medium"
                            })
        
        # Analyze entity-specific behavioral anomalies using RCF baselines
        entity_anomalies = []
        user_anomalies = []
        process_anomalies = []
        file_anomalies = []
        
        # Analyze host/entity behavioral anomalies using RCF baselines
        for bucket in entity_agg.get("buckets", []):
            entity_name = bucket["key"]
            total_activity = bucket["doc_count"]
            
            # Use RCF-derived minimum activity threshold
            min_activity_threshold = 3
            if rcf_behavioral_baselines and "host_behavior_patterns" in rcf_behavioral_baselines:
                baseline_mean = rcf_behavioral_baselines["host_behavior_patterns"].get("current_baseline", 3)
                min_activity_threshold = max(2, int(baseline_mean * 0.1))
            
            if total_activity < min_activity_threshold:
                continue
                
            # Extract RCF behavioral feature values for this entity
            user_diversity = bucket.get("user_activity_diversity", {}).get("value", 0)
            process_diversity = bucket.get("process_execution_diversity", {}).get("value", 0)
            file_access_count = bucket.get("file_access_count", {}).get("value", 0)
            auth_activity = bucket.get("authentication_activity", {}).get("auth_count", {}).get("value", 0)
            
            behavioral_changes = []
            anomaly_score = 0
            
            # Compare against RCF baselines for behavioral anomaly detection
            if rcf_behavioral_baselines:
                # User activity pattern analysis
                if "user_activity_patterns" in rcf_behavioral_baselines and user_diversity > 0:
                    baseline_data = rcf_behavioral_baselines["user_activity_patterns"]
                    baseline_mean = baseline_data.get("current_baseline", 0)
                    threshold = baseline_data.get("behavioral_threshold", baseline_mean)
                    
                    # Apply sensitivity adjustment only if needed
                    if multiplier != 1.0:
                        threshold *= multiplier
                    
                    if user_diversity > threshold:
                        deviation_ratio = user_diversity / baseline_mean if baseline_mean > 0 else user_diversity
                        behavioral_changes.append(f"User activity diversity anomaly: {deviation_ratio:.1f}x RCF baseline")
                        # Use RCF confidence to adjust anomaly score increment
                        score_increment = max(20, int(30 * (1 - rcf_confidence + 0.5)))
                        anomaly_score += score_increment
                
                # Process execution pattern analysis
                if "process_execution_patterns" in rcf_behavioral_baselines and process_diversity > 0:
                    baseline_data = rcf_behavioral_baselines["process_execution_patterns"]
                    baseline_mean = baseline_data.get("current_baseline", 0)
                    threshold = baseline_data.get("behavioral_threshold", baseline_mean)
                    
                    # Apply sensitivity adjustment only if needed
                    if multiplier != 1.0:
                        threshold *= multiplier
                    
                    if process_diversity > threshold:
                        deviation_ratio = process_diversity / baseline_mean if baseline_mean > 0 else process_diversity
                        behavioral_changes.append(f"Process execution anomaly: {deviation_ratio:.1f}x RCF baseline")
                        # Use RCF confidence to adjust anomaly score increment
                        score_increment = max(25, int(35 * (1 - rcf_confidence + 0.5)))
                        anomaly_score += score_increment
                
                # File access pattern analysis
                if "file_access_patterns" in rcf_behavioral_baselines and file_access_count > 0:
                    baseline_data = rcf_behavioral_baselines["file_access_patterns"]
                    baseline_mean = baseline_data.get("current_baseline", 0)
                    threshold = baseline_data.get("behavioral_threshold", baseline_mean)
                    
                    # Apply sensitivity adjustment only if needed
                    if multiplier != 1.0:
                        threshold *= multiplier
                    
                    if file_access_count > threshold:
                        deviation_ratio = file_access_count / baseline_mean if baseline_mean > 0 else file_access_count
                        behavioral_changes.append(f"File access anomaly: {deviation_ratio:.1f}x RCF baseline")
                        # Use RCF confidence to adjust anomaly score increment
                        score_increment = max(18, int(25 * (1 - rcf_confidence + 0.5)))
                        anomaly_score += score_increment
                
                # Authentication behavior pattern analysis
                if "authentication_behavior_patterns" in rcf_behavioral_baselines and auth_activity > 0:
                    baseline_data = rcf_behavioral_baselines["authentication_behavior_patterns"]
                    baseline_mean = baseline_data.get("current_baseline", 0)
                    threshold = baseline_data.get("behavioral_threshold", baseline_mean)

                    # Apply sensitivity adjustment only if needed
                    if multiplier != 1.0:
                        threshold *= multiplier

                    if auth_activity > threshold:
                        deviation_ratio = auth_activity / baseline_mean if baseline_mean > 0 else auth_activity
                        behavioral_changes.append(f"Authentication behavior anomaly: {deviation_ratio:.1f}x RCF baseline")
                        # Use RCF confidence to adjust anomaly score increment
                        score_increment = max(30, int(40 * (1 - rcf_confidence + 0.5)))
                        anomaly_score += score_increment
            
            if behavioral_changes:
                # Use RCF-derived risk thresholds based on anomaly grades
                medium_threshold = max(40, int(50 * (1 - rcf_anomaly_grade_mean + 0.5))) if rcf_behavioral_baselines else 50
                critical_threshold = max(70, int(80 * (1 - rcf_anomaly_grade_mean + 0.3))) if rcf_behavioral_baselines else 80
                
                entity_anomalies.append({
                    "entity": entity_name,
                    "entity_type": "host",
                    "anomaly_type": "rcf_behavioral_deviation",
                    "current_activity": total_activity,
                    "user_diversity": user_diversity,
                    "process_diversity": process_diversity,
                    "file_access_count": file_access_count,
                    "authentication_activity": auth_activity,
                    "anomaly_score": min(100, anomaly_score),
                    "risk_level": "Critical" if anomaly_score > critical_threshold else "High" if anomaly_score > medium_threshold else "Medium",
                    "behavioral_changes": behavioral_changes,
                    "rcf_enhanced": True
                })
        
        # Analyze user behavioral anomalies using RCF baselines
        for bucket in user_agg.get("buckets", []):
            user_name = bucket["key"]
            total_activity = bucket["doc_count"]
            
            # Use RCF-derived minimum activity threshold for users
            min_user_activity_threshold = 3
            if rcf_behavioral_baselines and "user_activity_patterns" in rcf_behavioral_baselines:
                baseline_mean = rcf_behavioral_baselines["user_activity_patterns"].get("current_baseline", 3)
                min_user_activity_threshold = max(2, int(baseline_mean * 0.05))
            
            if total_activity < min_user_activity_threshold:
                continue
                
            # Extract RCF behavioral feature values for this user
            host_diversity = bucket.get("host_diversity", {}).get("value", 0)
            process_diversity = bucket.get("process_diversity", {}).get("value", 0)
            file_access_activity = bucket.get("file_access_activity", {}).get("value", 0)
            auth_activity = bucket.get("authentication_activity", {}).get("auth_count", {}).get("value", 0)
            
            behavioral_changes = []
            anomaly_score = 0
            
            # Compare against RCF user activity patterns
            if rcf_behavioral_baselines and "user_activity_patterns" in rcf_behavioral_baselines:
                baseline_data = rcf_behavioral_baselines["user_activity_patterns"]
                baseline_mean = baseline_data.get("current_baseline", 0)
                behavioral_threshold = baseline_data.get("behavioral_threshold", baseline_mean)
                anomaly_threshold = baseline_data.get("anomaly_threshold", baseline_mean)
                
                # Apply sensitivity adjustment only if needed
                if multiplier != 1.0:
                    behavioral_threshold *= multiplier
                    anomaly_threshold *= multiplier
                
                # Host diversity analysis (lateral movement detection)
                if host_diversity > behavioral_threshold:
                    deviation_ratio = host_diversity / baseline_mean if baseline_mean > 0 else host_diversity
                    is_critical = host_diversity > anomaly_threshold
                    anomaly_type = "critical lateral movement" if is_critical else "lateral movement"
                    behavioral_changes.append(f"Host diversity anomaly: {deviation_ratio:.1f}x RCF baseline (potential {anomaly_type})")
                    # Use RCF confidence to adjust anomaly score increment
                    base_increment = 50 if is_critical else 35
                    score_increment = max(base_increment - 15, int(base_increment * (1 - rcf_confidence + 0.5)))
                    anomaly_score += score_increment
                
                # Process execution diversity analysis
                if process_diversity > behavioral_threshold:
                    deviation_ratio = process_diversity / baseline_mean if baseline_mean > 0 else process_diversity
                    behavioral_changes.append(f"Process execution diversity anomaly: {deviation_ratio:.1f}x RCF baseline")
                    # Use RCF confidence to adjust anomaly score increment
                    score_increment = max(25, int(35 * (1 - rcf_confidence + 0.5)))
                    anomaly_score += score_increment
                
                # File access pattern analysis
                if file_access_activity > behavioral_threshold:
                    deviation_ratio = file_access_activity / baseline_mean if baseline_mean > 0 else file_access_activity
                    behavioral_changes.append(f"File access activity anomaly: {deviation_ratio:.1f}x RCF baseline")
                    # Use RCF confidence to adjust anomaly score increment
                    score_increment = max(20, int(30 * (1 - rcf_confidence + 0.5)))
                    anomaly_score += score_increment
                
                # Authentication activity analysis
                if auth_activity > behavioral_threshold:
                    deviation_ratio = auth_activity / baseline_mean if baseline_mean > 0 else auth_activity
                    behavioral_changes.append(f"Authentication activity anomaly: {deviation_ratio:.1f}x RCF baseline")
                    # Use RCF confidence to adjust anomaly score increment
                    score_increment = max(30, int(40 * (1 - rcf_confidence + 0.5)))
                    anomaly_score += score_increment
            
            if behavioral_changes:
                # Use RCF-derived risk thresholds based on anomaly grades
                medium_threshold = max(40, int(50 * (1 - rcf_anomaly_grade_mean + 0.5))) if rcf_behavioral_baselines else 50
                critical_threshold = max(70, int(80 * (1 - rcf_anomaly_grade_mean + 0.3))) if rcf_behavioral_baselines else 80
                
                user_anomalies.append({
                    "entity": user_name,
                    "entity_type": "user",
                    "anomaly_type": "rcf_behavioral_deviation",
                    "current_activity": total_activity,
                    "host_diversity": host_diversity,
                    "process_diversity": process_diversity,
                    "file_access_activity": file_access_activity,
                    "authentication_activity": auth_activity,
                    "anomaly_score": min(100, anomaly_score),
                    "risk_level": "Critical" if anomaly_score > critical_threshold else "High" if anomaly_score > medium_threshold else "Medium",
                    "behavioral_changes": behavioral_changes,
                    "rcf_enhanced": True
                })
        
        # Analyze process execution behavioral anomalies using RCF baselines
        for bucket in process_agg.get("buckets", []):
            process_name = bucket["key"]
            execution_count = bucket["doc_count"]
            
            # Use RCF-derived minimum execution threshold for processes
            min_process_threshold = 5
            if rcf_behavioral_baselines and "process_execution_patterns" in rcf_behavioral_baselines:
                baseline_mean = rcf_behavioral_baselines["process_execution_patterns"].get("current_baseline", 5)
                min_process_threshold = max(3, int(baseline_mean * 0.1))
            
            if execution_count < min_process_threshold:
                continue
                
            # Extract behavioral metrics for this process
            host_spread = bucket.get("host_spread", {}).get("value", 0)
            user_diversity = bucket.get("user_diversity", {}).get("value", 0)
            
            behavioral_changes = []
            anomaly_score = 0
            
            # Compare against RCF process execution patterns
            if rcf_behavioral_baselines and "process_execution_patterns" in rcf_behavioral_baselines:
                baseline_data = rcf_behavioral_baselines["process_execution_patterns"]
                baseline_mean = baseline_data.get("current_baseline", 0)
                behavioral_threshold = baseline_data.get("behavioral_threshold", baseline_mean)
                
                # Apply sensitivity adjustment only if needed
                if multiplier != 1.0:
                    behavioral_threshold *= multiplier
                
                # Process execution frequency analysis
                if execution_count > behavioral_threshold:
                    deviation_ratio = execution_count / baseline_mean if baseline_mean > 0 else execution_count
                    behavioral_changes.append(f"Process execution frequency anomaly: {deviation_ratio:.1f}x RCF baseline")
                    # Use RCF confidence to adjust anomaly score increment
                    score_increment = max(30, int(40 * (1 - rcf_confidence + 0.5)))
                    anomaly_score += score_increment
                
                # Host spread analysis (potential process propagation)
                # Use RCF-derived spread threshold instead of hard-coded 0.5 multiplier
                spread_multiplier = max(0.3, 0.5 * (1 - rcf_confidence + 0.5)) if rcf_behavioral_baselines else 0.5
                spread_divisor = max(0.05, 0.1 * (1 - rcf_confidence + 0.5)) if rcf_behavioral_baselines else 0.1
                if host_spread > behavioral_threshold * spread_multiplier:
                    spread_ratio = host_spread / (baseline_mean * spread_divisor) if baseline_mean > 0 else host_spread
                    behavioral_changes.append(f"Process host spread anomaly: {spread_ratio:.1f}x RCF baseline")
                    # Use RCF confidence to adjust anomaly score increment
                    score_increment = max(25, int(35 * (1 - rcf_confidence + 0.5)))
                    anomaly_score += score_increment
            
            if behavioral_changes:
                # Use RCF-derived risk thresholds
                medium_threshold = max(35, int(45 * (1 - rcf_anomaly_grade_mean + 0.5))) if rcf_behavioral_baselines else 45
                critical_threshold = max(60, int(70 * (1 - rcf_anomaly_grade_mean + 0.3))) if rcf_behavioral_baselines else 70
                
                process_anomalies.append({
                    "entity": process_name,
                    "entity_type": "process",
                    "anomaly_type": "rcf_behavioral_deviation",
                    "execution_count": execution_count,
                    "host_spread": host_spread,
                    "user_diversity": user_diversity,
                    "anomaly_score": min(100, anomaly_score),
                    "risk_level": "Critical" if anomaly_score > critical_threshold else "High" if anomaly_score > medium_threshold else "Medium",
                    "behavioral_changes": behavioral_changes,
                    "rcf_enhanced": True
                })
        
        # Analyze file access behavioral anomalies using RCF baselines
        for bucket in file_agg.get("buckets", []):
            file_path = bucket["key"]
            access_count = bucket["doc_count"]
            
            # Use RCF-derived minimum access threshold for files
            min_file_threshold = 3
            if rcf_behavioral_baselines and "file_access_patterns" in rcf_behavioral_baselines:
                baseline_mean = rcf_behavioral_baselines["file_access_patterns"].get("current_baseline", 3)
                min_file_threshold = max(2, int(baseline_mean * 0.05))
            
            if access_count < min_file_threshold:
                continue
                
            # Extract behavioral metrics for this file
            host_accessing = bucket.get("host_accessing", {}).get("value", 0)
            
            behavioral_changes = []
            anomaly_score = 0
            
            # Compare against RCF file access patterns
            if rcf_behavioral_baselines and "file_access_patterns" in rcf_behavioral_baselines:
                baseline_data = rcf_behavioral_baselines["file_access_patterns"]
                baseline_mean = baseline_data.get("current_baseline", 0)
                behavioral_threshold = baseline_data.get("behavioral_threshold", baseline_mean)
                
                # Apply sensitivity adjustment only if needed
                if multiplier != 1.0:
                    behavioral_threshold *= multiplier
                
                # File access frequency analysis
                if access_count > behavioral_threshold:
                    deviation_ratio = access_count / baseline_mean if baseline_mean > 0 else access_count
                    behavioral_changes.append(f"File access frequency anomaly: {deviation_ratio:.1f}x RCF baseline")
                    # Use RCF confidence to adjust anomaly score increment
                    score_increment = max(22, int(30 * (1 - rcf_confidence + 0.5)))
                    anomaly_score += score_increment
            
            if behavioral_changes:
                # Use RCF-derived risk thresholds
                high_threshold = max(30, int(40 * (1 - rcf_anomaly_grade_mean + 0.5))) if rcf_behavioral_baselines else 40
                
                file_anomalies.append({
                    "entity": file_path,
                    "entity_type": "file",
                    "anomaly_type": "rcf_behavioral_deviation",
                    "access_count": access_count,
                    "host_accessing": host_accessing,
                    "anomaly_score": min(100, anomaly_score),
                    "risk_level": "High" if anomaly_score > high_threshold else "Medium",
                    "behavioral_changes": behavioral_changes,
                    "rcf_enhanced": True
                })
        
        # Sort all anomalies by score
        behavioral_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        entity_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        user_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        process_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        file_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)

        # Build RCF-enhanced result
        all_anomalies = behavioral_anomalies + entity_anomalies + user_anomalies + process_anomalies + file_anomalies
        
        result = {
            "analysis_period": timeframe,
            "total_alerts": current_total,
            "rcf_detector_info": {
                "index_name": BEHAVIOUR_DETECTOR_INDEX,
                "rcf_baselines_used": bool(rcf_behavioral_baselines),
                "baseline_period": baseline,
                "baseline_results_count": rcf_behavioral_baselines.get("results_count", 0) if rcf_behavioral_baselines else 0,
                "confidence_score": rcf_behavioral_baselines.get("confidence_scores", {}).get("mean", 0) if rcf_behavioral_baselines else 0
            },
            "behavioral_settings": {
                "sensitivity": sensitivity,
                "sensitivity_multiplier": multiplier if rcf_behavioral_baselines else "static_fallback"
            },
            "behavioral_time_series": time_series_data,
            "rcf_behavioral_analysis": {
                "temporal_behavioral_anomalies": behavioral_anomalies[:limit],
                "entity_behavioral_anomalies": entity_anomalies[:limit],
                "user_behavioral_anomalies": user_anomalies[:limit],
                "process_behavioral_anomalies": process_anomalies[:limit],
                "file_behavioral_anomalies": file_anomalies[:limit]
            },
            "rcf_baselines": rcf_behavioral_baselines if rcf_behavioral_baselines else {},
            "summary": {
                "total_behavioral_anomalies": len(all_anomalies),
                "temporal_anomalies": len(behavioral_anomalies),
                "entity_anomalies": len(entity_anomalies),
                "user_anomalies": len(user_anomalies),
                "process_anomalies": len(process_anomalies),
                "file_anomalies": len(file_anomalies),
                "highest_anomaly_score": max([a["anomaly_score"] for a in all_anomalies]) if all_anomalies else 0,
                "critical_anomalies": len([a for a in all_anomalies if a.get("risk_level") == "Critical"]),
                "high_risk_anomalies": len([a for a in all_anomalies if a.get("risk_level") == "High"]),
                "rcf_enhanced_detections": len([a for a in all_anomalies if a.get("rcf_enhanced", False)]),
                "risk_assessment": "Critical" if any(a.get("risk_level") == "Critical" for a in all_anomalies) else "High" if any(a.get("risk_level") == "High" for a in all_anomalies) else "Medium" if all_anomalies else "Low"
            }
        }
        
        logger.info("RCF-enhanced behavioral anomaly detection completed", 
                   total_alerts=current_total,
                   behavioral_anomalies=result["summary"]["total_behavioral_anomalies"],
                   critical_anomalies=result["summary"]["critical_anomalies"],
                   rcf_enhanced=result["summary"]["rcf_enhanced_detections"],
                   temporal_anomalies=result["summary"]["temporal_anomalies"],
                   entity_anomalies=result["summary"]["entity_anomalies"])
        
        return result
        
    except Exception as e:
        logger.error("Behavioral anomaly detection failed", error=str(e))
        raise Exception(f"Failed to detect behavioral anomalies: {str(e)}")