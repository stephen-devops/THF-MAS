"""
Detect anomalous activity using dynamic metric thresholds established by RCF-learned baselines.
Identifies when alert counts, severity levels, or host activity deviate significantly from 
established statistical baselines using OpenSearch Anomaly Detection plugin.
"""
from typing import Dict, Any
import structlog
import os
import aiohttp

logger = structlog.get_logger()

# Load environment variables
THRESHOLD_DETECTOR_INDEX = os.getenv("THRESHOLD_DETECTOR_INDEX", "opensearch-ad-plugin-result-alert-threshold")
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = os.getenv("OPENSEARCH_PORT", "9200")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")
OPENSEARCH_USE_SSL = os.getenv("OPENSEARCH_USE_SSL", "false").lower() == "true"
OPENSEARCH_VERIFY_CERTS = os.getenv("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true"


async def get_detector_info_via_api(detector_id: str) -> Dict[str, Any]:
    """
    Get detector information via OpenSearch Anomaly Detection REST API
    
    Args:
        detector_id: Anomaly detector ID
        
    Returns:
        Detector configuration and metadata
    """
    try:
        protocol = "https" if OPENSEARCH_USE_SSL else "http"
        base_url = f"{protocol}://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}"
        
        # OpenSearch Anomaly Detection API endpoint
        url = f"{base_url}/_plugins/_anomaly_detection/detectors/{detector_id}"
        
        # Setup authentication
        auth = aiohttp.BasicAuth(OPENSEARCH_USER, OPENSEARCH_PASSWORD)
        
        # SSL configuration
        connector = aiohttp.TCPConnector(verify_ssl=OPENSEARCH_VERIFY_CERTS)
        
        async with aiohttp.ClientSession(auth=auth, connector=connector) as session:
            async with session.get(url) as response:
                if response.status == 200:
                    detector_info = await response.json()
                    logger.info("Retrieved detector info via API", 
                               detector_id=detector_id,
                               detector_name=detector_info.get("name", "Unknown"))
                    return detector_info
                else:
                    logger.error("Failed to get detector info", 
                               detector_id=detector_id,
                               status=response.status)
                    return {}
                    
    except Exception as e:
        logger.error("Error calling detector API", detector_id=detector_id, error=str(e))
        return {}


async def get_anomaly_results_via_search(timeframe: str) -> Dict[str, Any]:
    """
    Retrieve RCF-learned baselines by directly querying the threshold detector anomaly results index
    
    Args:
        timeframe: Time range for baseline retrieval
        
    Returns:
        RCF baseline data with learned thresholds and confidence intervals
    """
    try:
        protocol = "https" if OPENSEARCH_USE_SSL else "http"
        base_url = f"{protocol}://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}"
        
        # Calculate time range for query
        from datetime import datetime, timedelta
        import re
        
        # Parse timeframe (e.g., "7d", "24h", "30m")
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
                # Default to 7 days
                end_time = datetime.now()
                start_time = end_time - timedelta(days=7)
        else:
            # Default to 7 days
            end_time = datetime.now()
            start_time = end_time - timedelta(days=7)
        
        # Query the threshold detector anomaly results index directly using environment variable
        url = f"{base_url}/{THRESHOLD_DETECTOR_INDEX}/_search"
        
        # Build search query to get recent anomaly results from threshold detector
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
            "size": 100,
            "_source": ["detector_id", "feature_data", "anomaly_grade", "anomaly_score", "confidence", "threshold", "data_end_time"]
        }
        
        # Setup authentication
        auth = aiohttp.BasicAuth(OPENSEARCH_USER, OPENSEARCH_PASSWORD)
        
        # SSL configuration
        connector = aiohttp.TCPConnector(verify_ssl=OPENSEARCH_VERIFY_CERTS)
        
        async with aiohttp.ClientSession(auth=auth, connector=connector) as session:
            async with session.post(url, json=search_query) as response:
                if response.status == 200:
                    results_data = await response.json()
                    
                    # Extract anomaly results from search hits
                    hits = results_data.get("hits", {}).get("hits", [])
                    
                    if not hits:
                        logger.warning("No anomaly results found in threshold detector index", 
                                     index=THRESHOLD_DETECTOR_INDEX,
                                     timeframe=timeframe)
                        return {}
                    
                    # Extract baseline metrics from recent results
                    total_alerts_values = []
                    severity_sum_values = []
                    host_diversity_values = []
                    user_diversity_values = []
                    high_severity_values = []
                    anomaly_grades = []
                    anomaly_scores = []
                    confidence_scores = []
                    threshold_values = []
                    
                    for hit in hits:
                        source = hit.get("_source", {})
                        
                        # Extract feature data
                        feature_data = source.get("feature_data", [])
                        for feature in feature_data:
                            feature_name = feature.get("feature_name", "")
                            feature_value = feature.get("data", 0)
                            
                            if feature_name == "total_alerts":
                                total_alerts_values.append(feature_value)
                            elif feature_name == "severity_sum":
                                severity_sum_values.append(feature_value)
                            elif feature_name == "host_diversity":
                                host_diversity_values.append(feature_value)
                            elif feature_name == "user_diversity":
                                user_diversity_values.append(feature_value)
                            elif feature_name == "high_severity_alerts":
                                high_severity_values.append(feature_value)
                        
                        # Extract anomaly metrics
                        anomaly_grade = source.get("anomaly_grade", 0.0)
                        anomaly_score = source.get("anomaly_score", 0.0)
                        confidence = source.get("confidence", 0.0)
                        threshold = source.get("threshold", 0.0)
                        
                        anomaly_grades.append(anomaly_grade)
                        anomaly_scores.append(anomaly_score)
                        confidence_scores.append(confidence)
                        threshold_values.append(threshold)
                    
                    # Calculate statistical baselines
                    def calculate_stats(values):
                        if not values:
                            return {"mean": 0, "std": 0, "p95": 0, "p99": 0, "upper_threshold": 0, "lower_threshold": 0}
                        
                        import statistics
                        mean_val = statistics.mean(values)
                        std_val = statistics.stdev(values) if len(values) > 1 else 0
                        sorted_vals = sorted(values)
                        p95 = sorted_vals[int(0.95 * len(sorted_vals))] if len(sorted_vals) > 0 else 0
                        p99 = sorted_vals[int(0.99 * len(sorted_vals))] if len(sorted_vals) > 0 else 0
                        
                        return {
                            "mean": mean_val,
                            "std": std_val,
                            "p95": p95,
                            "p99": p99,
                            "upper_threshold": mean_val + (2 * std_val),
                            "lower_threshold": max(0, mean_val - (2 * std_val))
                        }
                    
                    baselines = {
                        "total_alerts": calculate_stats(total_alerts_values),
                        "severity_sum": calculate_stats(severity_sum_values),
                        "host_diversity": calculate_stats(host_diversity_values),
                        "user_diversity": calculate_stats(user_diversity_values),
                        "high_severity_alerts": calculate_stats(high_severity_values),
                        "anomaly_grades": calculate_stats(anomaly_grades),
                        "anomaly_scores": calculate_stats(anomaly_scores),
                        "confidence_scores": calculate_stats(confidence_scores),
                        "threshold_values": calculate_stats(threshold_values),
                        "results_count": len(hits),
                        "index_search_success": True,
                        "search_method": "direct_index_query",
                        "index_name": THRESHOLD_DETECTOR_INDEX
                    }
                    
                    logger.info("Retrieved RCF baselines via index search", 
                               index=THRESHOLD_DETECTOR_INDEX,
                               results_count=len(hits),
                               alert_baseline=baselines["total_alerts"]["mean"],
                               search_method="direct_index_query")
                    
                    return baselines
                    
                else:
                    logger.error("Failed to search threshold detector index", 
                               index=THRESHOLD_DETECTOR_INDEX,
                               status=response.status,
                               response_text=await response.text())
                    return {}
                    
    except Exception as e:
        logger.error("Failed to retrieve RCF baselines via index search", 
                   index=THRESHOLD_DETECTOR_INDEX, 
                   error=str(e))
        return {}


async def trigger_on_demand_detection(detector_id: str) -> Dict[str, Any]:
    """
    Trigger on-demand detection if no historical results are found
    
    Args:
        detector_id: Anomaly detector ID
        
    Returns:
        Empty dict indicating fallback should be used
    """
    try:
        protocol = "https" if OPENSEARCH_USE_SSL else "http"
        base_url = f"{protocol}://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}"
        
        # On-demand detection API endpoint
        url = f"{base_url}/_plugins/_anomaly_detection/detectors/{detector_id}/_preview"
        
        # Setup authentication
        auth = aiohttp.BasicAuth(OPENSEARCH_USER, OPENSEARCH_PASSWORD)
        
        # SSL configuration
        connector = aiohttp.TCPConnector(verify_ssl=OPENSEARCH_VERIFY_CERTS)
        
        # Calculate recent time range for on-demand detection
        from datetime import datetime, timedelta
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=2)  # Last 2 hours for on-demand
        
        preview_query = {
            "period_start": int(start_time.timestamp() * 1000),
            "period_end": int(end_time.timestamp() * 1000)
        }
        
        async with aiohttp.ClientSession(auth=auth, connector=connector) as session:
            async with session.post(url, json=preview_query) as response:
                if response.status == 200:
                    preview_data = await response.json()
                    logger.info("Triggered on-demand detection successfully", 
                               detector_id=detector_id,
                               preview_results=len(preview_data.get("anomaly_result", [])))
                    
                    # Return empty dict to indicate fallback should be used
                    # but log that on-demand detection was triggered
                    return {"on_demand_triggered": True, "detector_id": detector_id}
                else:
                    logger.error("Failed to trigger on-demand detection", 
                               detector_id=detector_id,
                               status=response.status)
                    return {}
                    
    except Exception as e:
        logger.error("Error triggering on-demand detection", 
                   detector_id=detector_id, 
                   error=str(e))
        return {}


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect threshold-based anomalies using RCF-learned baselines from OpenSearch Anomaly Detection plugin
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including threshold, metric, timeframe, baseline
        
    Returns:
        Threshold anomaly results with RCF-based thresholds, affected entities, and analysis
    """
    try:
        # Extract parameters
        threshold = params.get("threshold")  # User-provided threshold - ONLY used as fallback when no RCF baseline data exists
        metric = params.get("metric", "alert_count")  # What to measure
        timeframe = params.get("timeframe", "24h")
        baseline = params.get("baseline", "17d")  # Baseline period for comparison
        sensitivity = params.get("sensitivity", "medium")  # RCF confidence sensitivity
        limit = params.get("limit", 20)
        
        # Handle confidence-based queries (e.g., "confidence scores above 90%")
        confidence_threshold = params.get("confidence_threshold", 0.0)
        if threshold and threshold < 1.0:  # If threshold is 0.90, treat as confidence
            confidence_threshold = threshold
            threshold = None  # Clear threshold to force RCF usage
        
        logger.info("Detecting RCF-based threshold anomalies", 
                   index=THRESHOLD_DETECTOR_INDEX,
                   metric=metric,
                   timeframe=timeframe,
                   baseline=baseline,
                   sensitivity=sensitivity,
                   confidence_threshold=confidence_threshold)
        
        # Retrieve RCF-learned baselines from threshold detector index
        rcf_baselines = await get_anomaly_results_via_search(baseline)
        
        # Use RCF baselines if available, otherwise fall back to static values
        if (rcf_baselines and
            rcf_baselines.get("results_count", 0) > 0 and
            "total_alerts" in rcf_baselines):

            # Dynamic thresholds calculated from RCF baseline analysis
            # These thresholds OVERRIDE the user-provided threshold value for better accuracy
            try:
                alert_threshold = rcf_baselines["total_alerts"]["upper_threshold"]  # RCF-learned threshold for alert count
                severity_threshold = rcf_baselines["severity_sum"]["upper_threshold"]  # RCF-learned threshold for severity sum
                host_diversity_threshold = rcf_baselines["host_diversity"]["upper_threshold"]  # RCF-learned threshold for host diversity
                user_diversity_threshold = rcf_baselines["user_diversity"]["upper_threshold"]  # RCF-learned threshold for user diversity
                high_severity_threshold = rcf_baselines["high_severity_alerts"]["upper_threshold"]  # RCF-learned threshold for high severity
                
                logger.info("Using RCF-learned dynamic thresholds",
                           alert_threshold=alert_threshold,
                           severity_threshold=severity_threshold,
                           host_diversity_threshold=host_diversity_threshold,
                           user_diversity_threshold=user_diversity_threshold,
                           results_count=rcf_baselines.get("results_count", 0))
                           
            except KeyError as e:
                logger.warning("RCF baselines incomplete, using static thresholds",
                             missing_key=str(e))
                # Fall through to static thresholds
                rcf_baselines = {}
        
        # Static fallback thresholds (only used when RCF baseline data is unavailable)
        # These use the user-provided threshold parameter as the basis for calculations
        if not rcf_baselines or rcf_baselines.get("results_count", 0) == 0:
            alert_threshold = threshold or 50  # Fallback: use user threshold or default to 50
            severity_threshold = (threshold or 50) * 5  # Fallback: assuming avg severity ~5-7
            host_diversity_threshold = (threshold or 50) * 0.2  # Fallback: host diversity
            user_diversity_threshold = (threshold or 50) * 0.3  # Fallback: user diversity
            high_severity_threshold = (threshold or 50) * 0.5  # Fallback: high severity alerts
            
            fallback_reason = "no-rcf-data"
            logger.info("Using static fallback thresholds",
                       alert_threshold=alert_threshold,
                       severity_threshold=severity_threshold,
                       host_diversity_threshold=host_diversity_threshold,
                       user_diversity_threshold=user_diversity_threshold,
                       fallback_reason=fallback_reason)
        
        # Build base query for current timeframe
        must_conditions = [
            opensearch_client.build_single_time_filter(timeframe)
        ]
        
        # Build main query for threshold analysis
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "size": 0,  # We only need aggregations
            "aggs": {
                "total_count": {
                    "value_count": {
                        "field": "_id"
                    }
                },
                "host_alert_counts": {
                    "terms": {
                        "field": "agent.name",
                        "size": 100,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "severity_breakdown": {
                            "terms": {
                                "field": "rule.level",
                                "size": 10
                            }
                        },
                        "rule_breakdown": {
                            "terms": {
                                "field": "rule.groups",
                                "size": 10
                            }
                        },
                        "hourly_distribution": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1h"
                            }
                        }
                    }
                },
                "user_alert_counts": {
                    "terms": {
                        "field": "data.win.eventdata.targetUserName",
                        "size": 50,
                        "order": {"_count": "desc"}
                    }
                },
                "rule_alert_counts": {
                    "terms": {
                        "field": "rule.id",
                        "size": 50,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "rule_description": {
                            "terms": {
                                "field": "rule.description",
                                "size": 1
                            }
                        }
                    }
                },
                "failed_login_analysis": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"wildcard": {"rule.description": "*failed*"}},
                                {"wildcard": {"rule.description": "*authentication*failure*"}},
                                {"wildcard": {"rule.description": "*logon*failed*"}},
                                {"terms": {"rule.groups": ["authentication_failed", "authentication_failures"]}}
                            ]
                        }
                    },
                    "aggs": {
                        "hosts_with_failures": {
                            "terms": {
                                "field": "agent.name",
                                "size": 20
                            }
                        },
                        "users_with_failures": {
                            "terms": {
                                "field": "data.win.eventdata.targetUserName",
                                "size": 20
                            }
                        }
                    }
                },
                "high_severity_analysis": {
                    "filter": {
                        "range": {
                            "rule.level": {"gte": 8}
                        }
                    },
                    "aggs": {
                        "hosts_high_severity": {
                            "terms": {
                                "field": "agent.name",
                                "size": 20
                            }
                        }
                    }
                },
                "new_entities": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1d"
                    },
                    "aggs": {
                        "unique_hosts": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "unique_users": {
                            "cardinality": {
                                "field": "data.win.eventdata.targetUserName"
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
        total_alerts = response["aggregations"]["total_count"]["value"]
        
        # Process aggregations
        hosts_agg = response.get("aggregations", {}).get("host_alert_counts", {})
        users_agg = response.get("aggregations", {}).get("user_alert_counts", {})
        rules_agg = response.get("aggregations", {}).get("rule_alert_counts", {})
        failed_logins_agg = response.get("aggregations", {}).get("failed_login_analysis", {})
        high_severity_agg = response.get("aggregations", {}).get("high_severity_analysis", {})
        new_entities_agg = response.get("aggregations", {}).get("new_entities", {})
        
        # Analyze host threshold anomalies with RCF-based scoring
        host_anomalies = []
        for bucket in hosts_agg.get("buckets", []):
            host = bucket["key"]
            alert_count = bucket["doc_count"]
            
            # Calculate host-level severity metrics
            host_severity_sum = sum(sev_bucket["key"] * sev_bucket["doc_count"] 
                                  for sev_bucket in bucket.get("severity_breakdown", {}).get("buckets", []))
            host_avg_severity = host_severity_sum / alert_count if alert_count > 0 else 0
            host_rule_diversity = len(bucket.get("rule_breakdown", {}).get("buckets", []))
            
            # RCF-based anomaly detection
            # Compare current values against learned thresholds to identify anomalies
            is_anomaly = False
            anomaly_reasons = []
            rcf_anomaly_score = 0.0

            if rcf_baselines:
                # Check against RCF-learned thresholds (not user-provided threshold)
                if alert_count > alert_threshold:
                    is_anomaly = True
                    anomaly_reasons.append(f"Alert count {alert_count} exceeds RCF-learned threshold {alert_threshold:.1f}")
                    rcf_anomaly_score += 30

                if host_severity_sum > severity_threshold:
                    is_anomaly = True
                    anomaly_reasons.append(f"Severity sum {host_severity_sum} exceeds RCF-learned threshold {severity_threshold:.1f}")
                    rcf_anomaly_score += 25
                
                # Remove redundant avg_severity check - already covered by severity_sum RCF baseline
                
                if host_rule_diversity > host_diversity_threshold:
                    is_anomaly = True
                    anomaly_reasons.append(f"Rule diversity {host_rule_diversity} exceeds RCF-learned threshold {host_diversity_threshold:.1f}")
                    rcf_anomaly_score += 15
                
                # Apply confidence threshold filtering if specified
                # Note: Individual anomaly confidence would need to be retrieved from detector results
                # For now, use baseline confidence as a general filter
                baseline_confidence = rcf_baselines.get("confidence_scores", {}).get("mean", 0)
                if confidence_threshold > 0.95 and baseline_confidence < confidence_threshold:
                    # Only filter if very high confidence threshold requested (>95%)
                    is_anomaly = False  # Filter out anomalies from low-confidence baselines
                    anomaly_reasons = []
                    rcf_anomaly_score = 0
                
                # Calculate RCF confidence-based anomaly score
                if baseline_confidence > 0.7:
                    rcf_anomaly_score *= 1.2  # Boost score for high-confidence baselines
                
            else:
                # Fallback to static threshold logic
                if alert_count > alert_threshold:
                    is_anomaly = True
                    anomaly_reasons.append(f"Alert count exceeds static threshold")
                    rcf_anomaly_score = min(100, (alert_count / alert_threshold) * 30)
            
            if is_anomaly:
                # Get severity breakdown
                severity_breakdown = {}
                for sev_bucket in bucket.get("severity_breakdown", {}).get("buckets", []):
                    severity_breakdown[str(sev_bucket["key"])] = sev_bucket["doc_count"]
                
                # Get rule breakdown
                rule_breakdown = []
                for rule_bucket in bucket.get("rule_breakdown", {}).get("buckets", []):
                    rule_breakdown.append({
                        "rule_group": rule_bucket["key"],
                        "count": rule_bucket["doc_count"]
                    })
                
                # Get hourly distribution
                hourly_pattern = []
                for hour_bucket in bucket.get("hourly_distribution", {}).get("buckets", []):
                    hourly_pattern.append({
                        "hour": hour_bucket["key_as_string"],
                        "count": hour_bucket["doc_count"]
                    })
                
                # Determine risk level based on RCF score
                risk_level = "Critical" if rcf_anomaly_score > 70 else "High" if rcf_anomaly_score > 40 else "Medium"
                
                host_anomalies.append({
                    "entity": host,
                    "entity_type": "host",
                    "alert_count": alert_count,
                    "host_severity_sum": host_severity_sum,
                    "host_avg_severity": round(host_avg_severity, 2),
                    "host_rule_diversity": host_rule_diversity,
                    "threshold_exceeded": alert_count - alert_threshold,
                    "anomaly_score": round(min(100, rcf_anomaly_score), 2),
                    "anomaly_reasons": anomaly_reasons,
                    "rcf_based": bool(rcf_baselines),
                    "severity_breakdown": severity_breakdown,
                    "rule_breakdown": rule_breakdown,
                    "hourly_pattern": hourly_pattern[:24],  # Last 24 hours
                    "risk_level": risk_level
                })
        
        # Analyze user threshold anomalies with RCF-based scoring
        user_anomalies = []
        user_threshold = user_diversity_threshold if rcf_baselines else alert_threshold * 0.5
        
        for bucket in users_agg.get("buckets", []):
            user = bucket["key"]
            alert_count = bucket["doc_count"]
            
            # Check if user exceeds RCF-based threshold
            if alert_count > user_threshold:
                # Calculate RCF-based anomaly score
                if rcf_baselines:
                    rcf_score = (alert_count / user_threshold) * 40  # User-specific scoring
                    confidence_multiplier = rcf_baselines.get("confidence_scores", {}).get("mean", 0.5)
                    anomaly_score = min(100, rcf_score * confidence_multiplier)
                else:
                    anomaly_score = min(100, (alert_count / user_threshold) * 40)
                
                user_anomalies.append({
                    "entity": user,
                    "entity_type": "user",
                    "alert_count": alert_count,
                    "threshold_exceeded": alert_count - user_threshold,
                    "anomaly_score": round(anomaly_score, 2),
                    "rcf_based": bool(rcf_baselines),
                    "risk_level": "High" if alert_count > user_threshold * 2 else "Medium"
                })
        
        # Analyze rule threshold anomalies with RCF-based scoring
        rule_anomalies = []
        rule_threshold = high_severity_threshold if rcf_baselines else alert_threshold * 1.5
        
        for bucket in rules_agg.get("buckets", []):
            rule_id = bucket["key"]
            alert_count = bucket["doc_count"]
            
            # Get rule description
            rule_description = "Unknown"
            desc_buckets = bucket.get("rule_description", {}).get("buckets", [])
            if desc_buckets:
                rule_description = desc_buckets[0]["key"]
            
            # Check if rule exceeds RCF-based threshold
            if alert_count > rule_threshold:
                # Calculate RCF-based anomaly score for rules
                if rcf_baselines:
                    rcf_score = (alert_count / rule_threshold) * 35
                    # High severity factor from RCF baselines
                    severity_factor = rcf_baselines.get("high_severity_alerts", {}).get("std", 1.0)
                    anomaly_score = min(100, rcf_score * (1 + severity_factor/10))
                else:
                    anomaly_score = min(100, (alert_count / rule_threshold) * 35)
                
                rule_anomalies.append({
                    "entity": rule_id,
                    "entity_type": "rule",
                    "rule_description": rule_description,
                    "alert_count": alert_count,
                    "threshold_exceeded": alert_count - rule_threshold,
                    "anomaly_score": round(anomaly_score, 2),
                    "rcf_based": bool(rcf_baselines),
                    "risk_level": "Critical" if alert_count > rule_threshold * 3 else "High"
                })
        
        # Analyze failed login anomalies using RCF-enhanced thresholds
        failed_login_anomalies = []
        failed_login_total = failed_logins_agg.get("doc_count", 0)
        
        # Use RCF-based failed login threshold or fallback
        if rcf_baselines and "total_alerts" in rcf_baselines:
            # Calculate failed login threshold as a proportion of normal alert activity
            normal_alert_rate = rcf_baselines["total_alerts"]["mean"]
            failed_login_threshold = max(5, normal_alert_rate * 0.1)  # 10% of normal alert rate
        else:
            failed_login_threshold = (threshold or 50) // 5
        
        if failed_login_total > failed_login_threshold:
            # Hosts with most failures
            failed_hosts = []
            for bucket in failed_logins_agg.get("hosts_with_failures", {}).get("buckets", []):
                failed_hosts.append({
                    "host": bucket["key"],
                    "failed_attempts": bucket["doc_count"]
                })
            
            # Users with most failures
            failed_users = []
            for bucket in failed_logins_agg.get("users_with_failures", {}).get("buckets", []):
                failed_users.append({
                    "user": bucket["key"],
                    "failed_attempts": bucket["doc_count"]
                })
            
            failed_login_anomalies.append({
                "anomaly_type": "failed_authentication",
                "total_failures": failed_login_total,
                "threshold": failed_login_threshold,
                "threshold_exceeded": failed_login_total - failed_login_threshold,
                "rcf_based": bool(rcf_baselines),
                "affected_hosts": failed_hosts[:10],
                "affected_users": failed_users[:10],
                "risk_level": "High" if failed_login_total > failed_login_threshold * 2 else "Medium"
            })
        
        # Analyze high severity anomalies using RCF-enhanced thresholds  
        high_severity_anomalies = []
        high_severity_total = high_severity_agg.get("doc_count", 0)
        
        # Use RCF-based high severity threshold or fallback
        high_severity_analysis_threshold = (
            high_severity_threshold if rcf_baselines 
            else 5
        )
        
        if high_severity_total > high_severity_analysis_threshold:
            high_severity_hosts = []
            for bucket in high_severity_agg.get("hosts_high_severity", {}).get("buckets", []):
                high_severity_hosts.append({
                    "host": bucket["key"],
                    "high_severity_count": bucket["doc_count"]
                })
            
            high_severity_anomalies.append({
                "anomaly_type": "high_severity_alerts",
                "total_high_severity": high_severity_total,
                "threshold": high_severity_analysis_threshold,
                "threshold_exceeded": high_severity_total - high_severity_analysis_threshold,
                "rcf_based": bool(rcf_baselines),
                "affected_hosts": high_severity_hosts[:10],
                "risk_level": "Critical"
            })
        
        # Analyze new entity anomalies using RCF-enhanced thresholds
        new_entity_anomalies = []
        
        # Use RCF-based thresholds for new entity detection (remove hard-coded multipliers)
        if rcf_baselines:
            # Use RCF P95 percentiles for new entity thresholds instead of arbitrary multipliers
            new_host_threshold = rcf_baselines.get("host_diversity", {}).get("p95", host_diversity_threshold)
            new_user_threshold = rcf_baselines.get("user_diversity", {}).get("p95", user_diversity_threshold)
        else:
            new_host_threshold = 10
            new_user_threshold = 20
        
        for bucket in new_entities_agg.get("buckets", []):
            day = bucket["key_as_string"]
            unique_hosts = bucket.get("unique_hosts", {}).get("value", 0)
            unique_users = bucket.get("unique_users", {}).get("value", 0)
            
            anomaly_reasons = []
            is_new_entity_anomaly = False
            
            if unique_hosts > new_host_threshold:
                is_new_entity_anomaly = True
                anomaly_reasons.append(f"Host count {unique_hosts} exceeds RCF-learned threshold {new_host_threshold:.1f}")

            if unique_users > new_user_threshold:
                is_new_entity_anomaly = True
                anomaly_reasons.append(f"User count {unique_users} exceeds RCF-learned threshold {new_user_threshold:.1f}")
            
            if is_new_entity_anomaly:
                new_entity_anomalies.append({
                    "date": day,
                    "new_hosts": unique_hosts,
                    "new_users": unique_users,
                    "host_threshold": new_host_threshold,
                    "user_threshold": new_user_threshold,
                    "anomaly_reasons": anomaly_reasons,
                    "rcf_based": bool(rcf_baselines)
                })
        
        # Sort anomalies by score
        host_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        user_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        rule_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        
        # Build result with RCF baseline information
        result = {
            "total_alerts": total_alerts,
            "analysis_period": timeframe,
            "detector_info": {
                "index_name": THRESHOLD_DETECTOR_INDEX,
                "rcf_baselines_used": bool(rcf_baselines),
                "baseline_period": baseline,
                "baseline_results_count": rcf_baselines.get("results_count", 0) if rcf_baselines else 0,
                "index_search_success": rcf_baselines.get("index_search_success", False) if rcf_baselines else False,
                "search_method": rcf_baselines.get("search_method", "fallback") if rcf_baselines else "fallback"
            },
            "threshold_settings": {
                # Clarification section explaining threshold types and usage
                "threshold_explanation": {
                    "user_provided_threshold": threshold,  # The value from the query parameter
                    "threshold_usage": "RCF-learned thresholds from baseline analysis" if rcf_baselines else "User-provided fallback threshold",
                    "note": "RCF-learned thresholds override user-provided values when baseline data is available"
                },
                # Specific threshold values with clear naming (renamed for clarity)
                "alert_count_threshold": alert_threshold,  # Threshold for total alert count
                "severity_sum_threshold": severity_threshold,  # Threshold for cumulative severity
                "host_diversity_threshold": host_diversity_threshold,  # Threshold for unique host count
                "user_diversity_threshold": user_diversity_threshold,  # Threshold for unique user count
                "high_severity_threshold": high_severity_threshold,  # Threshold for high severity alerts (level >= 8)
                "failed_login_threshold": failed_login_threshold,  # Threshold for failed authentication attempts
                "new_host_threshold": new_host_threshold,  # Threshold for new host appearances
                "new_user_threshold": new_user_threshold,  # Threshold for new user appearances
                "confidence_threshold": confidence_threshold,  # Minimum confidence level for anomaly detection
                "baseline_confidence": rcf_baselines.get("confidence_scores", {}).get("mean", 0) if rcf_baselines else 0,  # Confidence level of RCF baseline
                "threshold_source": "RCF-learned from baseline" if rcf_baselines else "Static fallback (user-provided or default)"  # Source of threshold values
            },
            "rcf_baselines": rcf_baselines if rcf_baselines else {},
            "host_anomalies": host_anomalies[:limit],
            "user_anomalies": user_anomalies[:limit],
            "rule_anomalies": rule_anomalies[:limit],
            "failed_login_anomalies": failed_login_anomalies,
            "high_severity_anomalies": high_severity_anomalies,
            "new_entity_anomalies": new_entity_anomalies,
            "summary": {
                "total_anomalies": len(host_anomalies) + len(user_anomalies) + len(rule_anomalies),
                "hosts_above_threshold": len(host_anomalies),
                "users_above_threshold": len(user_anomalies),
                "rules_above_threshold": len(rule_anomalies),
                "rcf_based_detections": len([a for a in host_anomalies + user_anomalies + rule_anomalies if a.get("rcf_based", False)]),
                "highest_anomaly_host": host_anomalies[0]["entity"] if host_anomalies else None,
                "highest_anomaly_score": host_anomalies[0]["anomaly_score"] if host_anomalies else 0,
                "critical_anomalies": len([a for a in host_anomalies + user_anomalies + rule_anomalies if a.get("risk_level") == "Critical"]),
                "risk_assessment": "Critical" if any(a.get("risk_level") == "Critical" for a in host_anomalies + user_anomalies + rule_anomalies) else "High" if host_anomalies or user_anomalies or rule_anomalies else "Low"
            }
        }
        
        logger.info("RCF-based threshold anomaly detection completed", 
                   total_alerts=total_alerts,
                   anomalies_found=result["summary"]["total_anomalies"],
                   critical_anomalies=result["summary"]["critical_anomalies"],
                   rcf_baselines_used=bool(rcf_baselines),
                   index=THRESHOLD_DETECTOR_INDEX)
        
        return result
        
    except Exception as e:
        logger.error("Threshold anomaly detection failed", error=str(e))
        raise Exception(f"Failed to detect threshold anomalies: {str(e)}")