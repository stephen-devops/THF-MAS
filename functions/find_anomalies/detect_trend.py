"""
Identify trend-based anomalies by detecting unusual changes in temporal patterns, escalations
and directional shifts in security metrics over time. Use RCF to establish trend baselines.
"""
from typing import Dict, Any
import structlog
from datetime import datetime, timedelta
import statistics
import os
import aiohttp
import traceback

logger = structlog.get_logger()

# Load environment variables for RCF trend detector
TREND_DETECTOR_INDEX = os.getenv("TREND_DETECTOR_INDEX", "opensearch-ad-plugin-result-alert-trend-*")
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = os.getenv("OPENSEARCH_PORT", "9200")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")
OPENSEARCH_USE_SSL = os.getenv("OPENSEARCH_USE_SSL", "false").lower() == "true"
OPENSEARCH_VERIFY_CERTS = os.getenv("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true"


async def get_rcf_trend_baselines(timeframe: str) -> Dict[str, Any]:
    """
    Retrieve RCF-learned trend baselines from trend detector anomaly results index
    
    Args:
        timeframe: Time range for baseline retrieval
        
    Returns:
        RCF trend baseline data with learned thresholds and trend patterns
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
        
        # Query the trend detector anomaly results index
        url = f"{base_url}/{TREND_DETECTOR_INDEX}/_search"
        
        search_query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "data_end_time": {
                                    "gte": int(start_time.timestamp() * 1000),
                                    "lte": int(end_time.timestamp() * 1000)
                                }
                            }
                        },
                        {
                            "range": {
                                "anomaly_grade": {
                                    "gt": 0
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [{"data_end_time": {"order": "desc"}}],
            "size": 100,
            "_source": ["detector_id", "feature_data", "anomaly_grade", "anomaly_score", "confidence", "threshold", "data_end_time", "data_start_time", "relevant_attribution"]
        }

        # Calculate time range for query
        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)
        
        auth = aiohttp.BasicAuth(OPENSEARCH_USER, OPENSEARCH_PASSWORD)
        connector = aiohttp.TCPConnector(verify_ssl=OPENSEARCH_VERIFY_CERTS)
        
        async with aiohttp.ClientSession(auth=auth, connector=connector) as session:
            async with session.post(url, json=search_query) as response:
                if response.status == 200:
                    results_data = await response.json()
                    hits = results_data.get("hits", {}).get("hits", [])

                    if not hits:
                        logger.warning("No RCF trend results found", index=TREND_DETECTOR_INDEX)
                        return {}
                    
                    # Extract trend baselines from RCF results
                    alert_volume_values = []
                    severity_escalation_values = []
                    attack_diversity_values = []
                    temporal_spread_values = []
                    impact_progression_values = []
                    anomaly_grades = []
                    anomaly_scores = []
                    confidence_scores = []
                    threshold_values = []

                    # Store actual RCF-detected anomalies for return
                    rcf_detected_anomalies = []

                    for hit in hits:
                        source = hit.get("_source", {})
                        feature_data = source.get("feature_data", [])
                        
                        for feature in feature_data:
                            feature_name = feature.get("feature_name", "")
                            feature_value = feature.get("data", 0)
                            
                            if feature_name == "alert_volume_trend":
                                alert_volume_values.append(feature_value)
                            elif feature_name == "severity_escalation_trend":
                                severity_escalation_values.append(feature_value)
                            elif feature_name == "attack_diversity_trend":
                                attack_diversity_values.append(feature_value)
                            elif feature_name == "temporal_spread_trend":
                                temporal_spread_values.append(feature_value)
                            elif feature_name == "impact_progression_trend":
                                impact_progression_values.append(feature_value)
                        
                        anomaly_grade = source.get("anomaly_grade", 0.0)
                        anomaly_score = source.get("anomaly_score", 0.0)
                        confidence = source.get("confidence", 0.0)
                        threshold = source.get("threshold", 0.0)

                        anomaly_grades.append(anomaly_grade)
                        anomaly_scores.append(anomaly_score)
                        confidence_scores.append(confidence)
                        threshold_values.append(threshold)

                        # Store RCF-detected anomalies (grade > 0 indicates anomaly)
                        if anomaly_grade > 0:
                            # Convert Unix timestamp to readable format
                            data_end_time_ms = source.get("data_end_time", 0)
                            data_start_time_ms = source.get("data_start_time", 0)

                            # datetime is already imported at the top of the file
                            try:
                                timestamp_readable = datetime.fromtimestamp(data_end_time_ms / 1000).strftime('%Y-%m-%d %H:%M:%S') if data_end_time_ms else "Unknown"
                            except (ValueError, OSError, OverflowError):
                                timestamp_readable = "Invalid timestamp"

                            # Extract feature values for this specific anomaly
                            anomaly_features = {}
                            for feature in feature_data:
                                anomaly_features[feature.get("feature_name", "unknown")] = feature.get("data", 0)

                            rcf_detected_anomalies.append({
                                "timestamp": timestamp_readable,
                                "data_end_time": data_end_time_ms,
                                "data_start_time": data_start_time_ms,
                                "anomaly_grade": anomaly_grade,
                                "anomaly_score": anomaly_score,
                                "confidence": confidence,
                                "threshold": threshold,
                                "detector_id": source.get("detector_id", "unknown"),
                                "features": anomaly_features,
                                "risk_level": "Critical" if anomaly_grade > 0.7 else "High" if anomaly_grade > 0.4 else "Medium",
                                "relevant_attribution": source.get("relevant_attribution", [])
                            })
                    
                    # Calculate RCF-enhanced statistical baselines for trends
                    def calculate_trend_stats(values):
                        if not values:
                            return {"mean": 0, "std": 0, "trend_threshold": 0, "escalation_threshold": 0, "rcf_multiplier": 1.0}
                        
                        mean_val = statistics.mean(values)
                        std_val = statistics.stdev(values) if len(values) > 1 else 0
                        
                        # Use RCF data to determine dynamic multipliers instead of hard-coded 1.5/2.5
                        sorted_vals = sorted(values)
                        p75 = sorted_vals[int(0.75 * len(sorted_vals))] if len(sorted_vals) > 0 else mean_val
                        p90 = sorted_vals[int(0.90 * len(sorted_vals))] if len(sorted_vals) > 0 else mean_val
                        
                        # Dynamic multipliers based on RCF data distribution
                        trend_multiplier = (p75 - mean_val) / std_val if std_val > 0 else 1.2
                        escalation_multiplier = (p90 - mean_val) / std_val if std_val > 0 else 2.0
                        
                        return {
                            "mean": mean_val,
                            "std": std_val,
                            "trend_threshold": mean_val + (trend_multiplier * std_val),  # RCF-learned trend threshold
                            "escalation_threshold": mean_val + (escalation_multiplier * std_val),  # RCF-learned escalation threshold
                            "current_baseline": mean_val,
                            "rcf_trend_multiplier": trend_multiplier,
                            "rcf_escalation_multiplier": escalation_multiplier
                        }
                    
                    rcf_trend_baselines = {
                        "alert_volume_trend": calculate_trend_stats(alert_volume_values),
                        "severity_escalation_trend": calculate_trend_stats(severity_escalation_values),
                        "attack_diversity_trend": calculate_trend_stats(attack_diversity_values),
                        "temporal_spread_trend": calculate_trend_stats(temporal_spread_values),
                        "impact_progression_trend": calculate_trend_stats(impact_progression_values),
                        "anomaly_grades": calculate_trend_stats(anomaly_grades),
                        "anomaly_scores": calculate_trend_stats(anomaly_scores),
                        "confidence_scores": calculate_trend_stats(confidence_scores),
                        "threshold_values": calculate_trend_stats(threshold_values),
                        "results_count": len(hits),
                        "rcf_enhanced": True,
                        "index_name": TREND_DETECTOR_INDEX,
                        "rcf_detected_anomalies": rcf_detected_anomalies  # Include actual RCF anomalies
                    }
                    
                    logger.info("Retrieved RCF trend baselines",
                               results_count=len(hits),
                               rcf_anomalies_found=len(rcf_detected_anomalies))

                    return rcf_trend_baselines
                else:
                    logger.error("Failed to query trend detector index", 
                               status=response.status, index=TREND_DETECTOR_INDEX)
                    return {}


    except Exception as e:
        logger.error("Failed to retrieve RCF trend baselines",
                    error=str(e),
                    error_type=type(e).__name__,
                    traceback=traceback.format_exc())
        return {}


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Identify trend-based anomalies by detecting unusual changes in temporal patterns, escalations 
    and directional shifts in security metrics over time using RCF-learned trend baselines.
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including timeframe, trend_type, metric, baseline
        
    Returns:
        RCF-enhanced trend anomaly results with escalation patterns and directional shifts
    """
    try:
        # Extract parameters
        timeframe = params.get("timeframe", "24h")
        trend_type = params.get("trend_type", "both")  # increasing, decreasing, both
        metric = params.get("metric", "all_trends")  # Use all RCF trend features
        baseline = params.get("baseline", "17d")  # Baseline period for RCF trend comparison
        sensitivity = params.get("sensitivity", "medium")  # low, medium, high
        limit = params.get("limit", 20)
        
        logger.info("Detecting RCF-enhanced trend anomalies", 
                   timeframe=timeframe,
                   trend_type=trend_type,
                   metric=metric,
                   baseline=baseline,
                   sensitivity=sensitivity)
        
        # Retrieve RCF-learned trend baselines
        rcf_trend_baselines = await get_rcf_trend_baselines(baseline)

        # Build RCF-aligned query for trend analysis matching trend detector features
        query = {
            "query": {
                "bool": {
                    "must": [opensearch_client.build_single_time_filter(timeframe)]
                }
            },
            "size": 0,
            "aggs": {
                "total_count": {
                    "value_count": {
                        "field": "_id"
                    }
                },
                "trend_time_series": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "30m",  # Match trend detector 30-minute intervals
                        "order": {"_key": "asc"}
                    },
                    "aggs": {
                        "alert_volume_trend": {
                            "value_count": {
                                "field": "rule.id"
                            }
                        },
                        "severity_escalation_trend": {
                            "avg": {
                                "field": "rule.level"
                            }
                        },
                        "attack_diversity_trend": {
                            "cardinality": {
                                "field": "rule.id"
                            }
                        },
                        "temporal_spread_trend": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "impact_progression_trend": {
                            "sum": {
                                "field": "rule.level"
                            }
                        }
                    }
                },
                "host_trends": {
                    "terms": {
                        "field": "agent.name",
                        "size": 50
                    },
                    "aggs": {
                        "time_series": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "2h"
                            }
                        },
                        "severity_trend": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "2h"
                            },
                            "aggs": {
                                "avg_severity": {
                                    "avg": {
                                        "field": "rule.level"
                                    }
                                }
                            }
                        }
                    }
                },
                "user_trends": {
                    "terms": {
                        "field": "data.win.eventdata.targetUserName",
                        "size": 30
                    },
                    "aggs": {
                        "time_series": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "2h"
                            }
                        }
                    }
                },
                "rule_trends": {
                    "terms": {
                        "field": "rule.id",
                        "size": 30
                    },
                    "aggs": {
                        "time_series": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1h"
                            }
                        },
                        "rule_description": {
                            "terms": {
                                "field": "rule.description",
                                "size": 1
                            }
                        }
                    }
                },
                "failed_login_trends": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"wildcard": {"rule.description": "*failed*"}},
                                {"wildcard": {"rule.description": "*authentication*failure*"}},
                                {"terms": {"rule.groups": ["authentication_failed", "authentication_failures"]}}
                            ]
                        }
                    },
                    "aggs": {
                        "time_series": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1h"
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
        
        # Process RCF-aligned time series data
        trend_time_series_agg = response.get("aggregations", {}).get("trend_time_series", {})
        hosts_agg = response.get("aggregations", {}).get("host_trends", {})
        users_agg = response.get("aggregations", {}).get("user_trends", {})
        rules_agg = response.get("aggregations", {}).get("rule_trends", {})
        failed_logins_agg = response.get("aggregations", {}).get("failed_login_trends", {})
        
        # Use RCF baselines for trend detection or fall back to minimal static thresholds
        if rcf_trend_baselines and rcf_trend_baselines.get("results_count", 0) > 0:
            logger.info("Using RCF-learned trend thresholds",
                       confidence=rcf_trend_baselines.get("confidence_scores", {}).get("mean", 0))
            
            # Use RCF confidence score to determine sensitivity multiplier instead of hard-coded values
            rcf_confidence = rcf_trend_baselines.get("confidence_scores", {}).get("mean", 0.5)

            # Dynamic sensitivity based on RCF confidence and anomaly grade patterns
            rcf_anomaly_grade_mean = rcf_trend_baselines.get("anomaly_grades", {}).get("mean", 0.1)

            # Explicit None checks to prevent NoneType errors
            if rcf_confidence is None:
                rcf_confidence = 0.5
            if rcf_anomaly_grade_mean is None:
                rcf_anomaly_grade_mean = 0.1

            # Adjust sensitivity based on historical anomaly grades
            grade_adjustment = max(0.5, 1.0 - rcf_anomaly_grade_mean * 0.5)  # Lower grades = higher sensitivity

            sensitivity_multipliers = {
                "low": max(0.8, (1.0 - rcf_confidence * 0.3) * grade_adjustment),      # Less sensitive when RCF is confident
                "medium": max(0.6, (1.0 - rcf_confidence * 0.5) * grade_adjustment),    # Standard RCF-based sensitivity
                "high": max(0.4, (1.0 - rcf_confidence * 0.7) * grade_adjustment)       # More sensitive when RCF is confident
            }
            multiplier = sensitivity_multipliers.get(sensitivity, 0.7)

            # Ensure multiplier is not None
            if multiplier is None:
                multiplier = 0.7

            # Use RCF threshold values instead of arbitrary slopes
            rcf_threshold_mean = rcf_trend_baselines.get("threshold_values", {}).get("mean", 1.0)
            if rcf_threshold_mean is None:
                rcf_threshold_mean = 1.0

        else:
            # Minimal fallback - rely on basic statistical analysis only
            logger.info("No RCF data available - using static thresholds")
            multiplier = 1.0
            rcf_threshold_mean = 1.0

        # Analyze RCF-aligned trend features
        trend_time_series = []
        time_points = []
        alert_volume_values = []
        severity_escalation_values = []
        attack_diversity_values = []
        temporal_spread_values = []
        impact_progression_values = []
        
        for i, bucket in enumerate(trend_time_series_agg.get("buckets", [])):
            timestamp = bucket["key_as_string"]

            # Extract RCF trend feature values - EXPLICITLY handle None values
            alert_volume = bucket.get("alert_volume_trend", {}).get("value", 0)
            severity_escalation = bucket.get("severity_escalation_trend", {}).get("value", 0)
            attack_diversity = bucket.get("attack_diversity_trend", {}).get("value", 0)
            temporal_spread = bucket.get("temporal_spread_trend", {}).get("value", 0)
            impact_progression = bucket.get("impact_progression_trend", {}).get("value", 0)

            # Convert None to 0 to prevent statistics errors
            alert_volume = alert_volume if alert_volume is not None else 0
            severity_escalation = severity_escalation if severity_escalation is not None else 0
            attack_diversity = attack_diversity if attack_diversity is not None else 0
            temporal_spread = temporal_spread if temporal_spread is not None else 0
            impact_progression = impact_progression if impact_progression is not None else 0

            time_points.append(i)
            alert_volume_values.append(alert_volume)
            severity_escalation_values.append(severity_escalation)
            attack_diversity_values.append(attack_diversity)
            temporal_spread_values.append(temporal_spread)
            impact_progression_values.append(impact_progression)
            
            trend_time_series.append({
                "timestamp": timestamp,
                "alert_volume_trend": alert_volume,
                "severity_escalation_trend": severity_escalation,
                "attack_diversity_trend": attack_diversity,
                "temporal_spread_trend": temporal_spread,
                "impact_progression_trend": impact_progression
            })
        
        # Calculate RCF-enhanced trend analysis
        overall_trends = {}
        trend_anomalies = []

        if len(time_points) >= 3:
            # Analyze each RCF trend feature
            trend_features = {
                "alert_volume_trend": alert_volume_values,
                "severity_escalation_trend": severity_escalation_values, 
                "attack_diversity_trend": attack_diversity_values,
                "temporal_spread_trend": temporal_spread_values,
                "impact_progression_trend": impact_progression_values
            }
            
            for feature_name, feature_values in trend_features.items():
                if not feature_values or all(v == 0 for v in feature_values):
                    continue
                
                try:
                    # Calculate linear regression slope for trend detection
                    regression_result = statistics.linear_regression(time_points, feature_values)
                    slope = regression_result.slope if regression_result else 0
                    correlation = statistics.correlation(time_points, feature_values) if len(feature_values) > 1 else 0
                    mean_value = statistics.mean(feature_values)

                    # Skip if any critical values are None
                    if slope is None or mean_value is None:
                        continue
                    
                    # RCF-enhanced anomaly detection using learned baselines
                    if rcf_trend_baselines and feature_name in rcf_trend_baselines:
                        rcf_baseline = rcf_trend_baselines[feature_name]
                        baseline_mean = rcf_baseline.get("current_baseline", mean_value)

                        # Ensure baseline_mean is not None
                        if baseline_mean is None:
                            baseline_mean = mean_value

                        # Use RCF-learned thresholds directly (already calculated with proper multipliers)
                        trend_threshold = rcf_baseline.get("trend_threshold", baseline_mean)
                        escalation_threshold = rcf_baseline.get("escalation_threshold", baseline_mean)

                        # Ensure thresholds are not None
                        if trend_threshold is None:
                            trend_threshold = baseline_mean if baseline_mean else 1.0
                        if escalation_threshold is None:
                            escalation_threshold = baseline_mean if baseline_mean else 1.0

                        # Apply sensitivity adjustment only if needed
                        if multiplier != 1.0 and multiplier is not None:
                            trend_threshold *= multiplier
                            escalation_threshold *= multiplier
                        
                        # Detect trend anomalies using RCF thresholds
                        # Ensure no None values in calculations
                        if baseline_mean is None or mean_value is None:
                            continue

                        current_deviation = abs(mean_value - baseline_mean)
                        is_trend_anomaly = current_deviation > trend_threshold
                        is_escalation = current_deviation > escalation_threshold
                        
                        # Check for directional shifts
                        trend_direction = "increasing" if slope > 0 else "decreasing" if slope < 0 else "stable"
                        
                        if is_trend_anomaly or is_escalation:
                            anomaly_score = min(100, (current_deviation / baseline_mean * 100) if baseline_mean > 0 else 50)
                            
                            trend_anomalies.append({
                                "feature": feature_name,
                                "anomaly_type": "escalation" if is_escalation else "trend_shift",
                                "current_value": round(mean_value, 2),
                                "baseline_value": round(baseline_mean, 2),
                                "deviation": round(current_deviation, 2),
                                "trend_direction": trend_direction,
                                "slope": round(slope, 4),
                                "correlation": round(correlation, 3),
                                "anomaly_score": round(anomaly_score, 2),
                                "rcf_enhanced": True,
                                "risk_level": "Critical" if is_escalation else "High" if anomaly_score > 70 else "Medium"
                            })
                            
                    else:
                        # Fallback to basic statistical analysis without hard-coded thresholds
                        # Use standard deviation to identify significant trends
                        if len(feature_values) > 2 and slope is not None:
                            std_dev = statistics.stdev(feature_values)
                            trend_significance = abs(slope) * len(feature_values)  # Slope magnitude * data points
                            
                            # Use statistical significance instead of arbitrary thresholds
                            is_significant_trend = trend_significance > std_dev
                            
                            if is_significant_trend:
                                # Calculate anomaly score based on statistical significance
                                anomaly_score = min(100, (trend_significance / std_dev) * 20) if std_dev > 0 else 30
                                
                                trend_anomalies.append({
                                    "feature": feature_name,
                                    "anomaly_type": "trend_shift",
                                    "current_value": round(mean_value, 2),
                                    "trend_direction": "increasing" if slope > 0 else "decreasing",
                                    "slope": round(slope, 4),
                                    "correlation": round(correlation, 3),
                                    "anomaly_score": round(anomaly_score, 2),
                                    "statistical_significance": round(trend_significance, 2),
                                    "rcf_enhanced": False,
                                    "risk_level": "Medium"
                                })
                                
                except (ValueError, statistics.StatisticsError):
                    continue  # Skip if statistical calculation fails
            
            # Build overall trends summary
            if alert_volume_values:
                try:
                    regression = statistics.linear_regression(time_points, alert_volume_values)
                    alert_slope = regression.slope if regression else 0
                    mean_alerts = statistics.mean(alert_volume_values)

                    # Skip if critical values are None
                    if alert_slope is None or mean_alerts is None:
                        overall_trends = {"error": "Insufficient data for trend analysis"}
                        raise ValueError("None values in trend calculation")
                    
                    overall_trends = {
                        "primary_trend": "alert_volume_escalation" if alert_slope > 0 else "alert_volume_decline" if alert_slope < 0 else "stable",
                        "trend_slope": round(alert_slope, 4),
                        "mean_alert_volume": round(mean_alerts, 2),
                        "rcf_enhanced": bool(rcf_trend_baselines),
                        "total_trend_anomalies": len(trend_anomalies),
                        "confidence_score": rcf_trend_baselines.get("confidence_scores", {}).get("mean", 0) if rcf_trend_baselines else 0
                    }
                except (ValueError, statistics.StatisticsError):
                    overall_trends = {"error": "Insufficient data for trend analysis"}
        
        # Analyze host-specific trends
        host_trend_anomalies = []
        for bucket in hosts_agg.get("buckets", []):
            host = bucket["key"]
            total_alerts = bucket["doc_count"]
            
            if total_alerts < 5:  # Skip hosts with too few alerts
                continue
            
            # Extract time series data for this host
            host_time_points = []
            host_alert_counts = []
            host_severity_trend = []
            
            for i, time_bucket in enumerate(bucket.get("time_series", {}).get("buckets", [])):
                host_time_points.append(i)
                host_alert_counts.append(time_bucket["doc_count"])
            
            for sev_bucket in bucket.get("severity_trend", {}).get("buckets", []):
                avg_sev = sev_bucket.get("avg_severity", {}).get("value", 0)
                host_severity_trend.append(avg_sev if avg_sev else 0)
            
            # Calculate host trend statistics
            if len(host_time_points) >= 3:
                n = len(host_time_points)
                sum_x = sum(host_time_points)
                sum_y = sum(host_alert_counts)
                sum_xy = sum(x * y for x, y in zip(host_time_points, host_alert_counts))
                sum_x2 = sum(x * x for x in host_time_points)
                
                if n * sum_x2 - sum_x * sum_x != 0:
                    host_slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)

                    # Skip if slope calculation resulted in None
                    if host_slope is None:
                        continue

                    # Check for trend anomalies using RCF-learned thresholds
                    is_anomaly = False
                    anomaly_reasons = []
                    
                    # Use RCF-derived trend threshold instead of arbitrary slope calculations
                    if rcf_trend_baselines and rcf_trend_baselines.get("alert_volume_trend"):
                        # Use the actual RCF-learned trend threshold for slope comparison
                        baseline_data = rcf_trend_baselines["alert_volume_trend"]
                        slope_threshold = baseline_data.get("trend_threshold", baseline_data.get("std", 1.0))
                    else:
                        # Statistical fallback based on host data distribution
                        if len(host_alert_counts) > 1:
                            host_std = statistics.stdev(host_alert_counts)
                            slope_threshold = host_std / len(host_alert_counts) if len(host_alert_counts) > 0 else 0.1
                        else:
                            slope_threshold = 0.1
                    
                    if trend_type in ["increasing", "both"] and host_slope > slope_threshold:
                        is_anomaly = True
                        anomaly_reasons.append(f"Rapidly increasing alert trend (slope: {host_slope:.3f})")
                    
                    if trend_type in ["decreasing", "both"] and host_slope < -slope_threshold:
                        is_anomaly = True
                        anomaly_reasons.append(f"Rapidly decreasing alert trend (slope: {host_slope:.3f})")
                    
                    # Check severity trend using RCF-learned escalation patterns
                    if len(host_severity_trend) >= 3:
                        severity_regression = statistics.linear_regression(range(len(host_severity_trend)), host_severity_trend)
                        severity_slope = severity_regression.slope if severity_regression else 0

                        # Skip if severity_slope is None
                        if severity_slope is None:
                            severity_slope = 0
                        
                        # Use RCF-derived severity escalation threshold directly
                        if rcf_trend_baselines and rcf_trend_baselines.get("severity_escalation_trend"):
                            severity_baseline = rcf_trend_baselines["severity_escalation_trend"]
                            severity_threshold = severity_baseline.get("escalation_threshold", severity_baseline.get("std", 1.0))
                        else:
                            # Statistical fallback based on severity data
                            severity_std = statistics.stdev(host_severity_trend) if len(host_severity_trend) > 1 else 1.0
                            severity_threshold = severity_std * 0.5
                        
                        if severity_slope > severity_threshold:
                            is_anomaly = True
                            anomaly_reasons.append(f"Increasing severity trend (slope: {severity_slope:.3f})")
                    
                    if is_anomaly:
                        host_trend_anomalies.append({
                            "host": host,
                            "total_alerts": total_alerts,
                            "trend_slope": round(host_slope, 4),
                            "trend_direction": "increasing" if host_slope > 0 else "decreasing",
                            "anomaly_score": min(100, abs(host_slope) * 1000),
                            "anomaly_reasons": anomaly_reasons,
                            "time_series": [{"period": i, "count": count} for i, count in enumerate(host_alert_counts)],
                            "risk_level": "High" if abs(host_slope) > slope_threshold * multiplier else "Medium"
                        })
        
        # Analyze user activity trends
        user_trend_anomalies = []
        for bucket in users_agg.get("buckets", []):
            user = bucket["key"]
            total_activity = bucket["doc_count"]
            
            if total_activity < 3:  # Skip users with too little activity
                continue
            
            # Extract time series data for this user
            user_time_points = []
            user_activity_counts = []
            
            for i, time_bucket in enumerate(bucket.get("time_series", {}).get("buckets", [])):
                user_time_points.append(i)
                user_activity_counts.append(time_bucket["doc_count"])
            
            # Calculate user trend statistics
            if len(user_time_points) >= 3:
                try:
                    user_regression = statistics.linear_regression(user_time_points, user_activity_counts)
                    slope = user_regression.slope if user_regression else 0

                    # Skip if slope is None
                    if slope is None:
                        continue
                    
                    # Check for significant trends using RCF-learned baselines
                    if rcf_trend_baselines and rcf_trend_baselines.get("temporal_spread_trend"):
                        temporal_baseline = rcf_trend_baselines["temporal_spread_trend"]
                        user_slope_threshold = temporal_baseline.get("trend_threshold", temporal_baseline.get("std", 1.0))
                    else:
                        # Statistical fallback for user activity trends
                        if len(user_activity_counts) > 1:
                            user_std = statistics.stdev(user_activity_counts)
                            user_slope_threshold = user_std / len(user_activity_counts) if len(user_activity_counts) > 0 else 0.05
                        else:
                            user_slope_threshold = 0.05
                    
                    if abs(slope) > user_slope_threshold:
                        user_trend_anomalies.append({
                            "user": user,
                            "total_activity": total_activity,
                            "trend_slope": round(slope, 4),
                            "trend_direction": "increasing" if slope > 0 else "decreasing",
                            "anomaly_score": min(100, abs(slope) * 500),
                            "anomaly_reason": f"{'Increasing' if slope > 0 else 'Decreasing'} user activity trend",
                            "time_series": [{"period": i, "count": count} for i, count in enumerate(user_activity_counts)],
                            "risk_level": "Medium" if abs(slope) > user_slope_threshold * multiplier else "Low"
                        })
                except (ValueError, statistics.StatisticsError, ZeroDivisionError):
                    continue  # Skip if regression fails
        
        # Analyze rule firing trends
        rule_trend_anomalies = []
        for bucket in rules_agg.get("buckets", []):
            rule_id = bucket["key"]
            total_fires = bucket["doc_count"]
            
            # Get rule description
            rule_description = "Unknown"
            desc_buckets = bucket.get("rule_description", {}).get("buckets", [])
            if desc_buckets:
                rule_description = desc_buckets[0]["key"]
            
            if total_fires < 5:  # Skip rules with too few fires
                continue
            
            # Extract time series data for this rule
            rule_time_points = []
            rule_fire_counts = []
            
            for i, time_bucket in enumerate(bucket.get("time_series", {}).get("buckets", [])):
                rule_time_points.append(i)
                rule_fire_counts.append(time_bucket["doc_count"])
            
            # Calculate rule trend statistics
            if len(rule_time_points) >= 3:
                try:
                    rule_regression = statistics.linear_regression(rule_time_points, rule_fire_counts)
                    slope = rule_regression.slope if rule_regression else 0

                    # Skip if slope is None
                    if slope is None:
                        continue
                    
                    # Check for significant trends using RCF-learned attack diversity patterns
                    if rcf_trend_baselines and rcf_trend_baselines.get("attack_diversity_trend"):
                        diversity_baseline = rcf_trend_baselines["attack_diversity_trend"]
                        rule_slope_threshold = diversity_baseline.get("trend_threshold", diversity_baseline.get("std", 1.0))
                    else:
                        # Statistical fallback for rule firing trends
                        if len(rule_fire_counts) > 1:
                            rule_std = statistics.stdev(rule_fire_counts)
                            rule_slope_threshold = rule_std / len(rule_fire_counts) if len(rule_fire_counts) > 0 else 0.1
                        else:
                            rule_slope_threshold = 0.1
                    
                    if abs(slope) > rule_slope_threshold:
                        rule_trend_anomalies.append({
                            "rule_id": rule_id,
                            "rule_description": rule_description,
                            "total_fires": total_fires,
                            "trend_slope": round(slope, 4),
                            "trend_direction": "increasing" if slope > 0 else "decreasing",
                            "anomaly_score": min(100, abs(slope) * 300),
                            "anomaly_reason": f"{'Increasing' if slope > 0 else 'Decreasing'} rule firing trend",
                            "time_series": [{"period": i, "count": count} for i, count in enumerate(rule_fire_counts)],
                            "risk_level": "High" if abs(slope) > rule_slope_threshold * multiplier else "Medium"
                        })
                except (ValueError, statistics.StatisticsError, ZeroDivisionError):
                    continue  # Skip if regression fails
        
        # Analyze failed login trends
        failed_login_trends = []
        failed_login_time_points = []
        failed_login_counts = []
        
        for i, bucket in enumerate(failed_logins_agg.get("time_series", {}).get("buckets", [])):
            failed_login_time_points.append(i)
            failed_login_counts.append(bucket["doc_count"])
            
            failed_login_trends.append({
                "timestamp": bucket["key_as_string"],
                "failed_attempts": bucket["doc_count"]
            })
        
        # Calculate failed login trend statistics
        failed_login_anomaly = None
        if len(failed_login_time_points) >= 3 and sum(failed_login_counts) > 0:
            try:
                login_regression = statistics.linear_regression(failed_login_time_points, failed_login_counts)
                slope = login_regression.slope if login_regression else 0
                total_failures = sum(failed_login_counts)

                # Skip if slope is None
                if slope is None:
                    raise ValueError("Slope is None")
                
                # Use RCF-learned thresholds for failed login trend analysis
                if rcf_trend_baselines and rcf_trend_baselines.get("impact_progression_trend"):
                    impact_baseline = rcf_trend_baselines["impact_progression_trend"]
                    failed_login_threshold = impact_baseline.get("trend_threshold", impact_baseline.get("std", 1.0))
                    min_failures_threshold = max(3, int(rcf_trend_baselines.get("alert_volume_trend", {}).get("mean", 5) * 0.1))
                else:
                    # Statistical fallback for failed login trends
                    if len(failed_login_counts) > 1:
                        failed_login_std = statistics.stdev(failed_login_counts)
                        failed_login_threshold = failed_login_std / len(failed_login_counts) if len(failed_login_counts) > 0 else 0.05
                    else:
                        failed_login_threshold = 0.05
                    min_failures_threshold = 3
                
                if abs(slope) > failed_login_threshold and total_failures > min_failures_threshold:
                    failed_login_anomaly = {
                        "trend_slope": round(slope, 4),
                        "trend_direction": "increasing" if slope > 0 else "decreasing",
                        "total_failures": total_failures,
                        "anomaly_score": min(100, abs(slope) * 400),
                        "anomaly_reason": f"{'Increasing' if slope > 0 else 'Decreasing'} failed login trend",
                        "time_series": failed_login_trends,
                        "risk_level": "Critical" if slope > failed_login_threshold * multiplier else "High"
                    }
            except (ValueError, statistics.StatisticsError, ZeroDivisionError):
                pass  # Skip if regression fails
        
        # Sort anomalies by score
        host_trend_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        user_trend_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        rule_trend_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)

        # Extract RCF-detected anomalies from baselines
        rcf_detected_anomalies = rcf_trend_baselines.get("rcf_detected_anomalies", []) if rcf_trend_baselines else []

        # Build RCF-enhanced result
        result = {
            "total_alerts": total_alerts,
            "analysis_period": timeframe,
            "rcf_detector_info": {
                "index_name": TREND_DETECTOR_INDEX,
                "rcf_baselines_used": bool(rcf_trend_baselines),
                "baseline_period": baseline,
                "baseline_results_count": rcf_trend_baselines.get("results_count", 0) if rcf_trend_baselines else 0,
                "confidence_score": rcf_trend_baselines.get("confidence_scores", {}).get("mean", 0) if rcf_trend_baselines else 0,
                "rcf_anomalies_detected": len(rcf_detected_anomalies)
            },
            "rcf_detected_anomalies": rcf_detected_anomalies,  # Historical RCF anomalies
            "trend_settings": {
                "trend_type": trend_type,
                "sensitivity": sensitivity,
                "sensitivity_multiplier": multiplier if rcf_trend_baselines else "static_thresholds"
            },
            "overall_trends": overall_trends,
            "trend_time_series": trend_time_series,
            "rcf_trend_analysis": {
                "trend_anomalies": trend_anomalies[:limit],
                "escalation_patterns": [a for a in trend_anomalies if a.get("anomaly_type") == "escalation"],
                "directional_shifts": [a for a in trend_anomalies if a.get("anomaly_type") == "trend_shift"]
            },
            "rcf_baselines": rcf_trend_baselines if rcf_trend_baselines else {},
            "host_trend_anomalies": host_trend_anomalies[:limit],
            "user_trend_anomalies": user_trend_anomalies[:limit],
            "rule_trend_anomalies": rule_trend_anomalies[:limit],
            "failed_login_anomaly": failed_login_anomaly,
            "summary": {
                "total_trend_anomalies": len(trend_anomalies),
                "escalation_anomalies": len([a for a in trend_anomalies if a.get("anomaly_type") == "escalation"]),
                "directional_shift_anomalies": len([a for a in trend_anomalies if a.get("anomaly_type") == "trend_shift"]),
                "rcf_historical_anomalies": len(rcf_detected_anomalies),  # Count of RCF-detected anomalies
                "primary_trend_direction": overall_trends.get("primary_trend", "stable"),
                "highest_anomaly_score": max([a.get("anomaly_score", 0) for a in trend_anomalies if a.get("anomaly_score") is not None]) if trend_anomalies else 0,
                "highest_rcf_anomaly_grade": max([a.get("anomaly_grade", 0) for a in rcf_detected_anomalies if a.get("anomaly_grade") is not None]) if rcf_detected_anomalies else 0,
                "critical_trends": len([a for a in trend_anomalies if a.get("risk_level") == "Critical"]),
                "critical_rcf_anomalies": len([a for a in rcf_detected_anomalies if a.get("risk_level") == "Critical"]),
                "high_risk_trends": len([a for a in trend_anomalies if a.get("risk_level") == "High"]),
                "rcf_enhanced_detections": len([a for a in trend_anomalies if a.get("rcf_enhanced", False)]),
                "risk_assessment": "Critical" if any(a.get("risk_level") == "Critical" for a in trend_anomalies + rcf_detected_anomalies) else "High" if any(a.get("risk_level") == "High" for a in trend_anomalies + rcf_detected_anomalies) else "Medium" if trend_anomalies or rcf_detected_anomalies else "Low"
            }
        }
        
        logger.info("RCF-enhanced trend anomaly detection completed", 
                   total_alerts=total_alerts,
                   trend_anomalies=result["summary"]["total_trend_anomalies"],
                   escalation_patterns=result["summary"]["escalation_anomalies"],
                   directional_shifts=result["summary"]["directional_shift_anomalies"],
                   rcf_enhanced=result["summary"]["rcf_enhanced_detections"],
                   primary_trend=result["summary"]["primary_trend_direction"])
        
        return result

    except Exception as e:
        # Log complete stack trace for debugging
        error_trace = traceback.format_exc()
        logger.error("Trend anomaly detection failed",
                    error=str(e),
                    error_type=type(e).__name__,
                    traceback=error_trace)

        raise Exception(f"Failed to detect trend anomalies: {str(e)}")