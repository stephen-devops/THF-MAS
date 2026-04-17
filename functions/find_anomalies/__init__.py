"""
RCF-Enhanced Anomaly Detection Functions for Wazuh SIEM Data

This module provides three RCF-enhanced anomaly detection sub-actions:
- Threshold Detection: 5-minute intervals for immediate threat response
- Trend Detection: 30-minute intervals for pattern evolution and campaign analysis  
- Behavioral Detection: 4-hour intervals for long-term behavioral drift analysis

All detectors use Random Cut Forest (RCF) learned baselines from OpenSearch Anomaly Detection plugin
instead of static thresholds for sophisticated, adaptive threat detection.
"""

from .detect_threshold import execute as execute_threshold
from .detect_behavioral import execute as execute_behavioral
from .detect_trend import execute as execute_trend

__all__ = [
    "execute_threshold",
    "execute_behavioral", 
    "execute_trend"
]