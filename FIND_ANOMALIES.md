# Find Anomalies - User Guide

## Overview

The **Find Anomalies** functionality provides three specialized detection methods that work together to identify different types of security threats in your Wazuh SIEM environment. Each detection method uses OpenSearch's Random Cut Forest (RCF) clustering algorithm to establish intelligent baselines and detect anomalous behavior.

### Detection Methods Summary

| Detection Type | Best For | Time Scale | Example Threats |
|---------------|----------|------------|-----------------|
| **Threshold Detection** | Immediate bursts and spikes | Minutes to hours | Brute force attacks, worm propagation, DDoS attacks |
| **Trend Analysis** | Progressive escalation | Hours to weeks | Lateral movement, APT campaigns, data exfiltration |
| **Behavioral Baseline** | Entity behavior changes | Days to months | Compromised accounts, Living-off-the-Land (LotL), C2 communication, insider threats |

---

## 1. Threshold-Based Detection

### What It Detects

Threshold detection identifies **sudden bursts of anomalous activity** within short time periods by comparing real-time data against dynamic thresholds learned by RCF from historical baselines.

### Detection Capabilities

**File Location:** `functions/find_anomalies/detect_threshold.py`

**Key Anomalous Behaviors Detected:**
- **Brute Force Attacks**: Sudden spikes in failed login attempts
- **Worm Propagation**: Rapid malware spread across multiple hosts
- **Host Activity Spikes**: Unusual alert volume on specific hosts
- **User Activity Anomalies**: Abnormal user authentication patterns
- **High Severity Alert Bursts**: Sudden increases in critical alerts
- **Rule Firing Anomalies**: Specific security rules triggering excessively

**RCF Features Monitored:**
1. `total_alerts` - Overall alert volume
2. `severity_sum` - Cumulative severity of alerts
3. `host_diversity` - Number of unique hosts affected
4. `user_diversity` - Number of unique users involved
5. `high_severity_alerts` - Count of critical/high severity events

### Example Queries

```
"Detect sudden spikes in failed login attempts for the past 12 hours."
"Find authentication brute force attempts with exceeding user diversity anomalies in the last 2 hours using 3-day RCF baseline"
"Detect rapid malware spread with host diversity exceeding 20 affected systems and alert volume over 500 in the last 1 hour using 3-day RCF baseline"
"Find critical alert volume threshold breaches on hosts in the last 12 days using 3-day RCF learned baselines"
"Identify host diversity anomalies exceeding 10 affected hosts in the last 6 hours using 3-day RCF baseline.
```

### How It Works

1. Queries the threshold detector's anomaly results index
2. Retrieves RCF-learned baselines for the specified baseline time window (default: 17 days if not specified)
3. **Threshold Selection**:
   - **If RCF baselines are available**: RCF-learned dynamic thresholds are used and **override any user-provided threshold**
   - **If no RCF baseline data exists**: User-provided threshold from the query is used as a fallback (or default values if no threshold specified)
   - This ensures optimal accuracy by prioritizing machine-learned baselines over static thresholds
4. Compares current metrics against the selected thresholds (RCF-learned or fallback)
5. Identifies hosts, users, rules, and patterns exceeding thresholds
6. Scores anomalies based on deviation from baseline, with higher confidence scores for RCF-based detections

---

## 2. Trend Analysis Detection

### What It Detects

Trend detection identifies **escalating and progressive patterns** of anomalous cyber activity that build momentum over time, detecting directional shifts in security metrics.

### Detection Capabilities

**File Location:** `functions/find_anomalies/detect_trend.py`

**Key Anomalous Behaviors Detected:**
- **Lateral Movement**: Progressive spread across hosts
- **APT Campaigns**: Slow-burn advanced persistent threats
- **Insider Threat Escalation**: Gradual increase in suspicious user activity
- **Zero-Day Exploits**: New attack patterns gaining momentum
- **Data Exfiltration**: Increasing data transfer trends
- **Alert Volume Escalation**: Growing attack intensity over time

**RCF Features Monitored:**
1. `alert_volume_trend` - Alert count trends over time
2. `severity_escalation_trend` - Average severity trending upward
3. `attack_diversity_trend` - Variety of attack types increasing
4. `temporal_spread_trend` - Spread across hosts over time
5. `impact_progression_trend` - Cumulative impact growth

### Example Queries

```
"Show me escalating threat trends over the past week"
"Find data exfiltration trends with progressive impact escalation and alert volume increases in the last 5 days using 21-day RCF trend baseline with high sensitivity."
"Find increasing alert volume trends in the last 24 hours with high sensitivity using 7-day baseline"
"Detect lateral movement with progressive host spread trends and temporal escalation in the last 24 hours using 14-day RCF trend baseline with high sensitivity"
"Find insider threat escalation patterns with increasing user activity and severity progression in the last 7 days using 30-day RCF trend baseline"
```

### How It Works

1. Retrieves RCF-learned trend baselines from the trend detector index
2. Analyzes time-series data using 30-minute intervals
3. Calculates linear regression slopes for trend detection
4. Identifies escalation patterns and directional shifts
5. Compares current trends against learned baseline thresholds
6. Detects both increasing and decreasing trends

---

## 3. Behavioral Baseline Detection

### What It Detects

Behavioral detection identifies **long-term behavioral changes** in entity activities by comparing current behavior over extended periods against RCF-learned baselines.

### Detection Capabilities

**File Location:** `functions/find_anomalies/detect_behavioral.py`

**Key Anomalous Behaviors Detected:**
- **Compromised User Accounts**: Abnormal user activity patterns
- **Living-off-the-Land (LotL) Attacks**: Legitimate tools used maliciously
- **Command & Control (C2) Communication**: Unusual process execution
- **Insider Threats**: Abnormal access patterns and host diversity
- **Data Exfiltration**: Unusual file access patterns
- **Process Injection**: Abnormal process execution behavior
- **Authentication Anomalies**: Unusual authentication patterns

**RCF Features Monitored:**
1. `user_activity_patterns` - Unique user activity cardinality
2. `process_execution_patterns` - Unique process executions
3. `host_behavior_patterns` - Host activity diversity
4. `file_access_patterns` - File system access patterns
5. `authentication_behavior_patterns` - Authentication event patterns

### Example Queries

```
"Find coordinated activities involving user SYSTEM in the last 4 hours."
"Find living off the land attacks with unusual process execution patterns and host behaviour deviations in the last 5 days using 5-day RCF behavioural baseline."
"Detect compromised user account behaviour with abnormal user activity patterns and process execution deviations in the last 2 days using 7-day RCF behavioural baseline with high sensitivity"
"Detect insider threat behaviour with unusual user activity diversity and abnormal host access patterns in the last 21 days using 60-day RCF behavioural baseline with medium sensitivity"
```

### How It Works

1. Queries the behavioral detector's anomaly results index
2. Retrieves RCF-learned behavioral baselines
3. Analyzes entity-specific patterns using 1-hour intervals
4. Compares current behavior against learned thresholds
5. Identifies deviations in user, host, process, and file behaviors
6. Assigns risk scores based on behavioral deviation magnitude

---

## Using OpenSearch Anomaly Detection in Wazuh Dashboard

### Prerequisites

- Wazuh dashboard with OpenSearch backend
- OpenSearch Anomaly Detection plugin installed
- `wazuh-alerts-*` index pattern configured
- Sufficient historical data (recommended: 7+ days)

### Step 1: Access Anomaly Detection

1. Open your Wazuh dashboard
2. Navigate to the OpenSearch Dashboards menu
3. Select **OpenSearch Plugins** > **Anomaly Detection**

### Step 2: Create a Detector

You create the three types of detectors and the maximum number of RCF features allowed is 5:

#### A: Threshold Anomaly Detector

**Configuration:**
- **Detector Name**: `wazuh-threshold-anomaly-detector`
- **Data Source**: `wazuh-alerts-*`
- **Detector Interval**: 5 minutes
- **Window Delay**: 1 minute
- **Custom Result Index**: `opensearch-ad-plugin-result-alert-threshold`
- **Result Index TTL**: 60 days

**Features to Configure:**
1. **high_severity_alerts**
   ```json
   {
       "high_severity_count": {
           "value_count": {
               "field": "rule.level"
           }
       }
   }
   ```

2. **host_diversity**
   ```json
   {
       "host_count": {
           "cardinality": {
               "field": "agent.name"
           }
       }
   }
   ```

3. **severity_sum**
   ```json
   {
       "severity_total": {
           "sum": {
               "field": "rule.level"
           }
       }
   }
   ```

4. **total_alert**
   ```json
   {
       "alert_count": {
           "value_count": {
               "field": "rule.id"
           }
       }
   }
   ```

5. **user_diversity**
   ```json
   {
       "user_count": {
           "cardinality": {
               "field": "data.win.eventdata.targetUserName"
           }
       }
   }
   ```

#### B: Trend Anomaly Detector

**Configuration:**
- **Detector Name**: `wazuh-trend-anomaly-detector`
- **Data Source**: `wazuh-alerts-*`
- **Detector Interval**: 30 minutes
- **Window Delay**: 5 minutes
- **Custom Result Index**: `opensearch-ad-plugin-result-alert-trend`
- **Result Index TTL**: 365 days

**Features to Configure:**
1. **alert_volume_trend**
   ```json
   {
       "alert_count": {
           "value_count": {
               "field": "rule.id"
           }
       }
   }
   ```

2. **attack_diversity_trend**
   ```json
   {
       "unique_rules": {
           "cardinality": {
               "field": "rule.id"
           }
       }
   }
   ```

3. **impact_progression_trend**
   ```json
   {
       "severity_sum": {
           "sum": {
               "field": "rule.level"
           }
       }
   }
   ```

4. **severity_escalation_trend**
   ```json
   {
       "avg_severity": {
           "avg": {
               "field": "rule.level"
           }
       }
   }
   ```

5. **temporal_spread_trend**
   ```json
   {
       "host_spread": {
           "cardinality": {
               "field": "agent.name"
           }
       }
   }
   ```

#### C: Behavioral Anomaly Detector

**Configuration:**
- **Detector Name**: `wazuh-behavioral-anomaly-detector`
- **Data Source**: `wazuh-alerts-*`
- **Detector Interval**: 60 minutes (1 hour)
- **Window Delay**: 10 minutes
- **Custom Result Index**: `opensearch-ad-plugin-result-alert-behaviour`
- **Result Index TTL**: 365 days

**Features to Configure:**
1. **file_access_patterns**
   ```json
   {
       "file_access_patterns": {
           "value_count": {
               "field": "syscheck.path"
           }
       }
   }
   ```

2. **host_behaviour_patterns**
   ```json
   {
       "host_behaviour_patterns": {
           "cardinality": {
               "field": "agent.name"
           }
       }
   }
   ```

3. **authentication_behaviour_patterns**
   ```json
   {
       "auth_event_count": {
           "value_count": {
               "field": "rule.id"
           }
       }
   }
   ```

4. **process_execution_patterns**
   ```json
   {
       "process_execution_patterns": {
           "cardinality": {
               "field": "data.win.eventdata.image"
           }
       }
   }
   ```

5. **user_activity_patterns**
   ```json
   {
       "user_activity_patterns": {
           "cardinality": {
               "field": "data.win.eventdata.targetUserName"
           }
       }
   }
   ```

### Step 3: Configure Detector Settings

For each detector:

1. **Set Detection Interval**: Choose appropriate interval based on detector type
   - Threshold: 5 minutes (rapid detection)
   - Trend: 30 minutes (temporal analysis)
   - Behavioral: 60 minutes (long-term patterns)

2. **Configure Window Delay**: Allow time for data ingestion
   - Threshold: 1 minute
   - Trend: 5 minutes
   - Behavioral: 10 minutes

3. **Set Custom Result Index**: Configure result storage
   - Use the index names specified in each configuration
   - Set appropriate TTL based on retention needs

4. **Add RCF Features**: Add all 5 features for each detector
   - Copy the JSON aggregations exactly as shown
   - Ensure field names match your Wazuh index mappings

### Step 4: Start the Detector

1. Review your detector configuration
2. Click **Create detector** or **Update detector**
3. Navigate to the detector's detail page
4. Click **Start detector** to begin anomaly detection
5. Wait for the learning period (typically 7-10 days for optimal baselines)

### Step 5: Monitor Results

1. **View Anomalies**: Check the detector's **Anomaly results** tab
2. **Review Confidence**: Monitor confidence scores (higher = more reliable)
3. **Analyze Features**: Examine which features contribute to anomalies
4. **Set Alerts**: Configure notifications for high-grade anomalies

---

## Environment Variables Configuration

Ensure these environment variables are set for proper integration:

```bash
# Threshold Detector
THRESHOLD_DETECTOR_INDEX=opensearch-ad-plugin-result-alert-threshold

# Trend Detector
TREND_DETECTOR_INDEX=opensearch-ad-plugin-result-alert-trend

# Behavioral Detector
BEHAVIOUR_DETECTOR_INDEX=opensearch-ad-plugin-result-alert-behaviour

# OpenSearch Connection
OPENSEARCH_HOST=localhost
OPENSEARCH_PORT=9200
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=admin
OPENSEARCH_USE_SSL=false
OPENSEARCH_VERIFY_CERTS=false
```

---

## Best Practices

### Baseline Learning Period
- Allow detectors to run for at least 7-14 days before relying on results
- Longer baseline periods (14+ days) provide better behavioral context
- Update baselines regularly in dynamic environments

### Sensitivity Tuning
- **Low Sensitivity**: Fewer false positives, may miss subtle threats
- **Medium Sensitivity**: Balanced detection (recommended default)
- **High Sensitivity**: More comprehensive, higher false positive rate

### Query Optimization
- Specify appropriate timeframes based on detection type:
  - Threshold: Minutes to hours (e.g., "last 2 hours")
  - Trend: Hours to days (e.g., "last 24 hours")
  - Behavioral: Days to weeks (e.g., "last 7 days")

### Baseline Period Selection
- Threshold: 3-7 days baseline
- Trend: 7-10 days baseline
- Behavioral: 7-10 days baseline

---

## Troubleshooting

### No Anomalies Detected
- Verify that detectors are running and have completed initial learning period
- Check that historical data exists in the result indices
- Ensure environment variables point to correct indices
- Review detector confidence scores (low confidence = insufficient data)

### High False Positive Rate
- Reduce sensitivity setting
- Increase baseline period for better learning
- Review detector features and adjust aggregations
- Filter out known benign patterns in data source queries

### Missing RCF Baselines
- Verify custom result indices are created and accessible
- Check detector status and error logs
- Ensure sufficient data volume for statistical analysis
- Confirm detector interval matches expected data frequency

---

## Additional Resources

- **Detection Functions**: `functions/find_anomalies/`
  - `detect_threshold.py` - Threshold detection logic
  - `detect_trend.py` - Trend analysis logic
  - `detect_behavioral.py` - Behavioral baseline logic

- **README Reference**: Lines 161-187 for query examples and descriptions
