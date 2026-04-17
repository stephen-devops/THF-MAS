"""
Pydantic schemas for Wazuh function parameters
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any, Union
from enum import Enum


class AlertAction(str, Enum):
    """Actions for alert analysis"""
    RANKING = "ranking"
    FILTERING = "filtering" 
    COUNTING = "counting"
    DISTRIBUTION = "distribution"


class EntityType(str, Enum):
    """Types of entities to investigate"""
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    FILE = "file"
    IP = "ip"


class QueryType(str, Enum):
    """Types of entity queries"""
    ALERTS = "alerts"
    DETAILS = "details"
    ACTIVITY = "activity"
    STATUS = "status"


class ThreatType(str, Enum):
    """Types of threat detection"""
    TECHNIQUE = "technique"
    TACTIC = "tactic"
    THREAT_ACTOR = "threat_actor"
    INDICATORS = "indicators"
    CHAINS = "chains"


class AnomalyType(str, Enum):
    """Types of anomaly detection"""
    THRESHOLD = "threshold"
    BEHAVIORAL = "behavioral"
    TREND = "trend"


class ViewType(str, Enum):
    """Types of timeline views"""
    SEQUENCE = "sequence"
    PROGRESSION = "progression"
    TEMPORAL = "temporal"


class RelationshipType(str, Enum):
    """Types of relationship mapping"""
    ENTITY_TO_ENTITY = "entity_to_entity"
    BEHAVIORAL_CORRELATION = "behavioral_correlation"


class VulnerabilityAction(str, Enum):
    """Types of vulnerability checking actions"""
    LIST_BY_ENTITY = "list_by_entity"
    CHECK_CVE = "check_cve"
    CHECK_PATCHES = "check_patches"


class AgentMonitorAction(str, Enum):
    """Types of agent monitoring actions"""
    STATUS_CHECK = "status_check"
    VERSION_CHECK = "version_check"
    HEALTH_CHECK = "health_check"


class AnalyzeAlertsSchema(BaseModel):
    """Schema for analyze_alerts function"""
    action: AlertAction = Field(description="Type of analysis to perform")
    group_by: Optional[Union[str, List[str]]] = Field(default=None, description="Field(s) to group results by. Single dimension: 'severity', 'host', 'rule', 'time', 'user', 'process'. Multi-dimensional: ['severity', 'host'] or 'severity,host' for cross-correlations. TEMPORAL ANALYSIS: Use 'time', 'hourly', 'periods', 'histogram' for histogram-style bucket outputs with time-series data. Supports both list format ['severity', 'time'] and comma-separated string 'severity,time'. Temporal keywords automatically detected: 'today', 'hours', 'hourly', 'periods', 'histogram', 'timeline'.")
    filters: Optional[Dict[str, Any]] = Field(default=None, description="Filters to apply")
    limit: Optional[int] = Field(default=10, description="Maximum number of results")
    time_range: Optional[str] = Field(default="7d", description="Time range for analysis")


class InvestigateEntitySchema(BaseModel):
    """Schema for investigate_entity function"""
    entity_type: EntityType = Field(description="Type of entity to investigate")
    entity_id: str = Field(description="ID or name of the entity")
    query_type: QueryType = Field(description="Type of information to retrieve")
    time_range: Optional[str] = Field(default="24h", description="Time range for investigation")


class MapRelationshipsSchema(BaseModel):
    """Schema for map_relationships function"""
    model_config = ConfigDict(extra='allow', validate_default=True)

    source_type: EntityType = Field(description="Type of source entity")
    source_id: Optional[str] = Field(default=None, description="Identifier of specific source entity. For PROCESS: use full path (e.g., 'C:\\Windows\\System32\\cmd.exe') or executable name (e.g., 'cmd.exe'). For HOST: use hostname (e.g., 'U209-PC-BLEE'). For USER: use username (e.g., 'SYSTEM'). For FILE: use file path. Omit to query ALL entities of source_type.")
    target_type: Optional[EntityType] = Field(default=None, description="Type of target entity to find relationships TO. Omit or set to None for 'all relationships' queries to return connections to ALL entity types (host, user, process, file).")
    relationship_type: RelationshipType = Field(default=RelationshipType.ENTITY_TO_ENTITY, description="Type of relationship to explore: 'entity_to_entity' (map direct entity connections with connection strength, frequency counts, latest connection details, and relationship risk scoring - use for queries about 'what/who is connected to X', 'connection strength', 'latest connections', 'direct relationships', or 'connection counts'), 'behavioral_correlation' (analyze behavioral patterns, access sequences, authentication flows, temporal clustering, and coordinated activities - use for queries about 'behavior analysis', 'access patterns', 'suspicious activity', 'coordinated actions', 'authentication patterns', or 'temporal correlations')")
    host: Optional[str] = Field(default=None, description="Filter by specific host name (e.g., 'U209-PC-BLEE') to constrain relationships to events on that host")
    user: Optional[str] = Field(default=None, description="Filter by specific user name (e.g., 'admin') to constrain relationships to events by that user")
    timeframe: Optional[str] = Field(default="24h", description="Time frame for relationship mapping")


class DetectThreatsSchema(BaseModel):
    """Schema for detect_threats function"""
    threat_type: ThreatType = Field(description="Type of threat to detect")
    technique_id: Optional[str] = Field(default=None, description="MITRE ATT&CK technique ID")
    tactic_name: Optional[str] = Field(default=None, description="MITRE ATT&CK tactic name")
    actor_name: Optional[str] = Field(default=None, description="Threat actor name")
    timeframe: Optional[str] = Field(default="7d", description="Time frame for threat detection")


class FindAnomaliesSchema(BaseModel):
    """Schema for find_anomalies function"""
    anomaly_type: AnomalyType = Field(description="Type of anomaly detection - ALL three types support RCF baselines. KEYWORD PRECEDENCE: 'threshold' = queries with numeric limits ('threshold', 'violations', 'breaches', 'exceeding', 'over X alerts', 'above X') - ALWAYS use threshold even if query mentions 'RCF baseline'. 'behavioral' = entity behavior patterns without numeric limits. 'trend' = time-series pattern analysis, escalations, directional shifts.")
    metric: Optional[str] = Field(default=None, description="Specific metric to analyze (e.g., 'alert_count', 'severity')")
    timeframe: Optional[str] = Field(default="24h", description="Time frame for anomaly detection (e.g., '24h', '7d')")
    threshold: Optional[float] = Field(default=None, description="Threshold value for anomaly detection (REQUIRED only for 'threshold' type). All three anomaly types (threshold, behavioral, trend) can use RCF baselines for enhanced accuracy.")
    baseline: Optional[str] = Field(default=None, description="Baseline period for comparison (e.g., '7d', '30d')")


class TraceTimelineSchema(BaseModel):
    """Schema for trace_timeline function"""
    start_time: Optional[str] = Field(default=None, description="Start time for timeline (optional, defaults to 7 days ago for progression analysis)")
    end_time: Optional[str] = Field(default=None, description="End time for timeline (optional, defaults to now for progression analysis)")
    entity: Optional[str] = Field(default=None, description="Entity to focus timeline on")
    view_type: ViewType = Field(default=ViewType.PROGRESSION, description="Type of timeline view: 'sequence', 'progression', or 'temporal'")
    event_types: Optional[List[str]] = Field(default=None, description="Keywords describing event types to include (e.g., 'logon', 'process', 'file', 'network', 'malware') - these are mapped to actual rule groups dynamically")


class CheckVulnerabilitiesSchema(BaseModel):
    """Schema for check_vulnerabilities function"""
    action: VulnerabilityAction = Field(description="Type of vulnerability check to perform: 'list_by_entity', 'check_cve', or 'check_patches'")
    entity_filter: Optional[str] = Field(default=None, description="Filter by entity name or pattern")
    cve_id: Optional[str] = Field(default=None, description="Specific CVE ID to check (for check_cve action)")
    severity: Optional[str] = Field(default=None, description="Vulnerability severity level (low, medium, high, critical)")
    patch_status: Optional[str] = Field(default=None, description="Patch status filter (installed, missing, failed)")
    timeframe: Optional[str] = Field(default="30d", description="Time frame for vulnerability analysis (e.g., '30d', '7d')")


class MonitorAgentsSchema(BaseModel):
    """Schema for monitor_agents function"""
    action: AgentMonitorAction = Field(description="Type of agent monitoring to perform: 'status_check', 'version_check', or 'health_check'")
    agent_id: Optional[str] = Field(default=None, description="Specific agent ID, name, or IP address")
    status_filter: Optional[str] = Field(default=None, description="Filter by agent status (active, inactive, disconnected)")
    version_requirements: Optional[str] = Field(default=None, description="Version requirements (e.g., '>=4.5.0')")
    timeframe: Optional[str] = Field(default="24h", description="Time frame for analysis (e.g., '24h', '7d')")
    health_threshold: Optional[float] = Field(default=70.0, description="Health score threshold for health_check action")
