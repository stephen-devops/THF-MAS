# THF (Threat Hunting Framework)

An AI-powered natural language interface for Wazuh SIEM using LangChain and Anthropic Claude.

---

# 📖 User Guide

## Overview

THF (Threat Hunting Framework) is a sophisticated AI-powered security analysis platform that provides a conversational interface to Wazuh SIEM data. The system leverages Claude AI (Anthropic's Claude Sonnet 4) through LangChain to enable security analysts to investigate security incidents, analyze alerts, and understand their security posture using natural language queries.

The framework converts user queries into structured function calls, executes them against the Wazuh OpenSearch backend and Wazuh API, and returns actionable security insights with full context preservation across multi-turn conversations.

## Installation Instructions & Setup

### Prerequisites

- Python 3.9+
- Anthropic API key
- Access to Wazuh OpenSearch cluster
- Redis (optional, for caching)

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/resilmesh2/THF.git
   cd THF/
   ```

2. Install required dependencies
   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment variables
   ```bash
   cp .env.example .env
   ```

## Environment Variables

### Edit .env and configure your API keys

The following environment variables must be configured in your `.env` file:

**Anthropic Configuration:**
- `ANTHROPIC_API_KEY` - Your Anthropic API key for Claude AI access

**OpenSearch Configuration:**
- `OPENSEARCH_HOST` - Your OpenSearch host address
- `OPENSEARCH_PORT` - OpenSearch port (default: 9200)
- `OPENSEARCH_USER` - OpenSearch username (default: admin)
- `OPENSEARCH_PASSWORD` - OpenSearch password
- `OPENSEARCH_USE_SSL` - Enable SSL for OpenSearch connection (true/false)

**Wazuh API Configuration:**
- `WAZUH_API_HOST` - Wazuh API host address (default: localhost)
- `WAZUH_API_PORT` - Wazuh API port (default: 55000)
- `WAZUH_API_USERNAME` - Wazuh API username
- `WAZUH_API_PASSWORD` - Wazuh API password
- `WAZUH_API_USE_SSL` - Enable SSL for Wazuh API (true/false)
- `WAZUH_API_VERIFY_CERTS` - Verify SSL certificates (true/false)

**Redis Configuration (optional):**
- `REDIS_HOST` - Redis host address (default: localhost)
- `REDIS_PORT` - Redis port (default: 6379)
- `REDIS_PASSWORD` - Redis password (leave empty if not required)

**Application Configuration:**
- `LOG_LEVEL` - Logging level (INFO, DEBUG, WARNING, ERROR)
- `API_HOST` - FastAPI host binding (default: 0.0.0.0)
- `API_PORT` - FastAPI port (default: 8000 for Docker, 8000 for local)

**Note on Ports:**
- **Docker**: Container runs on port 8000, mapped to host port 8030 (access via `http://localhost:8030`)
- **Local**: Application runs directly on port 8000 (access via `http://localhost:8000`)

## Running the Application

Once dependencies are installed, you need to start the FastAPI backend and the Streamlit frontend UI.

1. First, start the FastAPI backend server:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```

2. Then in a new terminal, start the Streamlit UI:
   ```bash
   streamlit run ./streamlit_ui.py
   ```

The backend will be available at `http://localhost:8000` and the UI at `http://localhost:8501` by default.

**Note:** When using Docker, the backend is accessed via `http://localhost:8030` due to port mapping (`8030:8000` in docker-compose.yml).

3. Access the Streamlit UI and start threat hunting:
   - Open your browser and navigate to `http://localhost:8501`
   - Enter a natural language security query in the text input field
   - Press Enter or click outside the input field to submit

   Example threat hunting queries to try:
   ```
   Show me the top 10 hosts with most alerts the past two days
   What alerts are there for user SYSTEM?
   Find hosts with more than 20 failed login attempts
   Which agents are disconnected?
   Which users accessed host win10-01 in the last 24 hours?
   Find T1055 process injection techniques detected in the last 12 hours.
   Check for Log4Shell vulnerabilities on our Windows hosts.
   ```

## Features

### 8 Core Security Capabilities

1. **analyze_alerts** - Alert analysis with ranking, filtering, counting, distribution
2. **investigate_entity** - Entity investigation (host, user, process, file)
3. **detect_threats** - MITRE ATT&CK techniques, tactics, threat actors
4. **map_relationships** - Entity relationships, activity correlation
5. **find_anomalies** - Threshold, behavioral, trend detection
6. **trace_timeline** - Chronological event reconstruction
7. **check_vulnerabilities** - CVE checking and vulnerability assessment
8. **monitor_agents** - Agent status, health, and connectivity monitoring


### Detailed Security Intent and Sub-Action Decomposition

#### 1. Analyze Alerts

| Sub-Action | Description |
|------------|-------------|
| **Counting** | Returns quantitative alert volume analysis with statistical breakdowns by severity, rules, agents, and temporal patterns. |
| **Filtering** | Retrieves specific alert documents matching filter criteria with contextual summaries for investigation. |
| **Distribution** | Performs comprehensive single or multi-dimensional alert pattern analysis across security dimensions (agents, users, processes, rules, level severity, temporal criteria, rule groups, geography) with cross-correlations, percentage breakdowns, and temporal patterns for threat analysis. |
| **Ranking/Stacking** | Rank or stack entities by alert frequency (e.g. top alerting hosts, users, rules, most severe alerts, etc). |

**Example Queries:**

**Counting:**
- "Count all critical alerts from the last 24 hours"
- "Count alerts by user and integrity level for today"
- "Count high severity alerts with MITRE technique breakdown for the past 2 days"

**Filtering:**
- "Filter the dataset for alerts with severity level 15"
- "Find alerts with process name 'powershell.exe'"
- "Filter all critical alerts with rule group 'sysmon' in the past 12 hours"

**Distribution:**
- "Show me alert distribution by rule group this week"
- "Show me a distribution of alerts by severity levels and hourly time periods over the past three days"
- "Give me alert correlations between users, hosts, and severity levels"

**Ranking/Stacking:**
- "Rank hosts by alert frequency"
- "What are the most frequently triggered security rules on host U209-PC-BLEE in the last 24 hours?"
- "Show me the most active host in terms of security alerts over the past 6 hours"

#### 2. Find Anomalies

| Sub-Action | Description |
|------------|-------------|
| **Behavioral Baseline** | Detect long-term behavioral activity in entity activities by comparing current behavior over an extended period of days against RCF learned baselines. |
| **Threshold-Based Detection** | Detect sudden bursts of immense anomalous activity within a short period of time by comparing real-time data against dynamic metric thresholds (alert counts, host activity, user activity, alert severity) established by RCF-learned baselines. Anomalous activity detected includes Brute Force activity or a Worm propagation. |
| **Trend Analysis** | Detect escalating and progressive trends of anomalous cyber activity which are escalating and build momentum over long periods of time, including insider threat escalation detection or zero-day exploits. |

**Example Queries:**

**Threshold-Based Detection:**
- "Detect sudden spikes in failed login attempts for the past 12 hours."
- "Find authentication brute force attempts with exceeding user diversity anomalies in the last 2 hours using 3-day RCF baseline"
- "Detect rapid malware spread with host diversity exceeding 20 affected systems and alert volume over 500 in the last 1 hour using 3-day RCF baseline"
- "Find critical alert volume threshold breaches on hosts in the last 12 days using 3-day RCF learned baselines"

**Behavioral Baseline:**
- "Find coordinated activities involving user SYSTEM in the last 4 hours."
- "Detect compromised user account behaviour with abnormal user activity patterns and process execution deviations in the last 2 days using 7-day RCF behavioural baseline with high sensitivity"
- "Detect insider threat behaviour with unusual user activity diversity and abnormal host access patterns in the last 21 days using 60-day RCF behavioural baseline with medium sensitivity"

**Trend Analysis:**
- "Show me escalating threat trends over the past week"
- "Find increasing alert volume trends in the last 24 hours with high sensitivity using 7-day baseline"
- "Detect lateral movement with progressive host spread trends and temporal escalation in the last 24 hours using 14-day RCF trend baseline with high sensitivity"
- "Find insider threat escalation patterns with increasing user activity and severity progression in the last 7 days using 30-day RCF trend baseline"

#### 3. Investigate Entity

| Sub-Action | Description |
|------------|-------------|
| **Alert Retrieval** | Retrieve and analyze the alerts for a specified entity (a user account, host, file, process). This provides a statistical breakdown of alerts over a chronological timeline of alert distribution and most recently triggered alerts. |
| **Detailed Information** | Provides comprehensive details, a complete profile concerning an entity including total alerts, detailed MITRE ATT&CK associations, risk scoring and alert severity breakdowns. |
| **Activity Analysis** | Perform behavior analysis on an entity to identify behavioral patterns, including alert activity bursts, peak usage time windows, process execution and user interaction to provide insights into normal behavior for the specified entity. |
| **Status Monitoring** | Provides operational and performance analysis of an entity, including recent security alerts, agent connectivity status, service states, and the entity's overall health scoring. |

**Example Queries:**

**Alert Retrieval:**
- "Show me all alerts for host win10-01."
- "Give all alerts from host 012 for the last 6 hours."
- "What alerts have been triggered by user SYSTEM this week?"

**Detailed Information:**
- "Get detailed information about user administrator"
- "Show me detailed information for host U209-PC-BLEE for today"
- "Get full detail information for host 192.168.201.33 including risk score"

**Activity Analysis:**
- "Analyze activity patterns for process powershell.exe"
- "Analyze activity patterns for host win10-02 over the last three days"
- "Track activity patterns for host Win10-01 over the past four days"

**Status Monitoring:**
- "Show a status report on the host U209-PC-BLEE"
- "What's the current security status of host MAIL-SERVER?"
- "Give a status report on host with the IP address 192.168.201.33"

#### 4. Map Relationships

| Sub-Action | Description                                                                                                                                                                                                                                                                                                                                                        |
|------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Entity to Entity** | Map direct relationships between specified entities (hosts, users, processes, files) by finding shared events, or direct interactions in the security data. Identifies which entities interact with each other and assesses the strength of relationship, type and risk scoring based on alert severity for security investigation and lateral movement detection. |
| **Behavioral Correlation** | Identify correlated behavioral patterns or activities across multiple entities that occur in similar timeframes, suggesting coordinated actions, attack chains, or systematic behaviors.                                                                                                                                                                           |

**Example Queries:**

**Entity to Entity:**
- "Show me which hosts user SYSTEM accessed today."
- "Which users have accessed host with IP 192.168.201.33 in the past 24 hours?"
- "Show me all files that were loaded by the svchost.exe process over the past 6 hours"
- "What files were deleted by process TiWorker.exe on May 15 2025?"
- "Show me a process injecting into another process on Aug 13 2025"

**Behavioral Correlation:**
- "Analyse correlated activities between host win10-01 and other entities in the last 6 hours"
- "Find coordinated activities involving user SYSTEM in the last 4 hours"
- "Detect unusual access sequences from host with IP 192.168.201.33 for the past hour"

#### 5. Trace Timeline

| Sub-Action | Description |
|------------|-------------|
| **Show Sequence** | Produces a chronological timeline of security events in the order they occurred, like the sequence of actions on a host, by a user, or involving a specific process. |
| **Attack Progression** | Tracks how an attack evolved and progressed over time, identifying attack chains. Focuses on critical events and shows how attackers moved from initial compromise to later stages. |
| **Temporal Correlation** | Finds events that occurred close together in time (within a specified time window), helping identify related activities that might be part of the same attack or incident. |

**Example Queries:**

**Show Sequence:**
- "Show me the event sequence for host server-01 from 2pm to 4pm."
- "Display the sequence of events yesterday between 06:00:00 and 12:00:00"
- "Show a sequential timeline of all critical alerts over the past 12 hours"
- "Show me any detailed sequence of authentication events on agent 012 over the past 2 days"

**Attack Progression:**
- "Show a timeline of events preceding a T1059.003 alert over the past hour"
- "Trace how the attack developed on win10-01 from initial access at 09:47:45 UTC"
- "Show attack evolution for host with IP address 192.168.201.33 over past two hours"

**Temporal Correlation:**
- "Show me any temporal correlations between events for host win10-01 in the last four hours"
- "Identify coordinated activity patterns across multiple entities within 10-minute windows"
- "Show temporally correlated events for user SYSTEM for the past three days"


## Using THF for Threat Hunting

### Getting Started

1. **Ask Initial Questions**: Start with broad queries to understand your security posture
   - "Show me an alert breakdown for U209-PC-BLEE over the past 12 hours."
   - "Show me critical alerts from today"
   - "Which agents are disconnected?"
   - "What are the top 10 hosts with most alerts?"

2. **Follow-Up Questions**: THF remembers context from previous queries
   - After seeing alerts: "Give me more details on those critical alerts from this time frame."
   - After seeing a host: "What about authentication failures on that host?"
   - After investigating: "Show me a timeline for those events"

3. **Investigate Entities**: Deep-dive into specific hosts, users, processes, or files
   - "What alerts are there for host win10-01?"
   - "Show me all activity for user administrator in the last 24 hours"
   - "What files did powershell.exe create today?"

4. **Detect Threats**: Look for MITRE ATT&CK techniques and suspicious patterns
   - "Find T1055 process injection techniques detected recently"
   - "Show me unusual login patterns from yesterday"
   - "Are there any credential dumping attempts?"

5. **Map Relationships**: Understand connections between entities
   - "Which users accessed host win10-01 today?"
   - "What processes did cmd.exe create?"
   - "Show me files accessed by suspicious processes"

### Session Management

- Each conversation maintains context across multiple queries
- Use the "Reset Session" button in the sidebar to start a new investigation
- View session information to see conversation history

```bash
# Reset session memory
POST /reset?session_id=your-session-id

# Get session information
GET /session/{session_id}

# List all active sessions
GET /sessions
```

### Health & System Info
```bash
# Health check

```bash
curl http://localhost:8000/health
# Or if using Docker: curl http://localhost:8030/health
```

## Roadmap

### Completed Features ✓
- [x] Natural language interface with Claude Sonnet 4
- [x] Session-based conversation memory
- [x] Context preservation across queries
- [x] 8 core security analysis intents with 30+ sub-actions
- [x] Streamlit web interface
- [x] FastAPI REST API
- [x] OpenSearch and Wazuh API integration
- [x] Smart routing and field detection
- [x] Natural language time parsing
- [x] MITRE ATT&CK threat detection
- [x] Entity relationship mapping
- [x] Anomaly detection with RCF baselines
- [x] Comprehensive logging and tracing

### Planned Features
- [ ] Accelerated Threat Hunting Response using local model to replace Claude Sonnet 4.5
- [ ] Support for custom Wazuh rules and decoders
- [ ] Integration with external threat intelligence feeds
- [ ] Multi-tenant support with role-based access control
- [ ] Advanced visualization capabilities and dashboards
- [ ] Query result caching with Redis
- [ ] Automated report generation
- [ ] Scheduled threat hunting queries
- [ ] Integration with ticketing systems (Jira, ServiceNow)
- [ ] Mobile app interface

---

# 🔧 Technical Documentation

## Application Architecture

```
User Query → Context Processor → LangChain Agent → Tool Selection → Function Execution → OpenSearch/Wazuh API → Response Generation → User
     ↓                                                    ↓
Session Memory                                   Function Dispatcher
```

### Core Components

#### 1. WazuhSecurityAgent (`agent/wazuh_agent.py`)
The central orchestrator that manages the entire query processing lifecycle:

- **LLM Model**: Claude Sonnet 4
- **Agent Type**: STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION
- **Session Management**: Unique session IDs for isolated conversation contexts
- **Memory System**: ConversationSummaryBufferMemory (1500 token limit per session)
- **Max Iterations**: 3 with early stopping to optimize API usage
- **Timeout**: 30 seconds per API call with exponential backoff retry logic
- **Key Features**:
  - Session-based conversation memory prevents context bleed between users
  - Automatic retry on API overload (529 errors) with 2s, 4s backoff
  - Context preservation across multi-turn conversations
  - Real-time agent state management

#### 2. ConversationContextProcessor (`agent/context_processor.py`)
Intelligent context analysis and preservation system:

- **Context Detection**: Identifies contextual references ("these alerts", "that host", "this process")
- **Entity Extraction**: Extracts hosts, users, processes, files, IPs from conversation history
- **Temporal Context**: Preserves time ranges across queries
- **Query Enrichment**: Automatically applies previous filters to follow-up queries
- **Detection Strategies**:
  - Explicit keyword matching
  - Numerical reference tracking
  - Definite article patterns
  - Entity reference extraction

#### 3. Security Function Modules (`functions/`)
8 specialized modules with 30+ sub-actions for comprehensive security analysis:

- **analyze_alerts**: Alert ranking, filtering, counting, distribution analysis
- **investigate_entity**: Deep-dive investigation (host, user, process, file, IP)
- **detect_threats**: MITRE ATT&CK techniques, tactics, threat actors, IoCs
- **map_relationships**: Entity relationship mapping with behavioral correlation
- **find_anomalies**: Threshold, behavioral, trend detection with RCF baselines
- **trace_timeline**: Chronological event reconstruction and attack progression
- **check_vulnerabilities**: CVE checking, patch status, vulnerability assessment
- **monitor_agents**: Agent status, health, connectivity monitoring

#### 4. Data Integration Layer (`functions/_shared/`)

**WazuhOpenSearchClient**:
- Async OpenSearch connectivity with SSL support
- Intelligent field mapping (auto-detects agent.id vs agent.name)
- Smart query building with wildcard and term queries
- Natural language time range parsing ("3 days ago", "yesterday 6am-11am")
- Wazuh array field normalization

**WazuhAPIClient**:
- JWT authentication with token caching
- Agent status monitoring (active, disconnected, never_connected)
- Agent search and summary statistics
- Comprehensive agent information retrieval

#### 5. Web Interface

**FastAPI Backend** (`main.py`):
- Async REST API with WebSocket support
- Session management endpoints
- Health checks and monitoring
- CORS configuration for production

**Streamlit UI** (`streamlit_ui.py`):
- Real-time conversation interface
- Session management (create, reset, view info)
- Example query suggestions
- API health status indicator
- Conversation history with timestamps

#### 6. Type Safety & Validation (`schemas/`)
- Pydantic schemas for all function parameters
- Enum-based action/type selection
- Automatic JSON serialization
- Request/response validation


## Advanced Usage

### REST API

Query the assistant:
```bash
curl -X POST "http://localhost:8000/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "Show me critical alerts from the last hour"}'
```

### Query Endpoint
```bash
POST /query
Content-Type: application/json

{
  "query": "Show me critical alerts from the last hour",
  "session_id": "optional-session-id"
}
```

## Development

### Project Structure

```
THF/
├── agent/                         # Core LLM agent implementation
│   ├── wazuh_agent.py             # Main LangChain agent orchestrator
│   ├── context_processor.py       # Conversation context analysis
│   └── __init__.py
├── functions/                      # Security analysis function modules
│   ├── analyze_alerts/            # Alert ranking, filtering, counting, distribution
│   ├── investigate_entity/        # Host, user, process, file investigation
│   ├── map_relationships/         # Entity relationship mapping and correlation
│   ├── detect_threats/            # MITRE ATT&CK detection, threat actors, IoCs
│   ├── find_anomalies/            # Threshold, behavioral, trend anomaly detection
│   ├── trace_timeline/            # Event timeline reconstruction
│   ├── check_vulnerabilities/     # CVE checking, vulnerability assessment
│   ├── monitor_agents/            # Agent status, health, version monitoring
│   ├── smart_routing/             # Intelligent query routing
│   └── _shared/                   # Shared utilities
│       ├── opensearch_client.py   # OpenSearch integration
│       ├── wazuh_api_client.py    # Wazuh API integration
│       ├── time_parser.py         # Natural language time parsing
│       └── utils.py               # Common utilities
├── tools/                         # LangChain tool wrappers
├── schemas/                       # Pydantic validation schemas
├── assets/                        # Static assets (logos, images)
├── tests/                         # Test suite
├── docs/                          # Documentation
├── main.py                        # FastAPI backend server
├── streamlit_ui.py                # Streamlit web UI
├── demo_server.py                 # Demo/testing server
├── start_ui.py                    # UI launcher script
├── requirements.txt               # Python dependencies
├── README.md                      # This file
└── .env                           # Environment configuration
```

### Key Architectural Features

#### Session-Based Memory Management
- **Isolated Contexts**: Each user session maintains separate conversation memory
- **Prevents Memory Bleed**: Concurrent users don't interfere with each other
- **Context-Aware Follow-ups**: System remembers entities, filters, and time ranges from previous queries
- **Token Optimization**: ConversationSummaryBufferMemory with 1500 token limit

#### Intelligent Context Preservation
The `ConversationContextProcessor` (agent/context_processor.py:1) analyzes conversations to:
- Detect contextual references ("these alerts", "that host")
- Extract entities from previous responses
- Preserve temporal context across queries
- Enrich follow-up queries with relevant filters

#### Smart Routing & Field Detection
- **Automatic Field Mapping**: Detects whether to use agent.id or agent.name
- **Process Intelligence**: Searches across originalFileName, image, commandLine
- **Multi-field Search**: Comprehensive coverage for hosts, processes, files
- **Natural Language Time Parsing**: Supports "3 days ago", "yesterday 6am-11am"
