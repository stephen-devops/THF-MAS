"""
Simple demo server for UI testing - no external dependencies
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import random
import time

app = FastAPI(
    title="Wazuh LLM Assistant - Demo Mode",
    description="Demo server for UI testing",
    version="1.0.0-demo"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class QueryRequest(BaseModel):
    query: str
    session_id: str = "default"

class QueryResponse(BaseModel):
    response: str
    session_id: str
    status: str = "demo"

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "wazuh-llm-assistant-demo"}

@app.post("/query", response_model=QueryResponse)
async def query_agent(request: QueryRequest):
    """Demo query responses"""
    
    # Simulate processing time
    time.sleep(random.uniform(0.5, 2.0))
    
    query = request.query.lower()
    
    # Generate contextual demo responses
    if "alert" in query:
        demo_response = f"""
**🚨 Alert Analysis Demo**

Query: "{request.query}"

**Top 10 Alerting Hosts (Last 7 Days):**
1. web-server-01 - 156 alerts (Last: Authentication failure)
2. db-server-02 - 89 alerts (Last: SQL injection attempt)  
3. mail-server-03 - 67 alerts (Last: Suspicious email attachment)
4. workstation-045 - 45 alerts (Last: Malware detected)
5. firewall-01 - 34 alerts (Last: Port scan detected)

**Severity Breakdown:**
- Critical: 23 alerts
- High: 87 alerts  
- Medium: 156 alerts
- Low: 91 alerts

*This is demo data. Connect to OpenSearch for real alerts.*
"""
    elif "user" in query:
        demo_response = f"""
**👤 User Investigation Demo**

Query: "{request.query}"

**User Activity Summary:**
- Total alerts: 34
- First seen: 2024-01-15 09:23:45
- Last activity: 2024-01-15 16:47:12
- Risk score: Medium

**Recent Alerts:**
1. Multiple failed login attempts (16:45)
2. Unusual file access pattern (15:30)
3. After-hours system access (14:22)

**Associated Hosts:**
- workstation-067 (Primary)
- server-database-01 (Secondary)

*This is demo data. Connect to OpenSearch for real user data.*
"""
    elif "agent" in query:
        demo_response = f"""
**🔌 Agent Status Demo**

Query: "{request.query}"

**Agent Health Summary:**
- Total agents: 247
- Active: 234 (94.7%)
- Disconnected: 13 (5.3%)
- Never connected: 0

**Recently Disconnected:**
1. web-server-05 (Offline 2h 34m)
2. workstation-123 (Offline 45m)
3. backup-server-01 (Offline 12m)

**Version Distribution:**
- v4.5.2: 198 agents
- v4.5.1: 36 agents
- v4.4.x: 13 agents

*This is demo data. Connect to Wazuh API for real agent status.*
"""
    elif "vulnerability" in query or "cve" in query:
        demo_response = f"""
**🔍 Vulnerability Check Demo**

Query: "{request.query}"

**Critical Vulnerabilities Found:**
1. CVE-2023-12345 - Remote Code Execution (CVSS: 9.8)
   - Affected: 12 hosts
   - Status: Patch available
   
2. CVE-2023-67890 - Privilege Escalation (CVSS: 8.1)
   - Affected: 5 hosts
   - Status: Mitigation applied

**Severity Summary:**
- Critical: 2 CVEs (17 hosts affected)
- High: 8 CVEs (43 hosts affected)
- Medium: 23 CVEs (156 hosts affected)

*This is demo data. Connect to vulnerability scanner for real CVE data.*
"""
    elif "threat" in query or "mitre" in query:
        demo_response = f"""
**⚠️ Threat Detection Demo**

Query: "{request.query}"

**MITRE ATT&CK Techniques Detected:**
1. T1055 - Process Injection (3 occurrences)
2. T1078 - Valid Accounts (7 occurrences)
3. T1021 - Remote Services (2 occurrences)
4. T1059 - Command and Scripting Interpreter (12 occurrences)

**Threat Actor Indicators:**
- APT29 behavior patterns detected
- Lateral movement indicators present
- Persistence mechanisms identified

**Timeline:**
- 14:30 - Initial compromise detected
- 14:45 - Lateral movement began
- 15:15 - Data exfiltration attempt

*This is demo data. Connect to threat intelligence feeds for real data.*
"""
    else:
        demo_response = f"""
**🛡️ Wazuh Security Assistant Demo**

Query: "{request.query}"

I understand you're asking about: **{request.query}**

**Demo Features Available:**
- Alert analysis and ranking
- User and host investigation  
- Agent status monitoring
- Vulnerability assessments
- Threat detection (MITRE ATT&CK)
- Timeline reconstruction
- Relationship mapping
- Anomaly detection

**Try these example queries:**
- "Show me critical alerts"
- "Check user admin activity"  
- "Find disconnected agents"
- "Look for CVE vulnerabilities"
- "Detect MITRE techniques"

*This is demo mode. Connect to OpenSearch and configure Anthropic API for full functionality.*
"""
    
    return QueryResponse(
        response=demo_response,
        session_id=request.session_id,
        status="demo"
    )

@app.post("/reset")
async def reset_session():
    """Reset session (demo)"""
    return {"message": "Demo session reset"}

@app.get("/")
async def root():
    return {"message": "Wazuh LLM Assistant - Demo Mode", "status": "demo"}

if __name__ == "__main__":
    import uvicorn
    print("Starting Demo Server...")
    print("Use with Streamlit UI at http://localhost:8501")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")