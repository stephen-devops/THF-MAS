"""
Streamlit UI for Wazuh LLM Security Assistant
"""
import streamlit as st
import requests
from datetime import datetime
import time
import base64
import os

# Logo helper function
def get_logo_path():
    """Get logo file path if it exists"""
    logo_paths = [
        "assets/images/resilmesh_logo.png",
        "assets/images/resilmesh-logo.svg",
        "assets/images/resilmesh-logo.ico"
    ]
    for path in logo_paths:
        if os.path.exists(path):
            return path
    return None

def get_base64_logo():
    """Convert logo to base64 for embedding in HTML"""
    logo_path = get_logo_path()
    if logo_path and logo_path.endswith('.png'):
        try:
            with open(logo_path, "rb") as f:
                return base64.b64encode(f.read()).decode()
        except Exception:
            pass
    return None

# Page configuration
logo_path = get_logo_path()
st.set_page_config(
    page_title="Resilmesh C3 Threat Hunting Assistant",
    page_icon=logo_path if logo_path else "🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .status-indicator {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 5px;
    }
    .status-online {
        background-color: #28a745;
    }
    .status-offline {
        background-color: #dc3545;
    }
    .query-examples {
        background-color: #f8f9fa;
        border-left: 4px solid #007bff;
        padding: 1rem;
        margin: 1rem 0;
    }
    .response-container {
        background-color: #ffffff;
        border: 1px solid #dee2e6;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
    }
    .error-message {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 0.5rem;
        padding: 1rem;
        color: #721c24;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'messages' not in st.session_state:
    st.session_state.messages = []
if 'session_id' not in st.session_state:
    st.session_state.session_id = f"session_{int(time.time())}"
if 'last_query' not in st.session_state:
    st.session_state.last_query = ""
if 'context_info' not in st.session_state:
    st.session_state.context_info = {}

# Configuration
# For Docker: use port 8030 (host mapping), for local dev: use port 8000
API_PORT = os.getenv("API_PORT", "8000")  # Default to 8000 for local development
API_BASE_URL = f"http://localhost:{API_PORT}"

def check_api_health():
    """Check if the API is running"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def send_query(query: str, session_id: str):
    """Send query to the API"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/query",
            json={"query": query, "session_id": session_id},
            timeout=120
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API Error: {response.status_code}", "details": response.text}
    except requests.exceptions.RequestException as e:
        return {"error": f"Connection Error: {str(e)}"}

def reset_session(session_id: str):
    """Reset the conversation session"""
    try:
        response = requests.post(f"{API_BASE_URL}/reset", params={"session_id": session_id}, timeout=10)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def get_session_info(session_id: str):
    """Get session information"""
    try:
        response = requests.get(f"{API_BASE_URL}/session/{session_id}", timeout=10)
        if response.status_code == 200:
            return response.json()
        return None
    except requests.exceptions.RequestException:
        return None

# Main UI
# Add Resilmesh logo at the top center using get_logo_path function
main_logo_path = get_logo_path()
if main_logo_path:
    # Convert logo to base64 and display as HTML centered above heading
    try:
        with open(main_logo_path, "rb") as f:
            logo_data = base64.b64encode(f.read()).decode()
        st.markdown(f'<div style="text-align: center; margin-bottom: 1rem;"><img src="data:image/png;base64,{logo_data}" width="200" style="display: block; margin: 0 auto;"></div>', unsafe_allow_html=True)
    except Exception:
        st.markdown('<div style="text-align: center; margin-bottom: 1rem;"><strong>Resilmesh Logo</strong></div>', unsafe_allow_html=True)

# Main header - always use shield icon
st.markdown('<h1 class="main-header">🛡️ Resilmesh C3 Threat Hunting Assistant</h1>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.header("Configuration")

    # API Status
    api_status = check_api_health()
    status_class = "status-online" if api_status else "status-offline"
    status_text = "Online" if api_status else "Offline"
    st.markdown(f'<div><span class="status-indicator {status_class}"></span>API Status: {status_text}</div>', unsafe_allow_html=True)

    st.markdown("---")

    # Session Management
    st.subheader("Session Management")
    st.text(f"Session ID: {st.session_state.session_id[-8:]}")

    if st.button("🔄 Reset Session"):
        if reset_session(st.session_state.session_id):
            st.session_state.messages = []
            old_session = st.session_state.session_id
            st.session_state.session_id = f"session_{int(time.time())}"
            st.session_state.context_info = {}
            st.success(f"Session {old_session[-8:]} reset successfully!")
            st.rerun()
        else:
            st.error("Failed to reset session")

    # Show session info
    if st.button("📊 Session Info"):
        session_info = get_session_info(st.session_state.session_id)
        if session_info:
            st.session_state.context_info = session_info
            st.rerun()
        else:
            st.error("Failed to get session info")

    # Display session context info if available
    if st.session_state.context_info:
        st.subheader("Session Context")
        info = st.session_state.context_info
        if info.get("exists", False):
            st.write(f"**Messages in session:** {info.get('message_count', 0)}")
            st.write(f"**Session active:** Yes")
        else:
            st.write("**Session active:** No")

    st.markdown("---")

    # Quick Actions
    st.subheader("Quick Actions")

    example_queries = [
        "Show me the top 10 hosts with most alerts this week",
        "What alerts are there for user admin?",
        "Find hosts with more than 50 failed login attempts",
        "Show me critical alerts from the last hour",
        "Which agents are disconnected?",
        "Find authentication failures in the last 24 hours"
    ]

    # Context-aware follow-up examples
    followup_queries = [
        "Give me more details on those critical alerts",
        "What about authentication failures on that host?",
        "Show me the timeline for those events",
        "Are there any related security threats?",
        "Which users were affected?"
    ]

    query_type = st.radio(
        "Query Type:",
        ["Initial Queries", "Follow-up Queries (use after initial query)"]
    )

    if query_type == "Initial Queries":
        selected_queries = example_queries
        help_text = "These queries establish new context"
    else:
        selected_queries = followup_queries
        help_text = "These queries reference previous conversation context"

    selected_example = st.selectbox(
        "Example Queries:",
        ["Select an example..."] + selected_queries,
        help=help_text
    )

    if st.button("Use Example Query") and selected_example != "Select an example...":
        st.session_state.current_query = selected_example

# Main content area
if not api_status:
    st.error("⚠️ API is not running. Please start the FastAPI server first:")
    st.code("python main.py", language="bash")
    st.stop()

# Query input
st.subheader("Ask a Security Question")

# Use example query if selected
current_query = st.session_state.get('current_query', '')
if current_query:
    st.session_state.current_query = ''  # Clear after use

query = st.text_input(
    "Enter your security question:",
    value=current_query,
    placeholder="e.g., Show me the top 10 hosts with most alerts this week...",
    key="query_input"
)

if st.button("📋 Clear History"):
    st.session_state.messages = []
    st.rerun()

# Process query - automatically submit on Enter
if query and query.strip() and query != st.session_state.last_query:
    # Update last query to prevent duplicate submissions
    st.session_state.last_query = query
    
    # Add user message to history
    st.session_state.messages.append({
        "role": "user",
        "content": query,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    })

    # Show loading spinner
    with st.spinner("🤔 Analyzing your security question. This may take a few minutes ..."):
        response = send_query(query, st.session_state.session_id)

    # Add assistant response to history
    if "error" in response:
        st.session_state.messages.append({
            "role": "error",
            "content": response["error"],
            "details": response.get("details", ""),
            "timestamp": datetime.now().strftime("%H:%M:%S")
        })
    else:
        st.session_state.messages.append({
            "role": "assistant",
            "content": response["response"],
            "timestamp": datetime.now().strftime("%H:%M:%S")
        })

    # Rerun to update the interface
    st.rerun()

# Display conversation history
if st.session_state.messages:
    st.subheader("Conversation History")

    for i, message in enumerate(reversed(st.session_state.messages)):
        with st.container():
            col1, col2 = st.columns([1, 10])

            with col1:
                if message["role"] == "user":
                    st.markdown("**👤 You**")
                elif message["role"] == "assistant":
                    st.markdown("**🤖 Assistant**")
                else:
                    st.markdown("**❌ Error**")

            with col2:
                st.markdown(f"*{message['timestamp']}*")

                if message["role"] == "error":
                    st.markdown(f'<div class="error-message">{message["content"]}</div>', unsafe_allow_html=True)
                    if message.get("details"):
                        with st.expander("Error Details"):
                            st.text(message["details"])
                else:
                    st.markdown(f'<div class="response-container">{message["content"]}</div>', unsafe_allow_html=True)

            st.markdown("---")

# Help section
with st.expander("ℹ️ Help & Examples"):
    st.markdown("""
    ### How to Use
    1. **Start the API server** first: `python main.py`
    2. **Ask security questions** in natural language and press Enter to submit
    3. **Use example queries** from the sidebar for quick start
    4. **Reset session** to clear conversation history

    ### Example Queries
    """)

    for example in example_queries:
        st.markdown(f"• {example}")

    st.markdown("""
    ### Available Functions
    - **Alert Analysis**: Ranking, counting, filtering alerts
    - **Entity Investigation**: Investigate hosts, users, processes, files
    - **Threat Detection**: MITRE ATT&CK techniques and threat actors
    - **Relationship Mapping**: Connections between entities
    - **Anomaly Detection**: Unusual patterns and behaviors
    - **Timeline Reconstruction**: Chronological event analysis
    - **Vulnerability Checking**: CVE and patch status
    - **Agent Monitoring**: Agent health and connectivity
    """)

# Footer
st.markdown("---")
st.markdown("**Wazuh LLM Security Assistant** - Powered by Claude Sonnet 4 via LangChain")
