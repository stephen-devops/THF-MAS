"""
Wazuh LLM Assistant - Main FastAPI Application
"""
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import structlog
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Initialize FastAPI app
app = FastAPI(
    title="Wazuh LLM Security Assistant",
    description="Natural language interface for Wazuh SIEM using LangChain and Anthropic Claude",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global agent instance (will be initialized on startup)
agent = None

class QueryRequest(BaseModel):
    """Request model for user queries"""
    query: str
    session_id: Optional[str] = "default"

class QueryResponse(BaseModel):
    """Response model for agent responses"""
    response: str
    session_id: str
    status: str = "success"

class ErrorResponse(BaseModel):
    """Error response model"""
    error: str
    status: str = "error"

@app.on_event("startup")
async def startup_event():
    """Initialize the agent on startup"""
    global agent
    
    try:
        # Import here to avoid circular imports
        from agent.wazuh_agent import WazuhSecurityAgent
        
        # Initialize agent with configuration
        agent = WazuhSecurityAgent(
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            opensearch_config={
                "host": os.getenv("OPENSEARCH_HOST", "localhost"),
                "port": int(os.getenv("OPENSEARCH_PORT", "9200")),
                "auth": (
                    os.getenv("OPENSEARCH_USER", "admin"),
                    os.getenv("OPENSEARCH_PASSWORD", "admin")
                ),
                "use_ssl": os.getenv("OPENSEARCH_USE_SSL", "true").lower() == "true",
                "verify_certs": os.getenv("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true"
            }
        )
        
        logger.info("Wazuh LLM Assistant initialized successfully")
        
    except Exception as e:
        logger.error("Failed to initialize agent", error=str(e))
        raise

@app.post("/query", response_model=QueryResponse)
async def query_agent(request: QueryRequest):
    """Process natural language query against Wazuh SIEM"""
    global agent
    
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    try:
        logger.info("Processing query", 
                   query=request.query[:100],  # Log first 100 chars
                   session_id=request.session_id)
        
        # Process query with agent including session context
        response = await agent.query(request.query, request.session_id)
        
        logger.info("Query processed successfully", 
                   session_id=request.session_id,
                   response_length=len(response))
        
        return QueryResponse(
            response=response,
            session_id=request.session_id,
            status="success"
        )
        
    except Exception as e:
        logger.error("Query processing failed", 
                    error=str(e),
                    session_id=request.session_id)
        raise HTTPException(status_code=500, detail=f"Query processing failed: {str(e)}")

@app.post("/reset")
async def reset_session(session_id: str = "default"):
    """Reset conversation memory for a session"""
    global agent
    
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    
    try:
        await agent.reset_memory(session_id)
        logger.info("Session reset successfully", session_id=session_id)
        return {"message": "Session reset successfully", "session_id": session_id}
        
    except Exception as e:
        logger.error("Session reset failed", error=str(e), session_id=session_id)
        raise HTTPException(status_code=500, detail=f"Session reset failed: {str(e)}")

@app.get("/session/{session_id}")
async def get_session_info(session_id: str):
    """Get information about a specific session"""
    global agent

    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")

    try:
        session_info = agent.get_session_info(session_id)
        return session_info
    except Exception as e:
        logger.error("Failed to get session info", error=str(e), session_id=session_id)
        raise HTTPException(status_code=500, detail=f"Failed to get session info: {str(e)}")

@app.get("/sessions")
async def get_all_sessions():
    """Get information about all active sessions"""
    global agent

    if not agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")

    try:
        sessions_info = agent.get_session_info()
        return sessions_info
    except Exception as e:
        logger.error("Failed to get sessions info", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to get sessions info: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "wazuh-llm-assistant",
        "version": "1.0.0",
        "agent_initialized": agent is not None
    }

@app.get("/")
async def root():
    """Root endpoint with basic info"""
    return {
        "message": "Wazuh LLM Assistant",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }

if __name__ == "__main__":
    import uvicorn
    
    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", "8000"))
    log_level = os.getenv("LOG_LEVEL", "info").lower()
    
    logger.info("Starting Wazuh LLM Assistant", 
               host=host, 
               port=port, 
               log_level=log_level)
    
    uvicorn.run(
        app, 
        host=host, 
        port=port, 
        log_level=log_level,
        reload=True  # Enable for development
    )