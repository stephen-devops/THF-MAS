"""
Wazuh API client for direct API access to agent status, configuration, and management
"""
import os
import aiohttp
import base64
from typing import Dict
import structlog
from datetime import datetime

logger = structlog.get_logger()

class WazuhAPIClient:
    """Client for Wazuh API operations"""
    
    def __init__(self, host: str, port: int = 55000, username: str = None, password: str = None, 
                 use_ssl: bool = True, verify_certs: bool = False):
        """
        Initialize Wazuh API client
        
        Args:
            host: Wazuh API host
            port: Wazuh API port (default: 55000)
            username: API username
            password: API password
            use_ssl: Use HTTPS connection
            verify_certs: Verify SSL certificates
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.verify_certs = verify_certs
        
        # Build base URL
        protocol = "https" if use_ssl else "http"
        self.base_url = f"{protocol}://{host}:{port}"
        
        # Authentication token
        self.auth_token = None
        self.token_expires = None
        
        logger.info("WazuhAPIClient initialized", host=host, port=port, use_ssl=use_ssl)
    
    async def authenticate(self) -> str:
        """
        Authenticate with Wazuh API and get JWT token
        
        Returns:
            JWT authentication token
        """
        if self.auth_token and self.token_expires and datetime.now() < self.token_expires:
            return self.auth_token
            
        auth_url = f"{self.base_url}/security/user/authenticate"
        
        # Create basic auth header
        credentials = f"{self.username}:{self.password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        headers = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json"
        }
        
        connector = aiohttp.TCPConnector(ssl=self.verify_certs)
        
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(auth_url, headers=headers) as response:
                    if response.status == 200:
                        result = await response.json()
                        self.auth_token = result.get("data", {}).get("token")
                        # Token expires in 15 minutes by default
                        from datetime import timedelta
                        self.token_expires = datetime.now() + timedelta(minutes=15)
                        
                        logger.info("Successfully authenticated with Wazuh API")
                        return self.auth_token
                    else:
                        error_text = await response.text()
                        logger.error("Failed to authenticate", status=response.status, error=error_text)
                        raise Exception(f"Authentication failed: {response.status} - {error_text}")
                        
        except Exception as e:
            logger.error("Authentication error", error=str(e))
            raise Exception(f"Failed to authenticate with Wazuh API: {str(e)}")
    
    async def _make_request(self, endpoint: str, method: str = "GET", params: Dict = None, data: Dict = None) -> Dict:
        """
        Make authenticated request to Wazuh API
        
        Args:
            endpoint: API endpoint (without base URL)
            method: HTTP method
            params: Query parameters
            data: Request body data
            
        Returns:
            API response data
        """
        token = await self.authenticate()
        
        url = f"{self.base_url}{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        connector = aiohttp.TCPConnector(ssl=self.verify_certs)
        
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.request(method, url, headers=headers, params=params, json=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get("data", {})
                    else:
                        error_text = await response.text()
                        logger.error("API request failed", endpoint=endpoint, status=response.status, error=error_text)
                        raise Exception(f"API request failed: {response.status} - {error_text}")
                        
        except Exception as e:
            logger.error("API request error", endpoint=endpoint, error=str(e))
            raise Exception(f"Failed to make API request to {endpoint}: {str(e)}")
    
    async def get_agents(self, agent_id: str = None, status: str = None, limit: int = 500, offset: int = 0) -> Dict:
        """
        Get agent information from Wazuh API
        
        Args:
            agent_id: Specific agent ID to query
            status: Filter by agent status (active, disconnected, never_connected)
            limit: Maximum number of agents to return
            offset: Offset for pagination
            
        Returns:
            Agent information including status, version, last_keep_alive
        """
        endpoint = "/agents"
        
        params = {
            "limit": limit,
            "offset": offset,
            "select": "id,name,ip,status,version,lastKeepAlive,node_name,manager,os.name,os.version,os.platform"
        }
        
        if agent_id:
            endpoint = f"/agents/{agent_id}"
            params = {"select": "id,name,ip,status,version,lastKeepAlive,node_name,manager,os.name,os.version,os.platform"}
            
        if status:
            params["status"] = status
            
        logger.info("Getting agent information", agent_id=agent_id, status=status, limit=limit)
        
        try:
            result = await self._make_request(endpoint, params=params)
            
            # Handle single agent vs multiple agents response
            if agent_id:
                # Single agent response
                agents = [result] if result else []
            else:
                # Multiple agents response
                agents = result.get("affected_items", [])
                
            logger.info("Retrieved agent information", count=len(agents))
            
            return {
                "agents": agents,
                "total_agents": result.get("total_affected_items", len(agents)) if not agent_id else len(agents)
            }
            
        except Exception as e:
            logger.error("Failed to get agent information", error=str(e))
            raise Exception(f"Failed to retrieve agent information: {str(e)}")
    
    async def get_agent_summary(self) -> Dict:
        """
        Get agent summary statistics
        
        Returns:
            Summary of agent counts by status
        """
        endpoint = "/agents/summary/status"
        
        logger.info("Getting agent summary")
        
        try:
            result = await self._make_request(endpoint)
            
            logger.info("Retrieved agent summary", summary=result)
            
            return result
            
        except Exception as e:
            logger.error("Failed to get agent summary", error=str(e))
            raise Exception(f"Failed to retrieve agent summary: {str(e)}")
    
    async def search_agents(self, query: str) -> Dict:
        """
        Search agents by name, IP, or other criteria
        
        Args:
            query: Search query (can be name, IP, etc.)
            
        Returns:
            Matching agents
        """
        # Try different search approaches
        agents_found = []
        
        # Search by name
        try:
            result = await self.get_agents()
            agents = result.get("agents", [])
            
            # Filter agents based on query
            for agent in agents:
                if (query.lower() in agent.get("name", "").lower() or
                    query in agent.get("ip", "") or
                    str(agent.get("id", "")) == query):
                    agents_found.append(agent)
                    
        except Exception as e:
            logger.error("Failed to search agents", query=query, error=str(e))
            raise Exception(f"Failed to search agents: {str(e)}")
        
        logger.info("Agent search completed", query=query, found=len(agents_found))
        
        return {
            "agents": agents_found,
            "total_agents": len(agents_found),
            "search_query": query
        }


def create_wazuh_api_client_from_env() -> WazuhAPIClient:
    """
    Create WazuhAPIClient from environment variables
    
    Returns:
        Configured WazuhAPIClient instance
    """
    host = os.getenv("WAZUH_API_HOST", "localhost")
    port = int(os.getenv("WAZUH_API_PORT", "55000"))
    username = os.getenv("WAZUH_API_USERNAME", "wazuh")
    password = os.getenv("WAZUH_API_PASSWORD")
    use_ssl = os.getenv("WAZUH_API_USE_SSL", "true").lower() == "true"
    verify_certs = os.getenv("WAZUH_API_VERIFY_CERTS", "false").lower() == "true"
    
    if not password:
        raise ValueError("WAZUH_API_PASSWORD environment variable is required")
    
    return WazuhAPIClient(
        host=host,
        port=port,
        username=username,
        password=password,
        use_ssl=use_ssl,
        verify_certs=verify_certs
    )