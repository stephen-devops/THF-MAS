"""
Dynamic event type mapping based on natural language keywords and actual rule groups
"""
import re
from typing import List, Dict, Any, Optional


def infer_rule_groups_from_keywords(keywords: List[str]) -> List[Dict[str, Any]]:
    """
    Dynamically infer OpenSearch filters based on natural language keywords
    instead of hardcoded event type mappings
    
    Args:
        keywords: List of natural language terms from user query
        
    Returns:
        List of OpenSearch query filters
    """
    filters = []
    
    # Join all keywords for pattern matching
    combined_text = " ".join(keywords).lower()
    
    # Authentication/Login patterns
    auth_patterns = [
        r'\b(authentication|logon|login|credential|password|sign[\s-]?in)\b',
        r'\b(auth|logon|login)\b',
        r'\bwindows\s+(logon|login)\b'
    ]
    
    if any(re.search(pattern, combined_text) for pattern in auth_patterns):
        filters.append({
            "bool": {
                "should": [
                    # Windows authentication events
                    {"terms": {"rule.groups": ["windows_security", "authentication_success", "authentication_failed"]}},
                    # Linux/Unix authentication
                    {"terms": {"rule.groups": ["authentication", "pam", "ssh"]}},
                    # Description-based matching for authentication
                    {"wildcard": {"rule.description": "*logon*"}},
                    {"wildcard": {"rule.description": "*login*"}},
                    {"wildcard": {"rule.description": "*authentication*"}},
                    {"wildcard": {"rule.description": "*credential*"}}
                ],
                "minimum_should_match": 1
            }
        })
    
    # Process/Command execution patterns  
    process_patterns = [
        r'\b(process|command|execution|executable|program|script)\b',
        r'\b(powershell|cmd|bash|shell)\b',
        r'\b(exe|bat|ps1|sh)\b'
    ]
    
    if any(re.search(pattern, combined_text) for pattern in process_patterns):
        filters.append({
            "bool": {
                "should": [
                    # Windows process events
                    {"terms": {"rule.groups": ["windows", "audit"]}},
                    # Linux process events
                    {"terms": {"rule.groups": ["audit", "process"]}},
                    # Process execution indicators
                    {"exists": {"field": "data.command"}},
                    {"exists": {"field": "data.win.eventdata.commandLine"}},
                    {"exists": {"field": "data.win.eventdata.image"}},
                    # Description-based matching
                    {"wildcard": {"rule.description": "*process*"}},
                    {"wildcard": {"rule.description": "*command*"}},
                    {"wildcard": {"rule.description": "*execution*"}}
                ],
                "minimum_should_match": 1
            }
        })
    
    # File system patterns
    file_patterns = [
        r'\b(file|directory|folder|path|syscheck)\b',
        r'\b(created|modified|deleted|changed)\b',
        r'\b(integrity|fim)\b'
    ]
    
    if any(re.search(pattern, combined_text) for pattern in file_patterns):
        filters.append({
            "bool": {
                "should": [
                    {"terms": {"rule.groups": ["syscheck", "file_integrity"]}},
                    {"wildcard": {"rule.description": "*file*"}},
                    {"wildcard": {"rule.description": "*directory*"}},
                    {"wildcard": {"rule.description": "*integrity*"}}
                ],
                "minimum_should_match": 1
            }
        })
    
    # Network patterns
    network_patterns = [
        r'\b(network|connection|traffic|packet|firewall)\b',
        r'\b(tcp|udp|http|https|dns|port)\b',
        r'\b(src|dst|source|destination)[\s]?(ip|port)\b'
    ]
    
    if any(re.search(pattern, combined_text) for pattern in network_patterns):
        filters.append({
            "bool": {
                "should": [
                    {"exists": {"field": "data.srcip"}},
                    {"exists": {"field": "data.dstip"}},
                    {"terms": {"rule.groups": ["network", "firewall"]}},
                    {"wildcard": {"rule.description": "*network*"}},
                    {"wildcard": {"rule.description": "*connection*"}}
                ],
                "minimum_should_match": 1
            }
        })
    
    # Malware patterns
    malware_patterns = [
        r'\b(malware|virus|threat|suspicious|malicious)\b',
        r'\b(trojan|rootkit|backdoor|spyware)\b',
        r'\b(dropped|payload|infection)\b'
    ]
    
    if any(re.search(pattern, combined_text) for pattern in malware_patterns):
        filters.append({
            "bool": {
                "should": [
                    {"terms": {"rule.groups": ["malware", "virus", "rootcheck"]}},
                    {"wildcard": {"rule.description": "*malware*"}},
                    {"wildcard": {"rule.description": "*suspicious*"}},
                    {"wildcard": {"rule.description": "*threat*"}},
                    {"range": {"rule.level": {"gte": 10}}}  # High severity events
                ],
                "minimum_should_match": 1
            }
        })
    
    # Brute force patterns
    bruteforce_patterns = [
        r'\b(brute[\s-]?force|failed[\s]+(login|logon|auth))\b',
        r'\b(multiple[\s]+(failed|attempts))\b',
        r'\b(password[\s]+(attack|cracking))\b'
    ]
    
    if any(re.search(pattern, combined_text) for pattern in bruteforce_patterns):
        filters.append({
            "bool": {
                "should": [
                    {"wildcard": {"rule.description": "*failed*"}},
                    {"wildcard": {"rule.description": "*multiple*"}},
                    {"wildcard": {"rule.description": "*brute*force*"}},
                    {"terms": {"rule.groups": ["authentication_failed", "authentication_failure"]}},
                    {"range": {"rule.level": {"gte": 5}}}
                ],
                "minimum_should_match": 1
            }
        })
    
    return filters


def extract_keywords_from_query(query: str) -> List[str]:
    """
    Extract meaningful keywords from natural language query
    
    Args:
        query: Natural language query string
        
    Returns:
        List of relevant keywords
    """
    # Remove common stop words and extract meaningful terms
    stop_words = {
        'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 
        'of', 'with', 'by', 'show', 'me', 'find', 'get', 'trace', 'display',
        'over', 'past', 'last', 'during', 'from', 'any', 'all', 'events'
    }
    
    # Clean and tokenize
    words = re.findall(r'\b\w+\b', query.lower())
    keywords = [word for word in words if word not in stop_words and len(word) > 2]
    
    return keywords


def build_smart_event_filters(user_query: str, event_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Build smart event filters based on natural language query and optional event types
    
    Args:
        user_query: Original user query for context
        event_types: Optional list of event types from LLM
        
    Returns:
        List of OpenSearch filters
    """
    filters = []
    
    # Extract keywords from the original query
    query_keywords = extract_keywords_from_query(user_query)
    
    # If event_types provided, add them to keywords
    if event_types:
        query_keywords.extend(event_types)
    
    # Generate dynamic filters
    dynamic_filters = infer_rule_groups_from_keywords(query_keywords)
    filters.extend(dynamic_filters)
    
    # If no specific patterns matched, return broad security event filter
    if not filters:
        filters.append({
            "range": {"rule.level": {"gte": 3}}  # Basic security events
        })
    
    return filters