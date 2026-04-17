"""
Query pattern detector for smart routing.
Detects common query patterns and routes them to optimized functions.
"""

import re
from typing import Dict, Any, Optional, Tuple


def detect_process_alert_query(user_query: str) -> Optional[Dict[str, Any]]:
    """
    Detect if query matches process alert pattern and extract parameters.

    Patterns detected:
    - "Find all [process] alerts on [host] over/for the last [time]"
    - "Show [process] alerts on [host] for the past [time]"
    - "Get [process] alerts from [host] in the last [time]"

    Args:
        user_query: User's natural language query

    Returns:
        Dictionary with extracted parameters if pattern matches, None otherwise
    """
    query_lower = user_query.lower().strip()

    # Process alert query patterns
    patterns = [
        # Pattern 1: "Find all [process] alerts on [host] over/for the last [time]"
        r'find\s+all\s+([a-zA-Z0-9_.-]+\.exe)\s+alerts\s+on\s+([a-zA-Z0-9][a-zA-Z0-9_.-]*)\s+(?:over|for)\s+the\s+last\s+([0-9]+[hdwm])',

        # Pattern 2: "Show [process] alerts on [host] for the past [time]"
        r'show\s+([a-zA-Z0-9_.-]+\.exe)\s+alerts\s+on\s+([a-zA-Z0-9][a-zA-Z0-9_.-]*)\s+for\s+the\s+past\s+([0-9]+[hdwm])',

        # Pattern 3: "Get [process] alerts from [host] in the last [time]"
        r'get\s+([a-zA-Z0-9_.-]+\.exe)\s+alerts\s+from\s+([a-zA-Z0-9][a-zA-Z0-9_.-]*)\s+in\s+the\s+last\s+([0-9]+[hdwm])',

        # Pattern 4: More flexible pattern matching
        r'(?:find|show|get|display)\s+(?:all\s+)?([a-zA-Z0-9_.-]+\.exe)\s+alerts?\s+(?:on|from|for)\s+(?:host\s+)?([a-zA-Z0-9][a-zA-Z0-9_.-]*)\s+(?:over|for|in|during)\s+(?:the\s+)?(?:last|past)\s+([0-9]+\s*(?:hours?|days?|h|d))',

        # Pattern 5: Simple process + host pattern
        r'([a-zA-Z0-9_.-]+\.exe)\s+alerts?\s+(?:on|from)\s+([a-zA-Z0-9][a-zA-Z0-9_.-]*)',
    ]

    for pattern in patterns:
        match = re.search(pattern, query_lower)
        if match:
            groups = match.groups()

            if len(groups) >= 2:
                process_name = groups[0]
                host = groups[1]
                time_range = groups[2] if len(groups) > 2 else "24h"

                # Normalize time range
                time_range = _normalize_time_range(time_range)

                return {
                    "function": "smart_routing/process_alerts_query",
                    "params": {
                        "process_name": process_name,
                        "host": host,
                        "time_range": time_range,
                        "limit": 50
                    },
                    "pattern_matched": pattern,
                    "confidence": 0.9
                }

    return None


def detect_query_pattern(user_query: str) -> Optional[Dict[str, Any]]:
    """
    Main query pattern detector that tries different pattern types.

    Args:
        user_query: User's natural language query

    Returns:
        Dictionary with routing information if pattern detected, None otherwise
    """
    # Try process alert query detection first
    process_result = detect_process_alert_query(user_query)
    if process_result:
        return process_result

    # Future: Add more pattern detectors here
    # - Host-based queries: "Show all alerts on host-01"
    # - Time-based queries: "What happened in the last hour?"
    # - Severity-based queries: "Find critical alerts"
    # - User-based queries: "Show alerts for user john.doe"

    return None


def _normalize_time_range(time_str: str) -> str:
    """
    Normalize time range string to standard format.

    Args:
        time_str: Time range string (e.g., "12 hours", "24h", "1 day")

    Returns:
        Normalized time range (e.g., "12h", "24h", "1d")
    """
    time_str = time_str.lower().strip()

    # Handle numeric + unit patterns
    patterns = [
        (r'(\d+)\s*hours?', r'\1h'),
        (r'(\d+)\s*days?', r'\1d'),
        (r'(\d+)\s*weeks?', r'\1w'),
        (r'(\d+)\s*months?', r'\1m'),
        (r'(\d+)h', r'\1h'),  # Already normalized
        (r'(\d+)d', r'\1d'),  # Already normalized
        (r'(\d+)w', r'\1w'),  # Already normalized
        (r'(\d+)m', r'\1m'),  # Already normalized
    ]

    for pattern, replacement in patterns:
        match = re.search(pattern, time_str)
        if match:
            return re.sub(pattern, replacement, time_str)

    # Default fallback
    return "24h"


def should_use_smart_routing(user_query: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Determine if query should use smart routing and return routing info.

    Args:
        user_query: User's natural language query

    Returns:
        Tuple of (should_route, routing_info)
    """
    routing_info = detect_query_pattern(user_query)

    if routing_info:
        return True, routing_info

    return False, None


# Test function for development
def test_pattern_detection():
    """Test the pattern detection with various query examples."""
    test_queries = [
        "Find all powershell.exe alerts on win-3 over the last 12 hours",
        "Show chrome.exe alerts on host-01 for the past 24h",
        "Get net.exe alerts from server-02 in the last 6 hours",
        "Find all notepad.exe alerts on win10-01 over the last 1 day",
        "powershell.exe alerts on win-3",
        "Display cmd.exe alerts on localhost for 2 hours",
        "What happened on host-01 yesterday",  # Should not match
    ]

    print("=== Query Pattern Detection Test ===")
    for query in test_queries:
        should_route, routing_info = should_use_smart_routing(query)

        print(f"\nQuery: {query}")
        print(f"Should route: {should_route}")
        if routing_info:
            print(f"Function: {routing_info['function']}")
            print(f"Parameters: {routing_info['params']}")
            print(f"Confidence: {routing_info['confidence']}")


if __name__ == "__main__":
    test_pattern_detection()