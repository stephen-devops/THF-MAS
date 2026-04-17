"""
Context Preprocessing for Wazuh Security Agent

Handles conversation context analysis and parameter enrichment
separate from the LLM system prompt to prevent bias and pollution.
"""
import re
import structlog
from typing import Dict, Any, List, Optional

logger = structlog.get_logger()


class ConversationContextProcessor:
    """
    Processes conversation context and enriches user queries with
    contextual parameters without polluting the LLM system prompt.
    """

    def __init__(self):
        self.contextual_keywords = [
            # Demonstrative pronouns and determiners
            "those", "these", "that", "this", "the ones", "such",
            # Specific threat hunting references
            "the critical ones", "the high priority", "critical alerts", "high severity",
            "those alerts", "these alerts", "these events", "said alerts", "said events",
            "those processes", "these processes", "mentioned", "above", "earlier",
            # Contextual location/time references
            "from there", "on that host", "for that user", "same host", "same user",
            "same timeframe", "same period", "from before", "previously mentioned",
            # Request for additional details
            "more details", "more information", "further analysis", "dig deeper",
            "expand on", "tell me more", "additional context", "deeper dive"
        ]

        # Common context schema for both tool calls and user messages
        self.context_schema = {
            "hosts": [],
            "users": [],
            "timeframes": [],
            "alert_types": [],
            "ip_addresses": [],
            "processes": [],
            "rule_groups": [],
            "rule_ids": [],
            "ports": [],
            "protocols": [],
            "file_paths": [],
            "registry_keys": [],
            "domains": [],
            "severity_levels": [],
            "query_actions": []
        }

    def _detect_contextual_reference(self, user_input: str, chat_history: List) -> bool:
        """
        Enhanced contextual reference detection using multiple strategies.

        Args:
            user_input: User's query
            chat_history: Previous conversation messages

        Returns:
            Boolean indicating if query has contextual reference
        """
        user_input_lower = user_input.lower()

        # Strategy 1: Explicit contextual keywords
        if any(keyword in user_input_lower for keyword in self.contextual_keywords):
            return True

        # Strategy 2: Numerical references to specific counts mentioned in previous responses
        if chat_history:
            # Extract numbers from user query
            user_numbers = set(re.findall(r'\b(\d+)\b', user_input))

            # Look for these numbers in recent LLM responses
            for message in chat_history[-3:]:  # Check last 3 messages
                if hasattr(message, 'content') and self._is_llm_response(message.content):
                    message_numbers = set(re.findall(r'\b(\d+)\b', message.content))
                    # If user mentions a specific number that was in the LLM response
                    if user_numbers.intersection(message_numbers):
                        return True

        # Strategy 3: Definite article patterns with specific entities
        definite_patterns = [
            r'\bthe\s+(\d+)\s+(alerts?|events?|processes?|hosts?)',  # "the 26 alerts"
            r'\bthe\s+(alerts?|events?)\s+(caused|triggered|from)',    # "the alerts caused by"
            r'\bthe\s+(critical|high|medium|low)\s+(alerts?|events?)', # "the critical alerts"
        ]

        for pattern in definite_patterns:
            if re.search(pattern, user_input_lower):
                return True

        # Strategy 4: Entity references from previous context
        if chat_history:
            # Extract entity names from previous responses and check if referenced
            for message in chat_history[-2:]:  # Check last 2 messages
                if hasattr(message, 'content'):
                    content = message.content.lower()
                    # Look for specific process names, hosts, etc mentioned in previous responses
                    processes = re.findall(r'\b([a-zA-Z0-9_.-]+\.exe)\b', content)
                    hosts = re.findall(r'\bhost\s+([a-zA-Z0-9][a-zA-Z0-9_.-]*)', content)

                    # Check if any of these entities are mentioned in the user query
                    for entity in processes + hosts:
                        if entity.lower() in user_input_lower:
                            return True

        return False

    def process_query_with_context(self, user_input: str, chat_history: List) -> Dict[str, Any]:
        """
        Process user query and return enriched parameters based on context.

        Args:
            user_input: User's natural language query
            chat_history: Previous conversation messages

        Returns:
            Dictionary with:
            - original_query: Original user input
            - has_contextual_reference: Boolean if query references previous context
            - explicit_new_params: Boolean if user specified new parameters
            - suggested_filters: Dict of suggested filters from context
            - context_applied: Boolean if context should be applied
            - reasoning: String explaining the decision
        """
        result = {
            "original_query": user_input,
            "has_contextual_reference": False,
            "explicit_new_params": False,
            "suggested_filters": {},
            "context_applied": False,
            "reasoning": ""
        }

        # Step 1: Check for contextual references (enhanced detection)
        has_contextual_reference = self._detect_contextual_reference(user_input, chat_history)
        result["has_contextual_reference"] = has_contextual_reference

        # Step 2: Check for explicit new parameters (exclude contextual references)
        # Only consider it a NEW parameter if there's NO contextual reference detected
        # OR if the parameter is explicitly different from context (e.g., "last 24 hours" when context has "3 days")
        new_time_specified = False
        if not has_contextual_reference:
            # Enhanced patterns to catch more explicit time specifications
            time_patterns = [
                r'\b(\d+)\s*(hour|day|minute|week|month)s?\b',  # "3 days", "24 hours"
                r'\b(\d+)([hdwmy])\b',  # "3d", "24h", "1w"
                r'\b(yesterday|today|last\s+\w+|past\s+\d+)',  # "yesterday", "last week", "past 5"
                r'\bfrom\s+(\d+)\s*(hour|day)s?\s+ago\b',  # "from 3 days ago"
            ]
            new_time_specified = any(bool(re.search(pattern, user_input.lower())) for pattern in time_patterns)

        # FIXED: Don't treat host mentions as "new" if the query has contextual keywords
        # "Investigate these 78 alerts on host U209-PC-BLEE" = contextual reference (has "these", "78")
        # "Show me alerts on host WIN-SERVER" = new explicit specification (no context)
        new_host_specified = False
        if not has_contextual_reference:
            new_host_specified = bool(re.search(r'\b(?:host|agent|server)\s+(?![a-zA-Z]*(?:this|that|the))[a-zA-Z0-9._-]+', user_input.lower()))

        result["explicit_new_params"] = new_time_specified or new_host_specified

        # Step 3: Extract previous context
        previous_context = self._extract_previous_context(chat_history) if chat_history else {}

        # Step 4: Decision logic
        if result["explicit_new_params"]:
            result["reasoning"] = f"User specified new parameters (time: {new_time_specified}, host: {new_host_specified}). Skipping context preservation."
            logger.info("Skipping context preservation - explicit new parameters",
                       new_time=new_time_specified, new_host=new_host_specified)
            return result

        if not has_contextual_reference:
            result["reasoning"] = "No contextual keywords found. Treating as independent query."
            return result

        if not previous_context:
            result["reasoning"] = "Contextual keywords found but no previous context available."
            return result

        # Step 5: Build suggested filters from context
        suggested_filters = {}
        suggested_time_range = None

        if previous_context.get("hosts"):
            # Use 'host' for intelligent field detection (OpenSearch client will auto-detect agent.id vs agent.name)
            suggested_filters["host"] = previous_context["hosts"][0]

        if previous_context.get("timeframes"):
            # Convert timeframe to standardized format
            suggested_time_range = self._extract_timeframe(previous_context["timeframes"])

        if previous_context.get("alert_types"):
            if "critical" in previous_context["alert_types"]:
                suggested_filters["rule.level"] = {"gte": 12}
            elif "high" in previous_context["alert_types"]:
                suggested_filters["rule.level"] = {"gte": 8, "lte": 11}

        if previous_context.get("processes"):
            suggested_filters["process.name"] = previous_context["processes"][0]

        if previous_context.get("rule_groups"):
            suggested_filters["rule.groups"] = previous_context["rule_groups"]

        if previous_context.get("ip_addresses"):
            suggested_filters["ip.src"] = previous_context["ip_addresses"][0]

        result["suggested_filters"] = suggested_filters
        result["suggested_time_range"] = suggested_time_range
        result["context_applied"] = bool(suggested_filters) or bool(suggested_time_range)

        context_parts = []
        if suggested_filters:
            context_parts.append(f"filters: {list(suggested_filters.keys())}")
        if suggested_time_range:
            context_parts.append(f"time_range: {suggested_time_range}")

        result["reasoning"] = f"Applied context from previous query. {', '.join(context_parts) if context_parts else 'No context applied'}"

        logger.info("Context processing completed",
                   has_contextual_ref=has_contextual_reference,
                   previous_context=previous_context,
                   suggested_filters=suggested_filters,
                   suggested_time_range=suggested_time_range,
                   reasoning=result["reasoning"])

        return result

    def _extract_timeframe(self, timeframes: List[str]) -> Optional[str]:
        """Extract and normalize timeframe from context with enhanced patterns."""
        if not timeframes:
            return None

        # Priority order for timeframe selection
        timeframe_priority = ['h', 'd', 'w', 'm', 'y']

        for tf in timeframes:
            tf_lower = tf.lower().strip()

            # Direct hour/day/week/month/year patterns
            direct_patterns = {
                r'(\d+)\s*h(?:our)?s?': lambda m: f"{m.group(1)}h",
                r'(\d+)\s*d(?:ay)?s?': lambda m: f"{m.group(1)}d",
                r'(\d+)\s*w(?:eek)?s?': lambda m: f"{m.group(1)}w",
                r'(\d+)\s*m(?:onth)?s?': lambda m: f"{m.group(1)}m",
                r'(\d+)\s*y(?:ear)?s?': lambda m: f"{m.group(1)}y",
                r'(\d+)([hdwmy])': lambda m: f"{m.group(1)}{m.group(2)}"
            }

            for pattern, formatter in direct_patterns.items():
                match = re.search(pattern, tf_lower)
                if match:
                    return formatter(match)

            # Natural language patterns
            natural_patterns = {
                'today': '1d', 'yesterday': '1d', 'this week': '1w',
                'last week': '1w', 'this month': '1m', 'last month': '1m'
            }

            if tf_lower in natural_patterns:
                return natural_patterns[tf_lower]

            # Time range patterns (convert to hours)
            if 'between' in tf_lower or 'from' in tf_lower or 'to' in tf_lower:
                # Extract approximate duration from time ranges
                hour_range_match = re.search(r'(\d+)(?:am|pm)?\s*(?:to|-|and)\s*(\d+)(?:am|pm)?', tf_lower)
                if hour_range_match:
                    start, end = int(hour_range_match.group(1)), int(hour_range_match.group(2))
                    duration = abs(end - start)
                    return f"{duration}h" if duration > 0 else "6h"

        return "24h"  # default fallback

    def _is_llm_response(self, content: str) -> bool:
        """
        Determine if content is an LLM-generated response vs user query.

        LLM responses contain analysis language, insights, and formatted results.
        User queries are direct questions or commands.
        """
        # Skip very short content (likely user queries)
        if len(content) < 30:
            return False

        content_lower = content.lower()

        # Single strong LLM indicators (definitive analysis language)
        strong_llm_indicators = [
            'analysis shows', 'analysis reveals', 'data shows', 'findings show',
            'results indicate', 'the data suggests', 'pattern analysis',
            'threat assessment', 'security posture', 'risk analysis',
            'correlation analysis', 'behavioral analysis', 'key findings:',
            'summary:', 'recommendations:', 'insights:', 'conclusion:',
            'total_alerts', 'search_parameters', 'timeline_events',
            '@timestamp', 'agent.name', 'rule.level', 'overview',
            'alert summary', 'severity distribution', 'top alert types',
            'critical security events', 'timeline activity', 'peak activity',
            'immediate attention', 'security investigation', 'monitor',
            'investigate', 'review', 'check', 'verify'
        ]

        # Weaker indicators (need multiple)
        weak_llm_indicators = [
            'based on', 'indicates that', 'observation:', 'note that',
            'it appears', 'shows that', 'detected', 'found', 'identified',
            'suggests', 'may require', 'should', 'need'
        ]

        # Check for strong indicators (any one is sufficient)
        for indicator in strong_llm_indicators:
            if indicator in content_lower:
                return True

        # Check for multiple weak indicators
        weak_count = sum(1 for indicator in weak_llm_indicators if indicator in content_lower)

        return weak_count >= 2

    def _validate_extracted_value(self, context_key: str, value: str) -> bool:
        """
        Validate extracted values based on context type.
        """
        if not value or len(value) < 2:
            return False

        value_lower = value.lower()

        # Common blacklisted words
        common_blacklist = {
            'if', 'it', 'is', 'at', 'in', 'on', 'of', 'to', 'for', 'and', 'the', 'a', 'an',
            'this', 'that', 'these', 'those', 'any', 'all', 'each', 'some', 'such', 'other',
            'host', 'hosts', 'self', 'connections', 'shows', 'analysis', 'data',
            'information', 'details', 'summary', 'findings', 'results', 'may',
            'require', 'immediate', 'security', 'investigation', 'suggests'
        }

        if value_lower in common_blacklist:
            return False

        validation_rules = {
            'hosts': lambda v: re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*[a-zA-Z0-9]$', v) and len(v) > 2,
            'users': lambda v: re.match(r'^[a-zA-Z][a-zA-Z0-9_.-]*$', v) and len(v) > 2,
            'ip_addresses': lambda v: re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', v),
            'processes': lambda v: v.endswith('.exe') and len(v) > 6 and re.match(r'^[a-zA-Z0-9_.-]+\.exe$', v),
            'rule_groups': lambda v: re.match(r'^[a-zA-Z0-9_-]+$', v) and len(v) > 2,
            'rule_ids': lambda v: v.isdigit() or re.match(r'^[a-zA-Z0-9_-]+$', v),
            'timeframes': lambda v: True,  # Already validated in extraction
            'ports': lambda v: v.isdigit() and 1 <= int(v) <= 65535,
            'domains': lambda v: '.' in v and re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v),
            'file_paths': lambda v: '/' in v or '\\' in v,
            'protocols': lambda v: v.lower() in ['tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'ssh', 'ftp']
        }

        validator = validation_rules.get(context_key, lambda v: True)
        return validator(value)

    def _extract_tool_call_parameters(self, content: str) -> Dict[str, List]:
        """
        Extract context from LLM tool call parameters in message content.
        Captures time_range, entity_id, filters, etc. from function/tool calls.
        """
        tool_context = self.context_schema.copy()

        # Consolidated parameter extraction patterns
        extraction_patterns = {
            "timeframes": [
                r'"time_range"[:\s]*"([^"]+)"',
                r"'time_range'[:\s]*'([^']+)'",
                r'time_range[:\s]*["\']?(\d+[hdwmy])["\']?'
            ],
            "hosts": [
                r'"entity_id"[:\s]*"([^"]+)"',
                r"'entity_id'[:\s]*'([^']+)'",
                r'"host"[:\s]*"([^"]+)"',
                r"'host'[:\s]*'([^']+)'",
                r'"filters"[^}]*"host"[:\s]*"([^"]+)"'
            ],
            "users": [
                r'"user"[:\s]*"([^"]+)"',
                r'"username"[:\s]*"([^"]+)"'
            ],
            "ip_addresses": [
                r'"ip[._]?src"[:\s]*"([^"]+)"',
                r'"ip[._]?dst"[:\s]*"([^"]+)"'
            ],
            "processes": [
                r'"process[._]?name"[:\s]*"([^"]+)"'
            ],
            "rule_groups": [
                r'"rule[._]?groups?"[:\s]*"([^"]+)"'
            ],
            "rule_ids": [
                r'"rule[._]?id"[:\s]*"?([^"\s,}]+)"?'
            ],
            "ports": [
                r'"port"[:\s]*"?(\d+)"?',
                r'"dst[._]?port"[:\s]*"?(\d+)"?',
                r'"src[._]?port"[:\s]*"?(\d+)"?'
            ]
        }

        # Extract severity levels with special handling
        severity_patterns = [
            r'"severity"[:\s]*\[([^\]]+)\]',
            r'"rule\.level"[:\s]*\{"gte"[:\s]*(\d+)\}',
            r'"rule\.level"[:\s]*\[([^\]]+)\]'
        ]

        for pattern in severity_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                severity_numbers = re.findall(r'\d+', match)
                tool_context["severity_levels"].extend(severity_numbers)

        # Apply extraction patterns
        for context_key, patterns in extraction_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if self._validate_extracted_value(context_key, match):
                        tool_context[context_key].append(match)

        return tool_context

    def _extract_previous_context(self, chat_history: List) -> Dict[str, List]:
        """
        Extract relevant context from previous conversation messages.
        """
        context = self.context_schema.copy()

        # Look at recent messages (last 4-6 messages)
        recent_messages = chat_history[-6:] if len(chat_history) > 6 else chat_history

        for message in recent_messages:
            if hasattr(message, 'content'):
                content = message.content

                # Extract from LLM tool call parameters first (highest priority)
                tool_call_context = self._extract_tool_call_parameters(content)
                if tool_call_context:
                    # Merge tool call context with highest priority
                    for key, values in tool_call_context.items():
                        if key in context and isinstance(context[key], list):
                            context[key].extend(values)

                # CRITICAL FIX: Only extract from USER messages and FUNCTION PARAMETERS
                # Skip LLM-generated responses that contain analysis text
                if self._is_llm_response(content):
                    continue

                content_lower = content.lower()

                # Consolidated extraction patterns for user messages
                user_message_patterns = {
                    "hosts": [
                        r'\bhost\s+([a-zA-Z0-9][a-zA-Z0-9_.-]*)',
                        r'\bon\s+host\s+([a-zA-Z0-9][a-zA-Z0-9_.-]*)\b',
                        r'\bfor\s+host\s+([a-zA-Z0-9][a-zA-Z0-9_.-]*)\b',
                        r'\bfrom\s+host\s+([a-zA-Z0-9][a-zA-Z0-9_.-]*)\b',
                        r'\bconcentrated\s+on\s+([a-zA-Z0-9][a-zA-Z0-9_.-]*)\b',
                        r'\bactivity\s+on\s+([a-zA-Z0-9][a-zA-Z0-9_.-]*)\b'
                    ],
                    "users": [
                        r'\buser\s+([a-zA-Z][a-zA-Z0-9_.-]+)\b',
                        r'\busername\s+([a-zA-Z][a-zA-Z0-9_.-]+)\b',
                        r'\baccount\s+([a-zA-Z][a-zA-Z0-9_.-]+)\b'
                    ],
                    "ip_addresses": [
                        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    ],
                    "processes": [
                        r'\bprocess\s+([a-zA-Z0-9_.-]+\.exe)\b',
                        r'\b([a-zA-Z0-9_.-]+\.exe)\s+process\b'
                    ],
                    "rule_groups": [
                        r'rule\.groups["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]+)\b',
                        r'\brule\s+group[s]?\s+["\']?([a-zA-Z0-9_-]+)\b'
                    ],
                    "rule_ids": [
                        r'\brule\s+(\d+)\b',
                        r'\brule\s+id[:\s]+(\d+)\b'
                    ],
                    "ports": [
                        r'\bport\s+(\d+)\b',
                        r':(\d+)\b'
                    ],
                    "domains": [
                        r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
                    ],
                    "file_paths": [
                        r'([A-Za-z]:\\[^"\s]+)',  # Windows paths
                        r'(/[^"\s]+/[^"\s]*)'     # Unix paths
                    ],
                    "protocols": [
                        r'\b(tcp|udp|icmp|http|https|dns|ssh|ftp|smb|rdp|ldap)\b'
                    ],
                    "registry_keys": [
                        r'(HKEY_[A-Z_]+\\[^"\s]+)',
                        r'(HKLM\\[^"\s]+)', r'(HKCU\\[^"\s]+)'
                    ]
                }

                # Apply consolidated extraction patterns
                for context_key, patterns in user_message_patterns.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if self._validate_extracted_value(context_key, match):
                                context[context_key].append(match)

                # Extract timeframes with enhanced patterns
                timeframe_patterns = [
                    r'(last \d+ \w+)', r'(past \d+ \w+)', r'(over the (?:past|last) \d+ \w+)',
                    r'(between \d+(?:am|pm)? and \d+(?:am|pm)?)', r'(from \d+(?:am|pm)? to \d+(?:am|pm)?)',
                    r'(\d+(?:am|pm)? to \d+(?:am|pm)?)', r'(\d+(?:am|pm)? - \d+(?:am|pm)?)',
                    r'(\d+ hours?)', r'(\d+ days?)', r'(this week)', r'(today)', r'(yesterday)',
                    r'(\d+[hdwmy])', r'(this month)', r'(last month)'
                ]
                for pattern in timeframe_patterns:
                    matches = re.findall(pattern, content_lower)
                    context["timeframes"].extend(matches)

                # Extract alert types and severity levels
                severity_keywords = {
                    "critical": "12", "high": ["8", "9"], "medium": ["5", "6"], "low": ["3", "4"]
                }
                for keyword, levels in severity_keywords.items():
                    if keyword in content_lower:
                        context["alert_types"].append(keyword)
                        if isinstance(levels, list):
                            context["severity_levels"].extend(levels)
                        else:
                            context["severity_levels"].append(levels)

                # Extract query actions
                action_keywords = ["filtering", "ranking", "counting", "aggregating", "grouping"]
                for action in action_keywords:
                    if "action" in content and action in content:
                        context["query_actions"].append(action)

        # Remove duplicates and clean up
        for key in context:
            if isinstance(context[key], list):
                context[key] = list(set(context[key]))

        # Prioritize numeric hosts
        if context["hosts"]:
            numeric_hosts = [h for h in context["hosts"] if h.isdigit()]
            if numeric_hosts:
                context["hosts"] = numeric_hosts + [h for h in context["hosts"] if not h.isdigit()]

        return context

    def enhance_tool_parameters(self, tool_params: Dict[str, Any], suggested_filters: Dict[str, Any], suggested_time_range: str = None) -> Dict[str, Any]:
        """
        Enhance tool parameters with contextual filters and time range.

        Args:
            tool_params: Original tool parameters from LLM
            suggested_filters: Suggested filters from context
            suggested_time_range: Suggested time range from context

        Returns:
            Enhanced parameters with contextual filters merged
        """
        if not suggested_filters and not suggested_time_range:
            return tool_params

        enhanced_params = tool_params.copy()

        # Apply time_range if suggested - OVERRIDE any default time_range from LLM
        # Context preservation takes priority over LLM defaults
        if suggested_time_range:
            enhanced_params["time_range"] = suggested_time_range
            logger.info("Overriding time_range with context",
                       original=tool_params.get("time_range"),
                       suggested=suggested_time_range)

        # Merge filters
        if suggested_filters:
            if "filters" not in enhanced_params:
                enhanced_params["filters"] = {}

            for key, value in suggested_filters.items():
                # Add to filters (no longer handling time_range here)
                enhanced_params["filters"][key] = value

        applied_changes = []
        if suggested_time_range:
            applied_changes.append(f"time_range: {suggested_time_range}")
        if suggested_filters:
            applied_changes.extend([f"filter.{k}" for k in suggested_filters.keys()])

        logger.info("Enhanced tool parameters with context",
                   original_keys=list(tool_params.keys()),
                   applied_changes=applied_changes)

        return enhanced_params