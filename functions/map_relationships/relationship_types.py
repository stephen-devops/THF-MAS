"""
Infer relationship types between network entities (host, user, process, file) based on Wazuh event data
"""
from typing import Dict, Any, Optional

# Sysmon Event ID to relationship type mappings
SYSMON_EVENT_RELATIONSHIPS = {
    "1": "creates",           # Process Create (process creates another process)
    "2": "modified",          # File Creation Time Changed
    "3": "connected_to",      # Network Connection
    "5": "terminates",        # Process Terminated (self-termination - no actor)
    "6": "loaded",            # Driver Loaded
    "7": "loaded",            # Image/DLL Loaded
    "8": "accesses",          # CreateRemoteThread (Process Injection - simplified to accesses)
    "10": "accesses",         # Process Access (will be refined by grantedAccess field)
    "11": "creates",          # File Create
    "12": "creates",          # Registry Create/Delete
    "13": "writes",           # Registry Set Value
    "15": "creates",          # File Create Stream
    "17": "creates",          # Pipe Created
    "18": "connected_to",     # Pipe Connected
    "22": "queried",          # DNS Query
    "23": "deletes",          # File Delete
    "26": "deletes",          # File Delete Detected
}

# Windows Security Event ID to relationship type mappings
WINDOWS_EVENT_RELATIONSHIPS = {
    "4624": "authenticated_as",   # Logon Success
    "4625": "failed_auth_as",     # Logon Failed
    "4648": "authenticated_as",   # Logon with Explicit Credentials
    "4672": "elevated_to",        # Special Privileges Assigned
    "4688": "creates",            # Process Creation (process creates another process)
    "4689": "terminates",         # Process Termination (self-termination - no actor)
    "4698": "created",            # Scheduled Task Created
    "4699": "deleted",            # Scheduled Task Deleted
    "4720": "created",            # User Account Created
    "4726": "deleted",            # User Account Deleted
    "5140": "accesses",           # Network Share Access
    "5145": "accesses",           # Network Share Detailed Access
    "5156": "connected_to",       # Network Connection Allowed
    "5157": "blocked_connection_to", # Network Connection Blocked
}

# Reverse relationship mappings (for bidirectional queries)
# Maps forward relationships to their reverse equivalents
REVERSE_RELATIONSHIP_MAPPING = {
    # Process relationships - forward vs reverse (SIMPLIFIED TO 3 TYPES)
    "creates": "created_by",           # Process created another → Process created by another
    "terminates": "terminated_by",     # Process terminated another → Process terminated by another
    "accesses": "accessed_by",         # Process accessed another → Process accessed by another

    # File operation relationships - forward vs reverse
    "creates": "created_by",           # Process creates file → File created by process
    "deletes": "deleted_by",           # Process deletes file → File deleted by process
    "writes": "written_by",            # Process writes to file → File written by process
    "reads": "read_by",                # Process reads file → File read by process
    "modifies": "modified_by",         # Process modifies file → File modified by process
    "modified": "modified_by",         # Process modified file → File modified by process
    "loads": "loaded_by",              # Process loads file → File loaded by process
    "loaded": "loaded_by",             # Process loaded file → File loaded by process
    "accesses": "accessed_by",         # Process accesses file → File accessed by process
    "accessed": "accessed_by",         # Process accessed file → File accessed by process

    # Authentication relationships - forward vs reverse
    "authenticated_as": "authenticated", # Process authenticated as user → User authenticated
    "failed_auth_as": "failed_auth",   # Process failed auth as user → User failed auth

    # Execution relationships - forward vs reverse
    "executed_by": "executes",         # Process executed by user → User executes process
    "launched": "launched_by",         # User launched process → Process launched by user

    # Host relationships - forward vs reverse
    "runs_on": "hosts",                # Process runs on host → Host hosts process
    "logged_into": "hosts_logon_from", # User logged into host → Host hosts logon from user
    "contains": "stored_on",           # Host contains file → File stored on host

    # Privilege relationships
    "elevated_to": "elevated_from",    # Elevated to user → Elevated from user
    "elevated_by": "elevated",         # Elevated by user → User elevated

    # Ownership relationships
    "owns": "owned_by",                # User owns file → File owned by user
    "owned_by": "owns",                # File owned by user → User owns file
}

# Bidirectional relationships (same in both directions)
BIDIRECTIONAL_RELATIONSHIPS = [
    "connected_to",
    "interacts_with"
]


def get_reverse_relationship(relationship: str) -> str:
    """
    Get the reverse relationship type for bidirectional queries

    Args:
        relationship: Forward relationship type (e.g., 'spawned', 'creates')

    Returns:
        Reverse relationship type (e.g., 'spawned_by', 'created_by')
    """
    # Check if it's a bidirectional relationship (same in both directions)
    if relationship in BIDIRECTIONAL_RELATIONSHIPS:
        return relationship

    # Look up reverse mapping
    return REVERSE_RELATIONSHIP_MAPPING.get(relationship, relationship)


def _validate_relationship_for_pair(
    relationship: str,
    source_type: str,
    target_type: str
) -> bool:
    """
    Validate if a relationship type makes sense for the (source, target) entity pair

    Args:
        relationship: Relationship type label (e.g., 'spawned', 'creates')
        source_type: Source entity type (process, host, user, file)
        target_type: Target entity type (process, host, user, file)

    Returns:
        True if the relationship is valid for this (source, target) pair, False otherwise
    """
    if not target_type:
        # If target_type is None (all relationships), accept the relationship
        return True

    source = source_type.lower() if source_type else ""
    target = target_type.lower()

    # Define which relationships are valid for which (source, target) pairs
    # Format: relationship: [(source, target), ...]
    valid_mappings = {
        # Process → Process relationships (SIMPLIFIED TO 3 TYPES)
        "creates": [("process", "process")],
        "created_by": [("process", "process")],
        "terminates": [("process", "process")],
        "terminated_by": [("process", "process")],
        "accesses": [("process", "process"), ("process", "file"), ("user", "file")],
        "accessed_by": [("process", "process"), ("file", "process"), ("file", "user")],
        "interacts_with": [("process", "process")],

        # Process → File relationships
        "creates": [("process", "file")],
        "deletes": [("process", "file")],
        "writes": [("process", "file")],
        "reads": [("process", "file")],
        "modifies": [("process", "file")],
        "modified": [("process", "file")],
        "loads": [("process", "file")],
        "loaded": [("process", "file")],
        "accesses": [("process", "file"), ("process", "process"), ("user", "file")],

        # File → Process relationships (reverse)
        "created_by": [("file", "process")],
        "deleted_by": [("file", "process")],
        "written_by": [("file", "process")],
        "read_by": [("file", "process")],
        "modified_by": [("file", "process")],
        "loaded_by": [("file", "process")],
        "accessed_by": [("file", "process"), ("file", "user")],

        # Process → User relationships
        "authenticated_as": [("process", "user")],  # ONLY Process → User
        "failed_auth_as": [("process", "user")],
        "elevated_to": [("process", "user")],
        "elevated_by": [("process", "user")],
        "executed_by": [("process", "user")],

        # User → Process relationships (reverse)
        "authenticated": [("user", "process")],
        "failed_auth": [("user", "process")],
        "elevated": [("user", "process")],
        "elevated_from": [("user", "process")],
        "executes": [("user", "process"), ("host", "process")],
        "launched": [("user", "process")],
        "launched_by": [("process", "user")],

        # Process → Host relationships
        "runs_on": [("process", "host")],

        # Host → Process relationships
        "hosts": [("host", "process"), ("host", "user"), ("host", "file")],

        # User → Host relationships
        "logged_into": [("user", "host")],
        "hosts_logon_from": [("host", "user")],  # Reverse: Host received logon from user

        # Host → File relationships
        "contains": [("host", "file")],
        "stored_on": [("file", "host")],

        # User → File relationships
        "owns": [("user", "file")],
        "owned_by": [("file", "user")],

        # Generic relationships (multiple valid pairs)
        "accessed": [("process", "file"), ("user", "file"), ("user", "host"), ("process", "host"), ("process", "process")],
        "connected_to": [("process", "host"), ("process", "process"), ("user", "host"), ("file", "host")],
        "blocked_connection_to": [("process", "host")],
        "queried": [("process", "host")],
        "created": [("process", "file"), ("user", "user")],
        "deleted": [("process", "file"), ("user", "user")],
    }

    # Check if this relationship is valid for the (source, target) pair
    valid_pairs = valid_mappings.get(relationship)

    # If relationship not in mapping, accept it (unknown relationship types pass through)
    if valid_pairs is None:
        return True

    # Check if (source, target) pair is in the list of valid pairs
    return (source, target) in valid_pairs


def _parse_granted_access_for_event_id_10(event_data: Dict[str, Any]) -> Optional[str]:
    """
    Parse grantedAccess field for Sysmon Event ID 10 (ProcessAccess)
    to distinguish between "terminates" and generic "accesses"

    SIMPLIFIED: Only checks for PROCESS_TERMINATE (0x0001) bit
    - If TERMINATE bit is set → "terminates"
    - Otherwise → None (falls back to generic "accesses")

    Args:
        event_data: Wazuh alert event data

    Returns:
        "terminates" if PROCESS_TERMINATE access, None for generic "accesses"
    """
    win_eventdata = event_data.get("data", {}).get("win", {}).get("eventdata", {})
    granted_access = win_eventdata.get("grantedAccess", "")

    if not granted_access:
        return None

    try:
        # Parse hex value (e.g., "0x1400" or "1400")
        if granted_access.startswith("0x") or granted_access.startswith("0X"):
            access_int = int(granted_access, 16)
        else:
            # Try parsing as hex without 0x prefix
            try:
                access_int = int(granted_access, 16)
            except ValueError:
                # If that fails, try decimal
                access_int = int(granted_access)

        # SIMPLIFIED: Only check for PROCESS_TERMINATE (0x0001)
        if access_int & 0x0001:
            return "terminates"

        # For all other access types → None (falls back to generic "accesses")
        return None

    except (ValueError, TypeError):
        # If we can't parse the access value, return None (fall back to generic "accesses")
        return None


def infer_relationship_type(
    source_type: str,
    target_type: str,
    event_data: Dict[str, Any]
) -> str:
    """
    Infer the relationship type based on entity types and Wazuh event data

    Args:
        source_type: Source entity type (process, host, user, file)
        target_type: Target entity type (process, host, user, file)
        event_data: Wazuh alert event data containing rule groups, event IDs, etc.

    Returns:
        Relationship label (e.g., 'creates', 'executes', 'runs_on', 'executed_by')
    """
    # Extract event metadata
    win_system = event_data.get("data", {}).get("win", {}).get("system", {})
    event_id = win_system.get("eventID")
    rule_groups = event_data.get("rule", {}).get("groups", [])
    rule_description = event_data.get("rule", {}).get("description", "").lower()

    # Priority 1: Check Sysmon Event ID first (most specific)
    # SPECIAL CASE: Event ID 10 (ProcessAccess) - check grantedAccess field for specific relationship
    if event_id == "10" and source_type.lower() == "process" and target_type.lower() == "process":
        specific_relationship = _parse_granted_access_for_event_id_10(event_data)
        if specific_relationship:
            # Validate the specific relationship is valid for process-to-process
            if _validate_relationship_for_pair(specific_relationship, source_type, target_type):
                return specific_relationship
        # If no specific relationship found, fall through to default "accessed"

    # Continue with normal Event ID mapping
    if event_id and event_id in SYSMON_EVENT_RELATIONSHIPS:
        relationship = SYSMON_EVENT_RELATIONSHIPS[event_id]

        # Validate relationship against (source, target) entity pair
        if _validate_relationship_for_pair(relationship, source_type, target_type):
            return relationship
        # If invalid, fall through to next priority

    # Priority 2: Check Windows Security Event ID
    if event_id and event_id in WINDOWS_EVENT_RELATIONSHIPS:
        relationship = WINDOWS_EVENT_RELATIONSHIPS[event_id]

        # Validate relationship against (source, target) entity pair
        if _validate_relationship_for_pair(relationship, source_type, target_type):
            return relationship
        # If invalid, fall through to next priority

    # Priority 3: Infer from rule description keywords
    keyword_relationship = _infer_from_keywords(source_type, target_type, rule_description, rule_groups)
    if keyword_relationship:
        return keyword_relationship

    # Priority 4: Fallback to entity-type based inference
    return _infer_by_entity_types(source_type, target_type, rule_groups, rule_description)


def _infer_from_keywords(
    source_type: str,
    target_type: str,
    rule_description: str,
    rule_groups: list
) -> Optional[str]:
    """
    Infer relationship from rule description keywords

    Args:
        source_type: Source entity type
        target_type: Target entity type
        rule_description: Lowercase rule description
        rule_groups: Rule group classifications

    Returns:
        Relationship type or None if no clear match
    """
    # File operations - CONTEXT-AWARE
    if any(kw in rule_description for kw in ["file created", "file dropped", "dropped"]):
        if source_type.lower() == "process" and target_type.lower() == "file":
            return "creates"
        return None
    elif any(kw in rule_description for kw in ["file deleted", "removed"]):
        if source_type.lower() == "process" and target_type.lower() == "file":
            return "deletes"
        return None
    elif any(kw in rule_description for kw in ["file modified", "modified", "changed"]):
        if source_type.lower() == "process" and target_type.lower() == "file":
            return "modifies"
        return None
    elif any(kw in rule_description for kw in ["file read", "accessed", "opened"]):
        if source_type.lower() == "process" and target_type.lower() == "file":
            return "reads"
        elif source_type.lower() == "user" and target_type.lower() == "file":
            return "accessed"
        return None
    elif "wrote" in rule_description or "written" in rule_description:
        if source_type.lower() == "process" and target_type.lower() == "file":
            return "writes"
        return None

    # Process operations - CONTEXT-AWARE
    elif any(kw in rule_description for kw in ["process created", "new process", "spawned", "launched"]):
        # Only Process → Process or User → Process makes sense
        if source_type.lower() == "process" and target_type.lower() == "process":
            return "creates"  # SIMPLIFIED: spawned → creates
        elif source_type.lower() == "user" and target_type.lower() == "process":
            return "launched"
        return None
    elif any(kw in rule_description for kw in ["process terminated", "killed", "ended"]):
        if source_type.lower() == "process" and target_type.lower() == "process":
            return "terminates"  # SIMPLIFIED: terminated → terminates
        return None
    elif "executed" in rule_description or "execution" in rule_description:
        # Process executed by user, or host executes process
        if source_type.lower() == "process" and target_type.lower() == "user":
            return "executed_by"
        elif source_type.lower() == "user" and target_type.lower() == "process":
            return "executes"
        elif source_type.lower() == "host" and target_type.lower() == "process":
            return "executes"
        return None

    # DLL/Module operations - CONTEXT-AWARE
    elif "loaded" in rule_description or "dll" in rule_description:
        if source_type.lower() == "process" and target_type.lower() == "file":
            return "loads"
        return None

    # Authentication operations - CONTEXT-AWARE
    elif any(kw in rule_description for kw in ["logon success", "login success", "authenticated"]):
        # Process → User: authenticated_as
        # Host → User: hosts_logon_from
        # User → Host: logged_into
        if source_type.lower() == "process" and target_type.lower() == "user":
            return "authenticated_as"
        elif source_type.lower() == "host" and target_type.lower() == "user":
            return "hosts_logon_from"
        elif source_type.lower() == "user" and target_type.lower() == "host":
            return "logged_into"
        # Default for other pairs: skip this keyword match
        return None
    elif any(kw in rule_description for kw in ["logon fail", "login fail", "authentication fail"]):
        if source_type.lower() == "process" and target_type.lower() == "user":
            return "failed_auth_as"
        elif source_type.lower() == "host" and target_type.lower() == "user":
            return "hosts_logon_from"  # Still a logon attempt
        return None
    elif "privilege" in rule_description or "elevation" in rule_description:
        if source_type.lower() == "process" and target_type.lower() == "user":
            return "elevated_to"
        return None

    # Network operations
    elif "connection" in rule_description or "connected" in rule_description:
        return "connected_to"

    return None


def _infer_by_entity_types(
    source_type: str,
    target_type: str,
    rule_groups: list,
    rule_description: str
) -> str:
    """
    Infer relationship based on entity type combinations

    Args:
        source_type: Source entity type
        target_type: Target entity type
        rule_groups: Rule group classifications
        rule_description: Lowercase rule description

    Returns:
        Relationship type label
    """
    source = source_type.lower()
    target = target_type.lower()

    # Process → Host
    if source == "process" and target == "host":
        return "runs_on"

    # Process → User
    elif source == "process" and target == "user":
        if any(g in rule_groups for g in ["authentication", "authentication_success"]):
            return "authenticated_as"
        elif any(g in rule_groups for g in ["authentication_failed", "authentication_failures"]):
            return "failed_auth_as"
        elif "privilege" in rule_description or "elevation" in rule_description:
            return "elevated_to"  # FIXED: was "elevated_by"
        else:
            return "executed_by"

    # Process → Process (SIMPLIFIED TO 3 TYPES: creates, accesses, terminates)
    elif source == "process" and target == "process":
        if "inject" in rule_description or "remote" in rule_description:
            return "accesses"  # SIMPLIFIED: injected_into → accesses
        elif "terminate" in rule_description or "kill" in rule_description:
            return "terminates"  # SIMPLIFIED: terminated → terminates
        else:
            return "creates"  # SIMPLIFIED: spawned → creates

    # Process → File
    elif source == "process" and target == "file":
        # Check for specific file operations in rule groups
        if any("file" in g for g in rule_groups):
            if "delete" in rule_description:
                return "deletes"
            elif "modify" in rule_description or "write" in rule_description:
                return "writes"
            elif "read" in rule_description or "access" in rule_description:
                return "reads"
            elif "create" in rule_description or "drop" in rule_description:
                return "creates"
        # Default for process-file
        return "accesses"

    # Host → User
    elif source == "host" and target == "user":
        # Check for authentication events
        if any(g in rule_groups for g in ["authentication", "authentication_success", "logon"]):
            return "hosts_logon_from"  # Host received logon from user
        return "hosts"  # Generic: Host hosts user account

    # Host → Process
    elif source == "host" and target == "process":
        return "executes"

    # Host → File
    elif source == "host" and target == "file":
        return "contains"

    # User → Host
    elif source == "user" and target == "host":
        if any(g in rule_groups for g in ["authentication", "logon", "login"]):
            return "logged_into"
        return "accessed"

    # User → Process
    elif source == "user" and target == "process":
        return "launched"

    # User → File
    elif source == "user" and target == "file":
        # FIXED: Check for explicit ownership keywords first
        # "owns" should only be used for explicit ownership events (rare in Wazuh)
        if any(kw in rule_description for kw in ["owner", "ownership", "owns"]):
            return "owns"
        # Default: "accessed" is far more common and semantically correct
        # Most User→File events are access/modification, not ownership changes
        return "accessed"

    # File → Process
    elif source == "file" and target == "process":
        # File operations on process (loaded, executed)
        if "load" in rule_description or "dll" in rule_description or "module" in rule_description:
            return "loaded_by"
        return "loaded_by"  # Default: file loaded by process

    # File → Host
    elif source == "file" and target == "host":
        return "stored_on"

    # File → User
    elif source == "file" and target == "user":
        # FIXED: To match User→File default of "accessed", use "accessed_by" as default
        # Only use "owned_by" if explicitly about ownership in rule description
        if any(kw in rule_description for kw in ["owner", "ownership", "owns"]):
            return "owned_by"
        return "accessed_by"  # Default: reverse of User→File "accessed"

    # Default fallback
    else:
        return "connected_to"


def get_relationship_description(relationship_type: str) -> str:
    """
    Get human-readable description of relationship type

    Args:
        relationship_type: Relationship type label

    Returns:
        Human-readable description
    """
    descriptions = {
        # Forward Process → Process relationships (SIMPLIFIED TO 3 TYPES)
        "creates": "Process created another process",
        "terminates": "Process terminated another process",
        "accesses": "Process accessed another process",

        # Reverse Process → Process relationships
        "created_by": "Process created by another process",
        "terminated_by": "Process terminated by another process",
        "accessed_by": "Process accessed by another process",

        # Process → Other entities
        "runs_on": "Process executes on host",
        "executed_by": "Process executed by user",
        "deletes": "Process deleted file",
        "writes": "Process wrote to file",
        "reads": "Process read from file",
        "modifies": "Process modified file",
        "loads": "Process loaded library/module",
        "created_by": "File created by process",
        "deleted_by": "File deleted by process",
        "written_by": "File written by process",
        "read_by": "File read by process",
        "modified_by": "File modified by process",
        "loaded_by": "File loaded by process",
        "accessed_by": "File accessed by process",

        # Forward Authentication relationships
        "authenticated_as": "Successful authentication as user",
        "failed_auth_as": "Failed authentication attempt as user",
        "elevated_to": "Privilege elevation to user context",
        "elevated_by": "Privilege elevation by user",

        # Reverse Authentication relationships
        "authenticated": "User authenticated",
        "failed_auth": "User failed authentication",
        "elevated_from": "Privilege elevated from user",
        "elevated": "User performed privilege elevation",

        # Forward Host relationships
        "hosts": "Host contains entity",
        "executes": "Entity executes process",
        "contains": "Host stores file",

        # Reverse Host relationships
        "hosts_logon_from": "Host received logon from user",

        # Forward User relationships
        "logged_into": "User logged into host",
        "launched": "User launched process",
        "owns": "User owns file",

        # Reverse User relationships
        "launched_by": "Process launched by user",

        # Network relationships
        "connected_to": "Network connection established",
        "blocked_connection_to": "Network connection blocked",

        # File relationships
        "stored_on": "File stored on host",
        "owned_by": "File owned by user",

        # Generic access relationships
        "accessed": "Entity accessed another entity (file access, host access, etc.)",
        "accessed_by": "Entity accessed by another entity",
        "interacts_with": "Entity interacts with another entity",
    }

    return descriptions.get(relationship_type, f"Related via {relationship_type}")


def get_relationship_directionality(relationship_type: str) -> str:
    """
    Determine if relationship is directional or bidirectional

    Args:
        relationship_type: Relationship type label

    Returns:
        'directional' or 'bidirectional'
    """
    # Most relationships are directional (A → B is different from B → A)
    bidirectional = ["connected_to", "interacts_with"]

    if relationship_type in bidirectional:
        return "bidirectional"
    return "directional"
