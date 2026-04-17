# Entity Relationships Guide

## Overview

The **Entity-to-Entity** relationship mapping functionality analyzes connections between security entities in your Wazuh SIEM environment. It automatically discovers and analyzes relationships based on Windows event logs (Sysmon and Windows Security events) to help you understand how different entities interact with each other.

## Supported Entity Types

The system supports four core entity types:

| Entity Type | Description | Examples |
|-------------|-------------|----------|
| **Process** | Windows processes and applications | `powershell.exe`, `cmd.exe`, `svchost.exe`, `C:\Windows\System32\notepad.exe` |
| **Host** | Network hosts/machines (agents) | `WIN-SERVER-01`, `U209-PC-BLEE`, `192.168.1.100` |
| **User** | User accounts (local or domain) | `SYSTEM`, `Administrator`, `DOMAIN\john.doe` |
| **File** | Files, executables, and DLLs | `malware.exe`, `config.dll`, `C:\Users\Admin\document.txt` |

## How Relationships Work

### Bidirectional Queries

The system supports **bidirectional relationship mapping**, which provides two perspectives:

1. **Outbound Relationships**: What the source entity does TO other entities
   - Example: "What processes did `powershell.exe` create?"

2. **Inbound Relationships**: What other entities do TO the source entity
   - Example: "What processes created `cmd.exe`?"

### Relationship Inference

Relationships are automatically inferred from:
- **Sysmon Event IDs** (1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 17, 18, 22, 23, 26)
- **Windows Security Event IDs** (4624, 4625, 4648, 4672, 4688, 4689, 4698, 4699, 4720, 4726, 5140, 5145, 5156, 5157)
- **Rule descriptions and keywords** (for additional context)

## Supported Relationships by Entity Pair

### Process ↔ Process

**Outbound (Process → Process):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `creates` | Process created child process | Sysmon 1, Windows 4688 |
| `terminates` | Process terminated another process | Sysmon 5, Windows 4689, Sysmon 10 (with TERMINATE access) |
| `accesses` | Process accessed/injected into another | Sysmon 8 (CreateRemoteThread), Sysmon 10 (ProcessAccess) |

**Inbound (Process ← Process):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `created_by` | Process created by parent process | Sysmon 1, Windows 4688 |
| `terminated_by` | Process terminated by another process | Sysmon 5, Windows 4689, Sysmon 10 |
| `accessed_by` | Process accessed/injected by another process | Sysmon 8, Sysmon 10 |

**Example Queries:**
- "What processes did `powershell.exe` create in the last 4 hours?"
- "Show me processes that were created by `explorer.exe` today."
- "Which processes accessed `lsass.exe` on Aug 21 2025 at 15:07:03?"
- "Show me a process injecting into another process on Aug 13 2025."

---

### Process ↔ File

**Outbound (Process → File):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `creates` | Process created file | Sysmon 11, 15 |
| `deletes` | Process deleted file | Sysmon 23, 26 |
| `writes` | Process wrote to file | Registry Value Set (Sysmon 13) |
| `reads` | Process read from file | File access events |
| `modifies` | Process modified file | Sysmon 2 (File time changed) |
| `loads` | Process loaded DLL/module | Sysmon 6, 7 |
| `accesses` | Process accessed file (generic) | Sysmon events |

**Inbound (File ← Process):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `created_by` | File created by process | Sysmon 11, 15 |
| `deleted_by` | File deleted by process | Sysmon 23, 26 |
| `written_by` | File written by process | Sysmon 13 |
| `read_by` | File read by process | File access events |
| `modified_by` | File modified by process | Sysmon 2 |
| `loaded_by` | DLL/module loaded by process | Sysmon 6, 7 |
| `accessed_by` | File accessed by process | Sysmon events |

**Example Queries:**
- "What files were deleted by process `TiWorker.exe` on May 15 2025?"
- "What files were modified by process `dismhost.exe` on Nov 9 2024?"
- "Show me all files accessed by processes in the last 12 hours."
- "Show me all files that were loaded by the `svchost.exe` process over the past 6 hours."

---

### Process ↔ User

**Outbound (Process → User):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `executed_by` | Process launched by user | Process execution context |
| `authenticated_as` | Successful authentication as user | Windows 4624, 4648 |
| `failed_auth_as` | Failed authentication attempt | Windows 4625 |
| `elevated_to` | Privilege elevation to user context | Windows 4672 |

**Inbound (User ← Process):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `executes` | User executes/launched process | Process execution context |
| `authenticated` | User successfully authenticated | Windows 4624, 4648 |
| `failed_auth` | User failed authentication | Windows 4625 |
| `elevated` | User performed privilege elevation | Windows 4672 |

**Example Queries:**
- "What processes did user `SYSTEM` execute today?"
- "Show me all authentication attempts by user `Administrator` in the past 24 hours."
- "Which users have executed `cmd.exe` this week?"

---

### Process ↔ Host

**Outbound (Process → Host):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `runs_on` | Process executes on host | All process events |

**Inbound (Host ← Process):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `hosts` | Host contains/runs process | All process events |
| `executes` | Host executes process | Sysmon 1, Windows 4688 |

**Example Queries:**
- "Show me all processes hosted on host `U209-PC-BLEE` for today."
- "What processes are running on host `WIN-SERVER-01`?"

---

### Host ↔ User

**Outbound (Host → User):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `hosts` | Host contains user account | General host context |
| `hosts_logon_from` | Host received logon from user | Windows 4624 (authentication events) |

**Inbound (User ← Host):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `logged_into` | User authenticated to host | Windows 4624 |
| `accessed` | User accessed host | General access events |

**Example Queries:**
- "Show me all entity connections to host `U209-PC-BLEE` for today."
- "Which users have accessed host with IP `192.168.201.33` in the past 24 hours?"
- "Show me what hosts user `SYSTEM` has connected to this week."
- "Which users have the strongest connection to host `win10-02` in the past two days?"

---

### User ↔ File

**Outbound (User → File):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `accessed` | User accessed file (most common) | Windows 5140, 5145 (share access) |
| `owns` | User owns file (rare, explicit ownership events only) | File ownership events |

**Inbound (File ← User):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `accessed_by` | File accessed by user | Windows 5140, 5145 |
| `owned_by` | File owned by user (rare) | File ownership events |

**Example Queries:**
- "Show me files accessed by user `SYSTEM` in the last 6 hours."
- "Which users have accessed sensitive configuration files today?"

---

### Host ↔ File

**Outbound (Host → File):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `contains` | Host stores file | All file events |

**Inbound (File ← Host):**
| Relationship | Description | Event IDs |
|--------------|-------------|-----------|
| `stored_on` | File stored on host | All file events |

---

## Query Syntax Examples

### Basic Entity Relationships

Get all relationships for a specific entity:
```
"Analyse relationships between powershell.exe and other entities in the last 4 hours."
"Show me all entity relationships to svchost.exe over this time window."
```

### Specific Entity Pairs

Query relationships between specific entity types:
```
"What processes did SYSTEM user execute?"
"Which files were created by cmd.exe?"
"Show me all processes hosted on WIN-SERVER-01."
```

### Temporal Filtering

Add time constraints to your queries:
```
"Show me processes created in the last 24 hours."
"What files were deleted by TiWorker.exe on May 15 2025?"
"Which users logged into host U209-PC-BLEE today?"
```

### Network Relationships

Query network-related connections:
```
"Show me all network connections to this svchost.exe process over this time window."
```

### Risk Analysis

Calculate relationship risk scores:
```
"Calculate relationship risk scores for host U209-PC-BLEE over the past 4 hours."
```

## Understanding the Response

### Relationship Data Structure

Each relationship includes:

- **source_entity**: The entity initiating the relationship (type + id)
- **target_entity**: The entity receiving the relationship (type + id)
- **relationship_type**: The type of relationship (e.g., `creates`, `executed_by`)
- **relationship_description**: Human-readable description
- **connection_strength**: Number of occurrences/events (higher = more frequent)
- **connection_types**: Rule groups involved (e.g., `sysmon`, `windows`)
- **temporal_pattern**: Time distribution of the relationship
- **latest_connection**: Most recent occurrence with details
- **avg_severity**: Average alert severity for this relationship
- **relationship_score**: Calculated risk score (0-100)
- **risk_assessment**: Risk level (Low, Medium, High, Critical)
- **direction**: Whether this is "outbound" or "inbound"

### Summary Statistics

The response also includes:
- **total_connections**: Total number of relationship events
- **unique_targets**: Count of distinct target entities
- **avg_connection_strength**: Average connection frequency
- **risk_distribution**: Breakdown of relationships by risk level
- **high_risk_relationships**: Count of Critical/High risk relationships

## Special Features

### Automatic Event ID Handling

The system automatically handles different Windows event types:

**Sysmon Events:**
- Event ID 1: Process creation
- Event ID 8: Process injection (CreateRemoteThread)
- Event ID 10: Process access (with granular access right detection)
- Event ID 11: File creation
- Event ID 23/26: File deletion
- And many more...

**Windows Security Events:**
- Event ID 4624: Successful logon
- Event ID 4625: Failed logon
- Event ID 4688: Process creation
- Event ID 4672: Special privileges assigned
- And many more...

### Process Injection Detection

For Sysmon Event ID 8 and 10, the system:
- Uses `sourceImage` and `targetImage` fields
- Detects specific access rights (e.g., PROCESS_TERMINATE = 0x0001)
- Differentiates between termination vs generic access

### Field Flexibility

The system uses intelligent field detection to handle:
- Multiple process field names (`image`, `sourceImage`, `targetImage`, `parentImage`)
- Multiple user field names (`user`, `targetUserName`, `subjectUserName`)
- Wildcard matching for partial entity names

## Best Practices

1. **Use Specific Entity IDs**: Provide full paths for processes when possible
   - Good: `C:\Windows\System32\cmd.exe`
   - Also works: `cmd.exe` (will use wildcard matching)

2. **Specify Time Ranges**: Narrow down queries with temporal constraints
   - `"in the last 24 hours"`
   - `"on May 15 2025"`
   - `"this week"`

3. **Leverage Bidirectionality**: Think about both directions
   - "What did X create?" (outbound)
   - "What created X?" (inbound)

4. **Review Risk Scores**: Focus on high-risk relationships first
   - Risk factors: connection strength, severity, connection types

5. **Check Connection Strength**: High values may indicate:
   - Normal automated behavior
   - Potential compromise or abuse

## Limitations

- Relationships are based on alerts/events logged by Wazuh
- Not all Windows events generate Sysmon/Security logs
- Relationship inference depends on event data quality
- Very high connection volumes (>200) may need investigation for accuracy

## Technical Notes

- Relationships use **OpenSearch aggregations** for performance
- Supports up to 100 entities per aggregation bucket
- Temporal distribution uses 1-hour intervals
- Risk scoring combines connection strength, severity, and event types
