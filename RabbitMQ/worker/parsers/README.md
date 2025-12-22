# Scan Result Parsers

This directory contains parser functions for converting raw scan results into human-readable, structured formats. Each parser extracts only the most important information and presents it in an easy-to-understand format.

## Available Parsers

- **MCP Parser** (`mcp_parser.py`) - Parses MCP (Model Context Protocol) scan results
- **Discovery Parser** (`discovery_parser.py`) - Parses AI agent discovery scan results
- **LLM Parser** (`llm_parser.py`) - Parses LLM security scan results (Garak)
- **IAC Parser** (`iac_parser.py`) - Parses Infrastructure as Code scan results
- **Gitleaks Parser** (`gitleaks_parser.py`) - Parses secret detection scan results
- **SBOM Parser** (`sbom_parser.py`) - Parses Software Bill of Materials/SCA scan results
- **SAST Parser** (`sast_parser.py`) - Parses Static Application Security Testing results

## Usage

### Automatic Detection and Parsing

The easiest way to use the parsers is with automatic detection:

```python
from parsers import parse_scan_results
import json

# Load raw results from file
with open("scan_results.json", "r") as f:
    raw_results = json.load(f)

# Automatically detect scan type and parse
parsed_results = parse_scan_results(raw_results)

# Or specify scan type explicitly
parsed_results = parse_scan_results(raw_results, scan_type="mcp")
```

### Individual Parser Usage

You can also use individual parsers directly:

```python
from parsers import parse_mcp_results, parse_discovery_results, parse_llm_results
import json

# MCP results
with open("mcp_results.json", "r") as f:
    mcp_raw = json.load(f)
mcp_parsed = parse_mcp_results(mcp_raw)

# Discovery results
with open("discovery_results.json", "r") as f:
    discovery_raw = json.load(f)
discovery_parsed = parse_discovery_results(discovery_raw)

# LLM results
with open("llm_results.json", "r") as f:
    llm_raw = json.load(f)
llm_parsed = parse_llm_results(llm_raw)
```

## Output Format

Each parser returns a dictionary with two main sections:

### 1. Summary
High-level statistics and counts:
- Total issues/vulnerabilities found
- Breakdown by severity, type, file, etc.
- Risk metrics

### 2. Detailed Results
Structured list of individual findings with:
- Human-readable descriptions
- Location information (file, line numbers)
- Severity/risk levels
- Relevant metadata

## Example Outputs

### MCP Parser Output
```python
{
    "summary": {
        "total_issues": 25,
        "by_severity": {"high": 10, "low": 15},
        "by_type": {"toxic_flow": 8, "unknown": 17},
        "by_server": {"playwright": 25},
        "error_messages": []
    },
    "issues": [
        {
            "code": "TF001",
            "message": "Data leak toxic flow detected...",
            "severity": "HIGH",
            "type": "Toxic Flow",
            "server": "playwright",
            "tool": {
                "name": "browser_console_messages",
                "description": "Returns all console messages"
            }
        }
    ]
}
```

### Discovery Parser Output
```python
{
    "summary": {
        "total_agents": 2,
        "by_risk": {"high": 1, "low": 1},
        "by_framework": {"Langchain": 2},
        "high_risk_agents": 1
    },
    "agents": [
        {
            "id": "de22a67efc3c0e5...",
            "file_path": "path/to/agent.py",
            "role": "AI Assistant",
            "system_prompt": "Code helper...",
            "framework": "Langchain",
            "risk": "HIGH",
            "risk_reason": "The agent has filesystem...",
            "tools": ["filesystem_read", "filesystem_write"],
            "tool_count": 2
        }
    ]
}
```

### LLM Parser Output
```python
{
    "summary": {
        "status": "completed",
        "model_name": "Custom openai",
        "total_tests": 16,
        "total_hits": 0,
        "hit_rate_percent": 0.0,
        "risk_level": "low",
        "probes_used": ["malwaregen.TopLevel"]
    },
    "probe_details": [
        {
            "probe": "malwaregen.TopLevel",
            "detector": "malwaregen.AnyCode",
            "passed": 16,
            "failed": 0,
            "total": 16,
            "hit_rate_percent": 0.0,
            "status": "PASSED"
        }
    ]
}
```

## Features

- **Human-readable**: All output uses clear, descriptive language
- **Structured**: Consistent format across all parsers
- **Summarized**: Quick overview with detailed breakdowns
- **Filtered**: Only important information is included
- **Safe**: Secrets are masked in Gitleaks parser output
- **Type-safe**: Proper type hints for all functions

## Error Handling

All parsers handle missing fields gracefully:
- Missing fields default to "Unknown" or appropriate defaults
- Empty lists/arrays are handled correctly
- Invalid data structures won't crash the parser

## Testing

Test files are available in the parent directory:
- `mcp_results_testing.json`
- `discovery_results_testing.json`
- `llm_results_testing.json`
- `iac_results_testing.json`
- `gitleaks_results_testing.json`
- `sbom_results_testing.json`

You can use these to test the parsers:

```python
from parsers import parse_scan_results
import json

with open("../mcp_results_testing.json", "r") as f:
    results = json.load(f)
    parsed = parse_scan_results(results, scan_type="mcp")
    print(json.dumps(parsed, indent=2))
```

