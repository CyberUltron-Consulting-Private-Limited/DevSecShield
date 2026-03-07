# GVM (Greenbone Vulnerability Management) - Complete Technical Guide

## Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Container Deep Dive](#container-deep-dive)
4. [Data Flow & Protocols](#data-flow--protocols)
5. [Vulnerability Feeds](#vulnerability-feeds)
6. [Configuration Parameters](#configuration-parameters)
7. [Scan Configurations](#scan-configurations)
8. [Python Scanner API](#python-scanner-api)
9. [Output Format](#output-format)
10. [Maintenance & Operations](#maintenance--operations)
11. [Troubleshooting](#troubleshooting)
12. [Security Considerations](#security-considerations)

---

## Overview

**GVM (Greenbone Vulnerability Management)** is the world's most advanced open-source vulnerability scanner. It performs automated security audits by testing systems against a constantly updated database of **170,000+ Network Vulnerability Tests (NVTs)**.

### What GVM Does

1. **Network Discovery** - Identifies live hosts, open ports, running services
2. **Vulnerability Detection** - Tests for known CVEs, misconfigurations, weak credentials
3. **Compliance Checking** - Validates against security standards (CIS, DISA STIG)
4. **Risk Assessment** - Assigns severity scores (CVSS) to findings

### RedAmon Integration

RedAmon uses GVM in **headless API mode** (no web GUI) to:
- Consume reconnaissance data (IPs, hostnames from recon output)
- Automatically create scan targets and tasks via the Python GMP API
- Execute vulnerability scans and stream logs in real-time to the webapp
- Save structured JSON results (`gvm_scan/output/gvm_{projectId}.json`)
- Update the Neo4j graph with Vulnerability nodes (source="gvm"), CVE nodes, and relationships to IP/Subdomain nodes

**Webapp integration:** GVM scans are triggered from the Graph page via a dedicated "GVM Scan" button. The button is only enabled when recon data exists for the project. Logs stream in real-time to a log drawer with 4-phase progress (Loading Recon Data → Connecting to GVM → Scanning IPs → Scanning Hostnames). Results can be downloaded as JSON from the toolbar.

**Architecture:** The scan flow mirrors the recon pipeline: Webapp API → Recon Orchestrator → Docker container (`redamon-vuln-scanner`) → SSE log streaming → graph update.

> **Note:** The GVM infrastructure (`docker-compose.yml` for gvmd, ospd-openvas, redis, pg-gvm, etc.) is located in the `gvm_scan/` directory and runs separately. The Python scanner container is built and managed by the main `docker-compose.yml` at the project root.

---

## System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              RedAmon GVM Architecture                               │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│   ┌─────────────────┐                                                               │
│   │   RECON DATA    │  JSON input from Phase 1                                      │
│   │  (IPs, Hosts)   │  └── recon/output/recon_*.json                                │
│   └────────┬────────┘                                                               │
│            │                                                                        │
│            ▼                                                                        │
│   ┌─────────────────┐     Unix Socket      ┌─────────────────┐                      │
│   │  PYTHON SCANNER │────────────────────▶│      GVMD       │                      │
│   │   (redamon-     │   GMP Protocol       │   (Manager)     │                      │
│   │  vuln-scanner)  │   /run/gvmd/         │                 │                      │
│   └─────────────────┘   gvmd.sock          └────────┬────────┘                      │
│            │                                        │                               │
│            │                                        │ OSP Protocol                  │
│            │                                        │ /run/ospd/ospd-openvas.sock   │
│            │                                        ▼                               │
│            │                               ┌─────────────────┐                      │
│            │                               │  OSPD-OPENVAS   │                      │
│            │                               │  (Scanner)      │──────┐               │
│            │                               └─────────────────┘      │               │
│            │                                        │               │               │
│            │                    ┌───────────────────┼───────────────┤               │
│            │                    │                   │               │               │
│            │                    ▼                   ▼               ▼               │
│            │           ┌──────────────┐    ┌──────────────┐  ┌──────────────┐       │
│            │           │  POSTGRESQL  │    │    REDIS     │  │    NOTUS     │       │
│            │           │  (Database)  │    │   (Cache)    │  │  (Scanner)   │       │
│            │           └──────────────┘    └──────────────┘  └──────────────┘       │
│            │                                                                        │
│            ▼                                                                        │
│   ┌─────────────────┐                                                               │
│   │   JSON OUTPUT   │  Structured vulnerability report                              │
│   │                 │  └── gvm_scan/output/gvm_*.json                              │
│   └─────────────────┘                                                               │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### Communication Protocols

| Protocol | Purpose | Transport |
|----------|---------|-----------|
| **GMP** (Greenbone Management Protocol) | Python ↔ GVMD communication | Unix Socket (XML-based) |
| **OSP** (Open Scanner Protocol) | GVMD ↔ OSPD-OpenVAS | Unix Socket |
| **MQTT** | OSPD ↔ Notus Scanner | Internal message queue |

---

## Container Deep Dive

### Runtime Containers (Always Running)

#### 1. **redamon-gvm-gvmd** (Greenbone Vulnerability Manager Daemon)

| Property | Value |
|----------|-------|
| Image | `registry.community.greenbone.net/community/gvmd:stable` |
| Role | **Central Orchestrator** |
| Memory | 300-800 MB |

**What it does:**
- **Task Management**: Creates, schedules, monitors scan tasks
- **Target Management**: Stores scan targets (IPs, hostnames, credentials)
- **Result Storage**: Persists scan results to PostgreSQL
- **User Management**: Authentication, permissions, roles
- **API Server**: Exposes GMP protocol via Unix socket (`/run/gvmd/gvmd.sock`)
- **Feed Sync**: Coordinates NVT updates with OSPD-OpenVAS
- **Report Generation**: Creates reports in multiple formats

**Key Processes:**
```
gvmd (main process)
  ├── listens on /run/gvmd/gvmd.sock (GMP API)
  ├── connects to PostgreSQL for data storage
  ├── connects to /run/ospd/ospd-openvas.sock (scanner control)
  └── manages scheduled tasks and feed updates
```

**Important Files:**
- `/run/gvmd/gvmd.sock` - GMP API socket
- `/var/lib/gvm/` - GVM data directory

---

#### 2. **redamon-gvm-ospd** (OSPd-OpenVAS Scanner Daemon)

| Property | Value |
|----------|-------|
| Image | `registry.community.greenbone.net/community/ospd-openvas:stable` |
| Role | **Vulnerability Scanner Engine** |
| Memory | 500 MB - 2 GB (during scans) |

**What it does:**
- **NVT Loading**: Loads 170,000+ vulnerability test scripts from Redis
- **Scan Execution**: Runs actual network probes against targets
- **Result Collection**: Aggregates findings and sends to GVMD
- **Process Management**: Spawns OpenVAS scanner processes

**How scanning works internally:**
```
1. GVMD sends scan request via OSP socket
2. OSPD-OpenVAS loads required NVTs from Redis
3. Spawns OpenVAS process for each target
4. OpenVAS executes NVT scripts:
   - Port scanning (TCP/UDP)
   - Service detection
   - Version fingerprinting
   - Vulnerability checks
   - Authentication tests
5. Results streamed back to GVMD
```

**Required Capabilities:**
```yaml
cap_add:
  - NET_ADMIN    # Raw socket access for network scanning
  - NET_RAW      # ICMP ping, SYN scans
security_opt:
  - seccomp=unconfined    # Required for low-level network operations
  - apparmor=unconfined
```

---

#### 3. **redamon-gvm-postgres** (PostgreSQL Database)

| Property | Value |
|----------|-------|
| Image | `registry.community.greenbone.net/community/pg-gvm:stable` |
| Role | **Persistent Data Store** |
| Memory | 200-500 MB |
| Storage | 3-5 GB |

**What it stores:**

| Table Category | Contents |
|----------------|----------|
| **nvts** | 170,000+ vulnerability test definitions |
| **configs** | Scan configurations (Full and fast, Discovery, etc.) |
| **targets** | Scan targets (IPs, hostnames, port lists) |
| **tasks** | Scan task definitions and schedules |
| **results** | Vulnerability findings |
| **reports** | Generated scan reports |
| **users** | User accounts and permissions |
| **port_lists** | Port range definitions |

**Key Database:**
- Database name: `gvmd`
- User: `gvmd`
- Socket: `/var/run/postgresql/`

---

#### 4. **redamon-gvm-redis** (Redis Cache)

| Property | Value |
|----------|-------|
| Image | `registry.community.greenbone.net/community/redis-server` |
| Role | **High-Speed Cache & Message Queue** |
| Memory | 100-300 MB |

**What it does:**
- **NVT Cache**: Stores parsed NVT scripts for fast access
- **Scan Queue**: Coordinates scan jobs between components
- **Session State**: Maintains scanner state during scans
- **Inter-Process Communication**: Message passing between scanner processes

**Why Redis is essential:**
- NVTs are stored as files but need fast random access during scans
- Redis provides O(1) lookups vs file system I/O
- Enables parallel scanning with shared state

---

#### 5. **redamon-gvm-notus-scanner** (Notus Scanner)

| Property | Value |
|----------|-------|
| Image | `registry.community.greenbone.net/community/notus-scanner:stable` |
| Role | **Local Security Checks (LSC)** |
| Memory | 50-200 MB |

**What it does:**
- **Package Version Analysis**: Compares installed package versions against known vulnerable versions
- **Fast Local Checks**: No network probing required
- **OS-Specific**: Supports Linux, Windows package databases

**How it differs from OSPD-OpenVAS:**
| OSPD-OpenVAS | Notus Scanner |
|--------------|---------------|
| Network-based probing | Version comparison only |
| Sends packets to targets | Analyzes package lists |
| Slow (network latency) | Fast (local comparison) |
| Detects remote vulnerabilities | Detects missing patches |

---

### Data Containers (Run Once, Exit)

These containers download vulnerability data and exit immediately. They populate Docker volumes that persist between restarts.

#### 6. **vulnerability-tests** (NVT Feed)

| Property | Value |
|----------|-------|
| Image | `registry.community.greenbone.net/community/vulnerability-tests` |
| Volume | `vt_data` (~2 GB) |

**Contents:**
- **170,000+ NASL Scripts**: Network Attack Scripting Language
- **NVT Families**: Organized by category (web, databases, OS, etc.)
- **Detection Scripts**: Service/version fingerprinting
- **Exploit Scripts**: Proof-of-concept vulnerability tests

**Update Frequency:** Daily (05:00-07:00 UTC)

---

#### 7. **scap-data** (SCAP/CVE Feed)

| Property | Value |
|----------|-------|
| Image | `registry.community.greenbone.net/community/scap-data` |
| Volume | `scap_data` (~500 MB) |

**Contents:**
- **CVE Database**: Common Vulnerabilities and Exposures
- **CPE Dictionary**: Common Platform Enumeration (product identification)
- **CVSS Scores**: Severity ratings for vulnerabilities
- **EPSS Scores**: Exploit Prediction Scoring System

---

#### 8. **cert-bund-data** & **dfn-cert-data** (Advisory Feeds)

| Property | Value |
|----------|-------|
| Images | `cert-bund-data`, `dfn-cert-data` |
| Volume | `cert_data` |

**Contents:**
- **CERT-Bund**: German Federal Office for Information Security advisories
- **DFN-CERT**: German Research Network security advisories
- **Vendor Advisories**: Cross-referenced vulnerability information

---

#### 9. **data-objects** (Scan Configurations)

| Property | Value |
|----------|-------|
| Image | `registry.community.greenbone.net/community/data-objects` |
| Volume | `data_objects` |

**Contents:**
- **Scan Configs**: Pre-defined scan profiles (Full and fast, Discovery, etc.)
- **Port Lists**: Default port ranges (All TCP, Top 1000, etc.)
- **Filters**: Result filtering templates
- **Policies**: Compliance policy definitions

---

#### 10. **report-formats** (Report Templates)

| Property | Value |
|----------|-------|
| Image | `registry.community.greenbone.net/community/report-formats` |

**Contents:**
- **XML**: Raw machine-readable format
- **PDF**: Human-readable reports
- **CSV**: Spreadsheet-compatible
- **TXT**: Plain text summaries
- **HTML**: Web-viewable reports

---

#### 11. **gpg-data** (Signature Keys)

| Property | Value |
|----------|-------|
| Image | `registry.community.greenbone.net/community/gpg-data` |
| Volume | `gpg_data` |

**Purpose:**
- **Feed Verification**: GPG signatures ensure feed integrity
- **Authenticity**: Confirms feeds are from Greenbone
- **Tamper Detection**: Detects modified/corrupted feeds

---

#### 12. **notus-data** (Notus Feed)

| Property | Value |
|----------|-------|
| Image | `registry.community.greenbone.net/community/notus-data` |
| Volume | `notus_data` |

**Contents:**
- **Package Advisories**: Known vulnerable package versions
- **OS-Specific Data**: Debian, Ubuntu, RHEL, Windows packages
- **Version Mappings**: Package name → CVE mappings

---

## Data Flow & Protocols

### Complete Scan Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            COMPLETE SCAN FLOW                               │
└─────────────────────────────────────────────────────────────────────────────┘

1. INITIALIZATION
   ┌────────────────┐
   │ Python Scanner │
   │    main.py     │
   └───────┬────────┘
           │
           │ Load recon/output/recon_*.json
           ▼
   ┌────────────────┐
   │ Extract IPs &  │
   │   Hostnames    │
   └───────┬────────┘
           │
           │ Connect to /run/gvmd/gvmd.sock
           ▼
2. GMP AUTHENTICATION
   ┌────────────────┐     <authenticate>           ┌────────────────┐
   │ Python Scanner │ ──────────────────────────▶ │     GVMD       │
   │                │     username/password        │                │
   │                │ ◀────────────────────────── │                │
   └───────┬────────┘     <authenticate_response>  └────────────────┘
           │
3. TARGET CREATION
   ┌────────────────┐     <create_target>          ┌────────────────┐
   │ Python Scanner │ ──────────────────────────▶ │     GVMD       │
   │                │     hosts, port_list_id      │                │
   │                │ ◀────────────────────────── │                │
   └───────┬────────┘     target_id                └───────┬────────┘
           │                                               │
           │                                               │ INSERT INTO targets
           │                                               ▼
           │                                       ┌────────────────┐
           │                                       │   PostgreSQL   │
           │                                       └────────────────┘
4. TASK CREATION
   ┌────────────────┐     <create_task>            ┌────────────────┐
   │ Python Scanner │ ──────────────────────────▶ │     GVMD       │
   │                │     target_id, config_id     │                │
   │                │ ◀────────────────────────── │                │
   └───────┬────────┘     task_id                  └────────────────┘
           │
5. TASK START
   ┌────────────────┐     <start_task>             ┌────────────────┐
   │ Python Scanner │ ──────────────────────────▶ │     GVMD       │
   │                │     task_id                  │                │
   │                │ ◀────────────────────────── │                │
   └───────┬────────┘     report_id                └───────┬────────┘
           │                                               │
           │                                               │ OSP: <start_scan>
           │                                               ▼
           │                                       ┌────────────────┐
           │                                       │ OSPD-OpenVAS   │
           │                                       └───────┬────────┘
           │                                               │
           │                                               │ Load NVTs
           │                                               ▼
           │                                       ┌────────────────┐
           │                                       │     Redis      │
           │                                       └───────┬────────┘
           │                                               │
6. SCANNING                                                │ Execute NVTs
   ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ─ ┐
                                                           ▼
   │                                               ┌────────────────┐        │
                         NETWORK                   │  OpenVAS       │
   │                      TRAFFIC                  │  Processes     │        │
                            │                      └───────┬────────┘
   │    ┌───────────────────┼───────────────────┐          │                 │
        │                   │                   │          │
   │    ▼                   ▼                   ▼          │                 │
    ┌────────┐         ┌────────┐         ┌────────┐       │
   ││ Target │         │ Target │         │ Target │       │                 │
    │   1    │         │   2    │         │   3    │       │
   │└────────┘         └────────┘         └────────┘       │                 │
        │                   │                   │          │
   │    └───────────────────┼───────────────────┘          │                 │
                            │                              │
   │                   Results                             │                 │
    ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ┘
                            │                              │
                            ▼                              ▼
7. RESULT COLLECTION
   ┌────────────────┐                              ┌────────────────┐
   │   PostgreSQL   │ ◀──────────────────────────│ OSPD-OpenVAS   │
   │                │     Store results           │                │
   └───────┬────────┘                              └────────────────┘
           │
8. STATUS POLLING
   ┌────────────────┐     <get_task>               ┌────────────────┐
   │ Python Scanner │ ──────────────────────────▶ │     GVMD       │
   │                │     task_id                  │                │
   │                │ ◀────────────────────────── │                │
   │                │     status, progress         │                │
   │                │                              │                │
   │  (repeat until │                              │                │
   │   status=Done) │                              │                │
   └───────┬────────┘                              └────────────────┘
           │
9. REPORT RETRIEVAL
   ┌────────────────┐     <get_report>             ┌────────────────┐
   │ Python Scanner │ ──────────────────────────▶ │     GVMD       │
   │                │     report_id                │                │
   │                │ ◀────────────────────────── │                │
   └───────┬────────┘     XML report data          └────────────────┘
           │
           │ Parse XML → JSON
           ▼
10. OUTPUT
   ┌────────────────┐
   │ gvm_scan/      │
   │ output/        │
   │ gvm_*.json    │
   └────────────────┘
```

---

## Vulnerability Feeds

### Feed Types and Sources

| Feed | Source | Update Frequency | Size | Contents |
|------|--------|------------------|------|----------|
| **NVT Feed** | Greenbone | Daily | ~2 GB | 170,000+ vulnerability test scripts |
| **SCAP Feed** | NIST/Greenbone | Daily | ~500 MB | CVE definitions, CVSS scores |
| **CERT Feed** | CERT-Bund, DFN | Daily | ~100 MB | Security advisories |
| **Notus Feed** | Greenbone | Daily | ~200 MB | Package vulnerability data |

### Feed Version Format

Feed versions follow the format: `YYYYMMDDHHII`

Example: `202512240705` = December 24, 2025 at 07:05 UTC

### Feed Update Process

```
1. Data containers start
2. Download latest feed from Greenbone servers
3. Verify GPG signatures
4. Extract to Docker volumes
5. Container exits
6. GVMD detects new feed version
7. GVMD syncs feeds to PostgreSQL database
8. OSPD-OpenVAS reloads NVTs from Redis
```

---

## Configuration Parameters

### Per-Project Settings (Webapp UI)

GVM scan settings are configurable per-project via the webapp Project Settings UI ("GVM Scan" tab). Settings are stored in PostgreSQL and fetched at runtime by the scanner container via the webapp API.

The settings flow mirrors the recon and agentic modules:

```
Webapp UI → PostgreSQL (Prisma) → /api/projects/{id} → gvm_scan/project_settings.py → scanner
```

| Setting | DB Column | Type | Default | Description |
|---------|-----------|------|---------|-------------|
| Scan Profile | `gvm_scan_config` | String | `Full and fast` | GVM scan configuration preset (see Scan Configurations section) |
| Scan Targets Strategy | `gvm_scan_targets` | String | `both` | What to scan: `both`, `ips_only`, `hostnames_only` |
| Task Timeout | `gvm_task_timeout` | Int | `14400` | Max seconds per scan task (0 = unlimited) |
| Poll Interval | `gvm_poll_interval` | Int | `30` | Seconds between scan status checks |
| Cleanup After Scan | `gvm_cleanup_after_scan` | Boolean | `true` | Delete GVM targets/tasks after scan completion |

Default values are defined in `gvm_scan/project_settings.py` (`DEFAULT_GVM_SETTINGS`) and served to the frontend via the orchestrator `/defaults` endpoint.

### Environment Variables (Connection & Runtime)

GVM connection settings and runtime parameters are passed as environment variables by the orchestrator when starting the scanner container:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROJECT_ID` | — | Project identifier (set by orchestrator) |
| `USER_ID` | — | User identifier (set by orchestrator) |
| `TARGET_DOMAIN` | — | Target domain (set by orchestrator) |
| `WEBAPP_API_URL` | — | Webapp URL for fetching per-project settings (set by orchestrator) |
| `GVM_SOCKET_PATH` | `/run/gvmd/gvmd.sock` | Path to GVMD Unix socket |
| `GVM_USERNAME` | `admin` | GVM authentication username |
| `GVM_PASSWORD` | `admin` | GVM authentication password |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | — | Neo4j password |

---

## Scan Configurations

### Available Scan Profiles

| Config Name | Description | NVTs Used | Duration | Use Case |
|-------------|-------------|-----------|----------|----------|
| **Discovery** | Network discovery only | ~500 | 5-10 min | Quick host enumeration |
| **Host Discovery** | Basic host detection | ~100 | 2-5 min | Fastest option |
| **System Discovery** | OS and service detection | ~2,000 | 10-20 min | Inventory building |
| **Full and fast** | Comprehensive scan | ~50,000 | 30-60 min | **Recommended default** |
| **Full and fast ultimate** | Most thorough | ~70,000 | 1-2 hours | High-security targets |
| **Log4Shell** | Log4j specific | ~50 | 5-10 min | CVE-2021-44228 detection |

### Scan Config Internals

Each scan config defines:

1. **NVT Selection** - Which vulnerability tests to run
2. **Port List** - Which ports to scan
3. **Preferences** - Scan behavior settings
4. **Scanner** - Which scanner to use (OpenVAS Default)

### Port Lists

| Port List | Ports | Count |
|-----------|-------|-------|
| **All IANA assigned TCP** | 1-65535 (assigned) | ~5,000 |
| **All IANA assigned TCP and UDP** | TCP + UDP | ~10,000 |
| **All TCP and Nmap top 1000 UDP** | All TCP + top UDP | ~66,000 |
| **Nmap top 100 TCP** | Most common | 100 |

---

## Python Scanner API

### GVMScanner Class

```python
from gvm_scan.gvm_scanner import GVMScanner

# Initialize (reads GVM_SOCKET_PATH, GVM_USERNAME, GVM_PASSWORD from env)
scanner = GVMScanner(
    scan_config="Full and fast",
    task_timeout=14400,
    poll_interval=30
)

# Connect
scanner.connect()

# Create target
target_id = scanner.create_target(
    name="My Target",
    hosts=["192.168.1.1", "192.168.1.2"]
)

# Create and start task
task_id = scanner.create_task(
    name="My Scan",
    target_id=target_id
)
report_id = scanner.start_task(task_id)

# Wait for completion
status, report_id = scanner.wait_for_task(task_id)

# Get results
report = scanner.get_report(report_id)
vulnerabilities = scanner.parse_report(report)

# Cleanup
scanner.delete_target(target_id)
scanner.delete_task(task_id)
scanner.disconnect()
```

### Key Methods

| Method | Purpose | Returns |
|--------|---------|---------|
| `connect()` | Establish GMP connection | `bool` |
| `create_target(name, hosts)` | Create scan target | `target_id` |
| `create_task(name, target_id)` | Create scan task | `task_id` |
| `start_task(task_id)` | Start scanning | `report_id` |
| `wait_for_task(task_id)` | Wait for completion | `(status, report_id)` |
| `get_report(report_id)` | Fetch and parse report | `Dict` (with vulnerabilities, summary, raw_data) |
| `delete_target(target_id)` | Remove target | `None` |
| `delete_task(task_id)` | Remove task | `None` |

---

## Output Format

### JSON Structure

```json
{
  "metadata": {
    "scan_type": "vulnerability_scan",
    "scan_timestamp": "2025-12-28T17:00:00.000000",
    "target_domain": "example.com",
    "scan_strategy": "both",
    "recon_file": "recon_{projectId}.json",
    "targets": {
      "ips": ["192.168.1.1", "192.168.1.2"],
      "hostnames": ["www.example.com", "mail.example.com"]
    }
  },
  "scans": [
    {
      "scan_name": "IPs_example.com",
      "targets": ["192.168.1.1", "192.168.1.2"],
      "status": "completed",
      "scan_type": "ip_scan",
      "started": "2025-12-28T17:00:00Z",
      "finished": "2025-12-28T17:45:00Z",
      "duration_seconds": 2700,
      "vulnerabilities": [
        {
          "name": "SSL/TLS Certificate Expired",
          "oid": "1.3.6.1.4.1.25623.1.0.103955",
          "severity": "medium",
          "cvss_score": 5.0,
          "host": "192.168.1.1",
          "port": "443/tcp",
          "description": "The SSL certificate has expired...",
          "solution": "Replace the certificate with a valid one",
          "cve": ["CVE-2021-12345"],
          "references": ["https://nvd.nist.gov/..."]
        }
      ]
    }
  ],
  "summary": {
    "total_vulnerabilities": 15,
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 2,
    "log": 0,
    "hosts_scanned": 4
  }
}
```

### Severity Levels

| Level | CVSS Range | Color | Description |
|-------|------------|-------|-------------|
| **Critical** | 9.0 - 10.0 | 🔴 | Immediate action required |
| **High** | 7.0 - 8.9 | 🟠 | Serious vulnerability |
| **Medium** | 4.0 - 6.9 | 🟡 | Moderate risk |
| **Low** | 0.1 - 3.9 | 🔵 | Minor issue |
| **Log** | 0.0 | ⚪ | Informational only |

---

## Updating Vulnerability Data

GVM's vulnerability detection relies on regularly updated feeds from Greenbone. Understanding how to update these feeds is critical for effective scanning.

### How GVM Gets Vulnerability Data

GVM does **NOT calculate CVSS scores** - it retrieves pre-calculated scores from external sources:

| Data Source | What It Provides | Origin |
|-------------|------------------|--------|
| **NIST NVD** | CVE definitions, CVSS scores | National Vulnerability Database |
| **Greenbone Feed** | 170,000+ NVT scripts | Greenbone Security |
| **CERT-Bund** | German CERT advisories | BSI (German Federal Office) |
| **DFN-CERT** | Research network advisories | German Research Network |

### Feed Architecture in Docker

RedAmon uses **data containers** that download feeds once and populate Docker volumes:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        GVM FEED UPDATE FLOW                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   DATA CONTAINERS (run once, exit)                                      │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐        │
│   │ vulnerability-  │  │   scap-data     │  │  cert-bund-data │        │
│   │     tests       │  │                 │  │                 │        │
│   │                 │  │  CVE/CVSS from  │  │  German CERT    │        │
│   │  170K+ NVTs     │  │  NIST NVD       │  │  Advisories     │        │
│   └────────┬────────┘  └────────┬────────┘  └────────┬────────┘        │
│            │                    │                    │                  │
│            ▼                    ▼                    ▼                  │
│   ┌─────────────────────────────────────────────────────────────┐      │
│   │                    DOCKER VOLUMES                            │      │
│   │   vt_data (~2GB)   scap_data (~500MB)   cert_data (~100MB)  │      │
│   └─────────────────────────────────────────────────────────────┘      │
│            │                    │                    │                  │
│            └────────────────────┼────────────────────┘                  │
│                                 ▼                                       │
│                        ┌─────────────────┐                             │
│                        │      GVMD       │                             │
│                        │  Syncs feeds to │                             │
│                        │   PostgreSQL    │                             │
│                        └─────────────────┘                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Manual Feed Update (Recommended Weekly)

Since data containers only run once on first startup, you need to manually trigger updates:

```bash
# Step 1: Pull latest feed images (contains new vulnerability data)
docker compose pull vulnerability-tests notus-data scap-data \
                    cert-bund-data dfn-cert-data data-objects report-formats

# Step 2: Re-run data containers to update volumes
docker compose up vulnerability-tests notus-data scap-data \
                  cert-bund-data dfn-cert-data data-objects report-formats

# Step 3: Restart gvmd to reload updated feeds
docker compose restart gvmd

# Step 4: Wait for sync to complete (watch logs)
docker compose logs -f gvmd
# Look for: "Updating VTs in database ... done"
```

### What Each Feed Contains

| Container | Volume | Size | Update Frequency | Contents |
|-----------|--------|------|------------------|----------|
| `vulnerability-tests` | `vt_data` | ~2 GB | Daily | 170,000+ NASL vulnerability test scripts |
| `scap-data` | `scap_data` | ~500 MB | Daily | CVE definitions, CVSS scores, CPE dictionary |
| `cert-bund-data` | `cert_data` | ~50 MB | Daily | German CERT security advisories |
| `dfn-cert-data` | `cert_data` | ~50 MB | Daily | DFN-CERT research network advisories |
| `notus-data` | `notus_data` | ~200 MB | Daily | Package version → CVE mappings |
| `data-objects` | `data_objects` | ~10 MB | Weekly | Scan configs, port lists, policies |
| `report-formats` | `data_objects` | ~5 MB | Rarely | Report output templates |
| `gpg-data` | `gpg_data` | ~1 MB | Rarely | Feed signature verification keys |

### CVSS Score Source

GVM's `severity` field in scan results **IS the CVSS score** (0.0-10.0 float):

```python
# In gvm_scanner.py - severity comes directly from NVD via SCAP feed
severity = result.get('severity')  # e.g., 9.8
severity_class = classify_severity(severity)  # "critical"
```

**Severity Classification:**
```
CVSS 9.0-10.0  →  Critical
CVSS 7.0-8.9   →  High
CVSS 4.0-6.9   →  Medium
CVSS 0.1-3.9   →  Low
CVSS 0.0       →  Log/Info
```

### Update Frequency Recommendations

| Scenario | Update Frequency | Command |
|----------|------------------|---------|
| Regular assessments | Weekly | Full update (all containers) |
| Critical CVE announced | Immediately | Full update |
| Before important scan | Same day | Full update |
| Compliance audit | Day before | Full update + verify sync |

### Verifying Feed Status

```bash
# Check NVT count in database
docker compose exec pg-gvm psql -U gvmd -d gvmd -c "SELECT count(*) FROM nvts;"
# Expected: ~170,000+

# Check feed version
docker compose exec gvmd gvmd --get-feeds

# Check SCAP data
docker compose exec pg-gvm psql -U gvmd -d gvmd -c "SELECT count(*) FROM scap.cves;"
# Expected: ~250,000+
```

### Troubleshooting Feed Updates

| Issue | Solution |
|-------|----------|
| "Feed sync in progress" | Wait 10-20 minutes, check gvmd logs |
| Outdated NVT count | Re-run data containers, restart gvmd |
| "VT not found" errors | Feed sync incomplete, wait or re-sync |
| Disk space issues | GVM needs ~20GB; clean Docker: `docker system prune` |

---

## Maintenance & Operations

### Daily Operations
- Nothing required (automatic)

### Weekly Tasks

```bash
# Check disk space
docker system df

# Update vulnerability feeds (recommended method)
docker compose pull vulnerability-tests notus-data scap-data cert-bund-data dfn-cert-data data-objects report-formats
docker compose up vulnerability-tests notus-data scap-data cert-bund-data dfn-cert-data data-objects report-formats
docker compose restart gvmd
```

### Monthly Tasks

```bash
# Update container images
docker compose pull
docker compose down
docker compose up -d

# Clean unused Docker resources
docker system prune -f
```

### Useful Commands

```bash
# Check container status
docker compose ps

# View GVMD logs
docker compose logs -f gvmd

# View scanner logs
docker compose logs -f ospd-openvas

# Check NVT count
docker compose exec pg-gvm psql -U gvmd -d gvmd -c "SELECT count(*) FROM nvts;"

# List scan configs
docker compose exec pg-gvm psql -U gvmd -d gvmd -c "SELECT name FROM configs;"

# Check port lists
docker compose exec pg-gvm psql -U gvmd -d gvmd -c "SELECT name FROM port_lists;"

# Restart GVMD
docker compose restart gvmd

# Full reset (WARNING: loses all data)
docker compose down -v
docker compose up -d
```

---

## Troubleshooting

### Common Issues

#### "Scan config not found"
**Cause:** VT database sync not complete
**Solution:** Wait 10-20 minutes after first startup
```bash
docker compose logs --tail=20 gvmd
# Look for: "Updating VTs in database ... done"
```

#### "Failed to connect to GVM"
**Cause:** GVMD not ready or socket not mounted
**Solution:**
```bash
# Check GVMD is running
docker compose ps gvmd

# Check socket exists
docker compose exec gvmd ls -la /run/gvmd/
```

#### "OSPd OpenVAS is still starting"
**Cause:** Scanner loading NVTs (normal on startup)
**Solution:** Wait 5-10 minutes

#### "One of PORT_LIST and PORT_RANGE are required"
**Cause:** API compatibility issue
**Solution:** Ensure scanner code includes `port_list_id` in target creation

#### Scan stuck at 0%
**Cause:** Target unreachable or firewall blocking
**Solution:**
```bash
# Check scanner logs
docker compose logs ospd-openvas

# Verify target is reachable
docker compose exec ospd-openvas ping -c 3 <target_ip>
```

#### Memory issues
**Cause:** Insufficient RAM during large scans
**Solution:**
```bash
# Check container memory
docker stats

# Increase Docker memory limits if needed
```

---

## Security Considerations

### Network Security
1. **Isolated Network**: Run scanner on isolated VLAN when possible
2. **Firewall Rules**: Scanner needs outbound access to targets
3. **Traffic Volume**: Scans generate significant network traffic

### Credential Security
```bash
# Store password in .env file
echo "GVM_PASSWORD=your_secure_password" >> .env

# Ensure .env is in .gitignore
echo ".env" >> .gitignore
```

### Legal Considerations
⚠️ **WARNING**: Only scan systems you own or have explicit written permission to test.
Unauthorized vulnerability scanning may violate:
- Computer Fraud and Abuse Act (US)
- Computer Misuse Act (UK)
- Similar laws in other jurisdictions

### Best Practices
1. Document scan authorization in writing
2. Notify network/security teams before scanning
3. Schedule scans during low-traffic periods
4. Start with Discovery scans before Full scans
5. Monitor for unintended service disruption

---

## File Structure

```
redamon/
├── .env                              # Secrets (GVM_PASSWORD, NEO4J_PASSWORD, etc.)
├── docker-compose.yml                # Main stack (includes vuln-scanner build target)
│
├── gvm_scan/
│   ├── docker-compose.yml            # GVM infrastructure (gvmd, ospd-openvas, redis, pg-gvm)
│   ├── Dockerfile                    # Python scanner image (redamon-vuln-scanner)
│   ├── project_settings.py           # Per-project settings (fetched from webapp API)
│   ├── __init__.py                   # Package marker
│   ├── main.py                       # Entry point (reads PROJECT_ID from env)
│   ├── gvm_scanner.py                # GVM API wrapper (reads connection settings from env)
│   ├── requirements.txt              # Python dependencies
│   ├── README.GVM.md                 # This documentation
│   └── output/
│       └── gvm_{projectId}.json      # Scan results per project
│
├── recon/
│   └── output/
│       └── recon_{projectId}.json    # Input from recon pipeline
│
├── recon_orchestrator/
│   ├── api.py                        # GVM endpoints: /gvm/{id}/start, status, stop, logs
│   ├── container_manager.py          # GVM container lifecycle management
│   └── models.py                     # GvmState, GvmStatus, GvmLogEvent models
│
├── webapp/
│   ├── prisma/schema.prisma          # GVM fields: gvm_scan_config, gvm_scan_targets, etc.
│   └── src/
│       ├── app/api/gvm/[projectId]/  # API routes: start, status, logs, download
│       ├── app/graph/page.tsx        # GVM state wiring, log drawer, toolbar buttons
│       ├── components/projects/ProjectForm/sections/GvmScanSection.tsx  # GVM settings UI
│       ├── hooks/useGvmStatus.ts     # GVM status polling hook
│       ├── hooks/useGvmSSE.ts        # GVM SSE log streaming hook
│       └── lib/recon-types.ts        # GvmStatus, GvmState, GVM_PHASES types
│
└── graph_db/
    └── neo4j_client.py               # update_graph_from_gvm_scan() method
```

---

## Quick Reference

### Start GVM Infrastructure
```bash
cd gvm_scan
docker compose up -d
docker compose logs -f gvmd  # Wait for VT sync ("Updating VTs in database ... done")
```

### Build Scanner Image (from project root)
```bash
docker compose --profile tools build vuln-scanner
```

### Run Scan via Webapp (Recommended)
1. Ensure GVM infrastructure is running (`cd gvm_scan && docker compose up -d`)
2. Ensure the main stack is running (`docker compose up -d`)
3. Open http://localhost:3000, navigate to Graph page
4. Run recon first (GVM requires recon data)
5. Click "GVM Scan" button — logs stream in real-time

### Run Scan via CLI (Development)
```bash
PROJECT_ID=your_project_id TARGET_DOMAIN=example.com \
  python gvm_scan/main.py
```

### Check Results
```bash
cat gvm_scan/output/gvm_{projectId}.json | jq '.summary'
```

### Stop GVM Infrastructure
```bash
cd gvm_scan
docker compose down
```
