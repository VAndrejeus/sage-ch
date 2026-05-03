# SAGE-CH

SAGE-CH (Security Assessment using Graph-based Evaluation for Cyber Hygiene) is a cross-platform cyber hygiene assessment framework that integrates endpoint telemetry, network discovery, vulnerability intelligence, and graph-based analysis into a unified system.

The system operates in a strictly read-only mode and provides transparent, auditable, and structured visibility into enterprise cyber posture aligned with CIS Controls v8.1.

---

## Overview

SAGE-CH combines:

* Endpoint-based data collection (Windows and Linux agents)
* Network discovery for exposed services and unmanaged assets
* A staged ingestion and normalization pipeline
* A knowledge graph representing cyber entities and relationships
* CIS Controls-aligned rule-based analysis
* CVE-based vulnerability correlation (NEW)
* AI-assisted risk explanation and remediation generation
* Persistent graph storage using Kuzu

---

## Features

### Endpoint Agents (Windows and Linux)

* Host identification (hostname, OS, IP, MAC)
* Software inventory collection
* Update and patch status indicators
* Security configuration indicators (expanding)
* Read-only execution with audit logging
* Structured JSON output

---

### Network Discovery

* Allowlisted, non-intrusive scanning
* Host discovery within authorized scope
* TCP-based service probing
* Detection of exposed services (ports and protocols)
* Identification of unmanaged assets

---

### Collector Pipeline

* Staged batch ingestion system
* Schema validation and error handling
* Cross-platform normalization
* Deduplication of hosts and software
* Endpoint-to-network correlation
* Consolidated dataset generation

---

### CVE Correlation Engine (NEW)

#### Pipeline Stages

1. **Software Snapshot**
2. **CVE Snapshot (NVD Integration)**
3. **CVE Correlation**

#### Filtering Logic

* CVSS ≥ 7.0
* Last 10 years
* Top 3 CVEs per product

#### Output

* High-signal vulnerability findings
* Host-level CVE mapping
* Structured remediation + AI explanation

---

### Knowledge Graph

Node types:

* Host
* Software
* Service / Port
* Finding
* Control
* Evidence

Edge types:

* HOST_HAS_SOFTWARE
* HOST_EXPOSES_SERVICE
* HOST_HAS_FINDING
* FINDING_MAPS_TO_CONTROL
* FINDING_HAS_EVIDENCE

---

### Graph Persistence (Kuzu)

* Persistent graph database integration
* Tracks lifecycle (first_seen, last_seen)
* Supports querying and inspection

---

### CIS-Based Analysis Engine

* CIS Controls v8.1 alignment
* Structured findings
* Severity classification
* Risk scoring

---

### AI-Assisted Analysis

* Local LLM (Gemma2:9b)
* Risk explanations
* Remediation guidance

---

## How to Run

### 1. Endpoint Agents

Windows:

```bash
python -m agents.windows.main
```

Linux:

```bash
python3 -m agents.linux.main
```

---

### 2. Network Discovery

```bash
python tools/network_discovery.py
```

---

### 3. Move Reports

```text
collector/input/
```

---

### 4. Collector

```bash
python -m collector.main
```

---

### 5. CVE Pipeline

#### Software Snapshot

```bash
python tools/create_software_snapshot.py
```

#### CVE Snapshot

```bash
python tools/update_cve_snapshot.py
```

#### CVE Findings

```bash
python tools/correlate_cves_to_findings.py
```

---

## Output Structure

```
collector/output/
├── software_snapshot/
├── cve_snapshot/
├── cve_findings/
├── graph/
```

---

## System Pipeline

```
Endpoint + Network
↓
Collector
↓
Software Snapshot
↓
CVE Snapshot
↓
CVE Correlation
↓
Findings
↓
Graph
↓
AI Layer
↓
Reports
```

---

## Current Capabilities

* Endpoint + network visibility
* Knowledge graph construction
* CIS findings
* CVE vulnerability detection
* AI remediation
* Persistent graph tracking

---

## Limitations

* Not version-aware yet
* Keyword-based CVE matching
* Possible false positives

---

## Future Work

* Version-aware CVE matching (CPE)
* KEV / exploitability integration
* Risk scoring model
* UI integration for CVE pipeline
* Full pipeline orchestration

---

## Notes

* CVE pipeline runs separately
* Avoid frequent NVD calls (rate limiting)
* Designed for controlled execution

---

## License

Academic / controlled use only.

---

## Fresh Windows PC Quick Start

Use this path for a new machine, demo machine, or grader environment.

### Prerequisites

* Windows 10/11
* Python 3.11 or newer on PATH
* PowerShell
* Optional for AI enrichment: Ollama with `gemma2:9b`

### 1. Set up the project

Open PowerShell in the project folder and run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
```

This creates `.venv`, installs `requirements.txt`, and runs a preflight check.

### 2. Start the Streamlit console

```powershell
.\scripts\run_gui.ps1
```

Or double-click:

```text
START_SAGE_CH.bat
```

### 3. Verify health

Open the Streamlit sidebar:

```text
Operations -> Pipeline Health
```

Confirm:

* Kuzu is available
* Latest consolidated dataset is found
* Graph node counts are non-zero
* No unexpected batches are stuck in processing

### 4. Rebuild Kuzu if needed

If the Graph page shows an empty Kuzu database, use:

```text
Operations -> Actions -> Rebuild Kuzu
```

Or run:

```powershell
python tools\rebuild_kuzu_from_consolidated.py
```

### 5. Collector and AI workflow

Run the core collector without AI:

```powershell
.\scripts\run_collector.ps1
```

Run AI enrichment after the core graph is available:

```powershell
python tools\run_ai_enrichment.py
```

The Streamlit Actions page also exposes both operations.

### Troubleshooting

Run:

```powershell
.\.venv\Scripts\python.exe tools\preflight_check.py
```

If dependencies are missing, rerun:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
```
