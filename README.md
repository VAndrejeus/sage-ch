# SAGE-CH

SAGE-CH (Security Assessment using Graph-based Evaluation for Cyber Hygiene) is a cross-platform cyber hygiene assessment framework that integrates endpoint telemetry, network discovery, and graph-based analysis into a unified system.

The system operates in a strictly read-only mode and provides transparent, auditable, and structured visibility into enterprise cyber posture aligned with CIS Controls v8.1.

---

## Overview

SAGE-CH combines:

- Endpoint-based data collection (Windows and Linux agents)
- Network discovery for exposed services and unmanaged assets
- A staged ingestion and normalization pipeline
- A knowledge graph representing cyber entities and relationships
- CIS Controls-aligned rule-based analysis
- AI-assisted risk explanation and remediation generation
- Persistent graph storage using Kuzu

The result is a unified cyber knowledge graph that models hosts, software, services, findings, and their relationships.

---

## Features

### Endpoint Agents (Windows and Linux)

- Host identification (hostname, OS, IP, MAC)
- Software inventory collection
- Update and patch status indicators
- Security configuration indicators (expanding)
- Read-only execution with audit logging
- Structured JSON output

---

### Network Discovery

- Allowlisted, non-intrusive scanning
- Host discovery within authorized scope
- TCP-based service probing
- Detection of exposed services (ports and protocols)
- Identification of unmanaged assets

---

### Collector Pipeline

- Staged batch ingestion system
- Schema validation and error handling
- Cross-platform normalization
- Deduplication of hosts and software
- Endpoint-to-network correlation
- Consolidated dataset generation

---

### Knowledge Graph

Graph-based modeling of cyber entities:

Node types:
- Host (managed and discovered)
- Software
- Update Status
- Service / Port
- Finding
- Control
- Evidence

Edge types:
- HOST_HAS_SOFTWARE
- HOST_HAS_UPDATE_STATUS
- HOST_EXPOSES_SERVICE
- HOST_HAS_FINDING
- FINDING_MAPS_TO_CONTROL
- FINDING_HAS_EVIDENCE
- OBSERVATION_OF

---

### Graph Persistence (Kuzu)

- Persistent graph database integration
- Incremental graph updates across runs
- Tracks:
  - first_seen
  - last_seen
  - active vs inactive nodes
- Supports graph inspection and querying

---

### CIS-Based Analysis Engine

- Rule-based evaluation aligned to CIS Controls v8.1
- Structured findings generation
- Evidence traceability
- Severity classification
- Host-level risk scoring

---

### AI-Assisted Analysis

- Local LLM (Gemma2:9b)
- Host-level risk explanations
- Identification of key risk drivers
- Prioritized remediation plans

Safety layer:
- Removes unsafe or destructive commands
- Enforces read-only recommendations

---

### Reporting

- Machine-readable outputs (JSON)
- Human-readable reports (Markdown)
- AI-generated explanation and remediation outputs

---

## How to Run

### Run Windows Agent
python -m agents.windows.main

### Run Linux Agent
python3 -m agents.linux.main

### Run Network Discovery
python tools/network_discovery.py


Discovery output is written to:
outputs/discovery/

### Move Endpoint Reports

Copy endpoint reports into:
collector/input/

### Run Collector
python -m collector.main

### Inspect Graph (Kuzu)
python -m collector.graph.kuzu_inspector

## Output Files

### Endpoint Agents

agents/windows/output/
agents/linux/output/

Files:
- endpoint_report_YYYYMMDD_HHMM.json
- agent_audit_YYYYMMDD_HHMM.log

---

### Network Discovery
outputs/discovery/

Files:
- network_discovery_YYYYMMDD_HHMM.json

---

### Collector Outputs
collector/output/


Files:
- consolidated_dataset_batch_*.json
- findings_dataset_batch_*.json
- assessment_summary_batch_*.json
- scoreboard_report_batch_*.md
- ai_host_explanations_batch_*.json
- ai_remediation_plan_batch_*.md
- collector_audit.log

---

### Graph Storage
collector/output/graph/


Files:
- sage_ch_kuzu.db

---

## System Pipeline


Endpoint Agents + Network Discovery
↓
Ingestion
↓
Validation
↓
Normalization
↓
Correlation
↓
Graph Builder
↓
Kuzu Persistence
↓
CIS Rule Engine
↓
AI Layer
↓
Reporting


---

## Design Principles

- Strictly read-only execution
- Least-privilege data collection
- Allowlisted network discovery
- Transparent and auditable processing
- Separation of data collection, analysis, and AI layers
- Batch-based reproducibility

---

## Constraints

- No intrusive scanning
- No system modification
- Periodic execution (not real-time monitoring)
- Limited by available permissions and visibility

---

## Current Capabilities

- Cross-platform endpoint collection (Windows and Linux)
- Network discovery and service exposure mapping
- Unified knowledge graph construction
- CIS-aligned findings with evidence traceability
- AI-generated explanations and remediation plans
- Persistent graph storage with Kuzu

---

## Future Work

- CVE and CPE integration
- UCO or STIX alignment
- Attack path analysis using graph traversal
- Historical trend analysis across batches
- Distributed and large-scale deployment

---

## Notes

- Agents must be run before the collector
- Discovery must be executed separately
- Collector expects endpoint reports in `collector/input/`
- Graph persists across runs unless manually reset

---

## License and Usage

This project is intended for academic and controlled environments.

Ensure proper authorization before running on any network or system.