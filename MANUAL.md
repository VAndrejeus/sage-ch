# SAGE-CH User And Technical Manual

## 1. Overview

SAGE-CH stands for **Security Assessment using Graph-based Evaluation for Cyber Hygiene**. It is a cyber hygiene assessment framework that collects endpoint telemetry, incorporates network discovery, evaluates security posture against CIS Controls-aligned rules, correlates installed software with vulnerability intelligence, builds a knowledge graph, and presents results in a Streamlit-based security console.

The system is designed for academic and controlled-use environments. Its collection model is intentionally read-only: agents inspect system state and write structured JSON reports, but they do not modify endpoint configuration.

SAGE-CH is useful for answering questions such as:

- Which hosts are known and assessed?
- Which systems have missing patches, weak configurations, risky accounts, or exposed services?
- Which CIS Controls are most frequently violated?
- Which installed software products correlate with high-signal CVEs?
- How are hosts, software, services, findings, evidence, controls, explanations, and remediation actions related?
- Which hosts should be prioritized first?
- Has the pipeline completed successfully, and is the graph database healthy?

## 2. High-Level Architecture

SAGE-CH is organized into five major layers:

1. **Endpoint agents**
   Windows and Linux collectors gather local host telemetry and write endpoint reports.

2. **Network discovery**
   A non-intrusive scanner probes authorized local networks for exposed services and unmanaged assets.

3. **Collector pipeline**
   The collector validates reports, normalizes host data, correlates endpoint and discovery records, generates findings, builds the graph, and writes output files.

4. **Analysis and intelligence**
   This layer includes CIS Controls-aligned rule evaluation, CVE correlation, risk scoring, and optional AI remediation/explanation enrichment.

5. **Streamlit security console**
   The GUI provides dashboard, host, finding, graph, batch, action, settings, and pipeline health views.

The intended data flow is:

```text
Endpoint Agents + Network Discovery
        |
        v
Collector Input Queue
        |
        v
Validation -> Normalization -> Correlation
        |
        v
CIS Rule Findings + Evidence
        |
        v
Core Knowledge Graph
        |
        v
Kuzu Persistence + JSON/Markdown Output Files
        |
        v
Optional AI Enrichment
        |
        v
AI-Enriched Graph + Remediation Outputs
        |
        v
Streamlit Security Console
```

## 3. Repository Structure

Important folders and files:

```text
agents/
  windows/
    main.py
    collectors/
  linux/
    main.py
    collectors/

collector/
  main.py
  ingestion/
  validation/
  normalization/
  correlation/
  analysis/
  graph/
  alignment/
  security/cve/
  ai/
  input/
  output/
  manifests/

config/
  discovery_scope.json

gui/
  app.py
  pages/
  services/
  assets/

tools/
  network_discovery.py
  create_software_snapshot.py
  update_cve_snapshot.py
  correlate_cves_to_findings.py
  rebuild_kuzu_from_consolidated.py
  run_ai_enrichment.py
  preflight_check.py

scripts/
  setup_windows.ps1
  run_gui.ps1
  run_collector.ps1

requirements.txt
START_SAGE_CH.bat
README.md
MANUAL.md
```

PowerShell note for Windows users: if Windows blocks a project `.ps1` script because of the local execution policy, run the same script through PowerShell with an execution-policy bypass for that command. For example, instead of running `.\scripts\run_gui.ps1` directly, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_gui.ps1
```

The same pattern can be used for other project scripts, such as `.\scripts\run_collector.ps1` or `.\scripts\setup_windows.ps1`.

## 4. Core Components

### 4.1 Windows Endpoint Agent

Entry point:

```text
agents/windows/main.py
```

Run command:

```powershell
python -m agents.windows.main
```

The Windows agent collects:

- Host identity
- Operating system information
- Network interfaces and IP addresses
- Installed software inventory
- Update and hotfix indicators
- Security configuration
- Local account information
- Audit policy information
- Backup/shadow copy indicators

The output is a JSON endpoint report written under:

```text
agents/windows/output/
```

The agent also writes an audit log:

```text
agents/windows/output/agent_audit.log
```

### 4.2 Linux Endpoint Agent

Entry point:

```text
agents/linux/main.py
```

Run command:

```bash
python3 -m agents.linux.main
```

The Linux agent collects:

- Distro/platform information
- Package manager type
- Host identity
- Network interfaces and DNS/default gateway data
- Installed package/software inventory
- Update status
- Firewall state
- SSH configuration indicators
- Automatic update configuration
- Fail2ban indicators
- SELinux state
- Password policy indicators
- Local account information
- Audit policy information
- Backup indicators

The output is written under:

```text
agents/linux/output/
```

### 4.3 Network Discovery

Entry point:

```text
tools/network_discovery.py
```

Run command:

```powershell
python tools\network_discovery.py
```

The network discovery tool performs authorized, non-intrusive TCP service probing. Scope is controlled by:

```text
config/discovery_scope.json
```

Important scope fields:

- `authorized_networks`: CIDRs allowed for scanning, or `*`
- `authorized_interfaces`: interfaces allowed for scanning, or `*`
- `max_hosts_per_subnet`: safety limit
- `private_only`: prevents scanning public ranges when true

The scanner probes common service ports such as:

- SSH: 22
- HTTP/HTTPS: 80, 443
- SMB: 139, 445
- RDP: 3389
- WinRM: 5985, 5986
- Databases: 1433, 1521, 3306, 5432

Discovery output is written to:

```text
outputs/discovery/
```

The collector automatically looks for the latest discovery file in this directory.

### 4.4 Staged Collector Ingestion

The collector uses a staged ingestion system. Endpoint reports should be placed in:

```text
collector/input/incoming/
```

When the collector runs, it claims files into:

```text
collector/input/processing/<batch_id>/
```

After completion, files are moved to:

```text
collector/input/processed/<batch_id>/
```

Failed files are moved to:

```text
collector/input/failed/<batch_id>/
```

Batch manifests are written to:

```text
collector/manifests/
```

Each batch has:

- A claim manifest: `<batch_id>.json`
- A result manifest: `<batch_id>_result.json`

The manifest records file names, hashes, sizes, host identifiers, timestamps, and success/failure status.

### 4.5 Validation

Validation verifies that endpoint reports and discovery outputs have the fields required by SAGE-CH.

Relevant modules:

```text
collector/validation/schema_validator.py
collector/validation/discovery_validator.py
```

Validation helps prevent malformed input from poisoning the pipeline.

### 4.6 Normalization

Normalization converts raw platform-specific reports into a consistent host record shape.

Relevant modules:

```text
collector/normalization/normalizer.py
collector/normalization/discovery_normalizer.py
```

Normalized host fields include:

- `host_id`
- `hostname`
- `source_os`
- `os_name`
- `os_version`
- `platform`
- `network`
- `software`
- `update_status`
- `security_config`
- `account_info`
- `audit_policy`
- `backup_info`
- `source_report`

### 4.7 Endpoint-To-Discovery Correlation

Endpoint reports and network discovery records are correlated by matching hostnames and IP addresses.

Relevant module:

```text
collector/correlation/host_correlator.py
```

This step identifies relationships between managed endpoint records and discovered network observations.

### 4.8 CIS-Aligned Rule Engine

The rule engine evaluates normalized hosts against CIS Controls-aligned rules.

Relevant modules:

```text
collector/analysis/rules.py
collector/analysis/rule_engine.py
collector/analysis/evidence_mapper.py
collector/analysis/finding_builder.py
```

Rule categories include:

- Patching
- Inventory
- Host identity
- Network configuration
- Secure configuration
- Account management
- Access control
- Audit logging
- Malware defense
- Data recovery
- Application security
- Incident response
- Vulnerability management

Example finding fields:

- Finding ID
- Rule ID
- Title
- Severity
- Category
- Hostname
- Platform
- IP address
- Description
- Expected state
- Recommendation
- CIS Controls
- Evidence
- Batch ID

### 4.9 Risk And Control Scoring

Assessment summaries include:

- Total hosts
- Total findings
- Affected hosts
- Severity counts
- Category counts
- CIS Control counts
- Control scores
- Host risk scores

Relevant modules:

```text
collector/analysis/report_generator.py
collector/analysis/risk_score_calculator.py
collector/analysis/control_score_calculator.py
```

### 4.10 Knowledge Graph Construction

The graph builder converts normalized assessment data into graph nodes and edges.

Relevant modules:

```text
collector/graph/graph_builder.py
collector/alignment/graph_mapper.py
collector/graph/graph_persistence.py
collector/graph/kuzu_backend.py
collector/graph/kuzu_schema.py
```

Important graph node types:

- Host
- Software
- PatchStatus
- Service
- Finding
- Control
- Evidence
- Explanation
- Remediation

Important graph edge types:

- `HAS_SOFTWARE`
- `HAS_PATCH_STATUS`
- `EXPOSES_SERVICE`
- `HAS_FINDING`
- `MAPS_TO_CONTROL`
- `SUPPORTED_BY`
- `HAS_EXPLANATION`
- `HAS_REMEDIATION`
- `OBSERVATION_OF`

SAGE-CH stores graph data in two forms:

1. JSON graph data inside consolidated output files
2. Persistent Kuzu graph database

Kuzu database path:

```text
collector/output/graph/sage_ch_kuzu.db
```

### 4.11 Kuzu Persistence

Kuzu is used to persist graph state across runs.

SAGE-CH currently stores graph records in generic graph tables:

- `GraphNode`
- `GraphEdge`
- `NodeObservation`
- `EdgeObservation`

Relationship tables:

- `EDGE_SOURCE`
- `EDGE_TARGET`
- `OBSERVATION_OF_NODE`
- `OBSERVATION_OF_EDGE`

Each graph node and edge tracks:

- First seen
- Last seen
- Last run ID
- Active/missing state
- Status
- Original type
- Semantic type
- JSON properties

This allows the graph to represent both the latest assessment and lifecycle observations.

### 4.12 CVE Pipeline

The CVE pipeline is separate from the core collector.

It has three stages:

1. Software snapshot
2. CVE snapshot
3. CVE findings

#### Stage 1: Software Snapshot

Command:

```powershell
python tools\create_software_snapshot.py
```

This extracts installed software from endpoint reports and groups products by normalized software name.

Output:

```text
collector/output/software_snapshot/software_snapshot_latest.json
```

#### Stage 2: CVE Snapshot

Command:

```powershell
python tools\update_cve_snapshot.py
```

This queries NVD for CVE data associated with software candidates.

Output:

```text
collector/output/cve_snapshot/cve_snapshot_latest.json
```

Important note: this stage uses network access and may be rate limited by NVD.

#### Stage 3: CVE Findings

Command:

```powershell
python tools\correlate_cves_to_findings.py
```

This converts CVE snapshot entries into SAGE-CH vulnerability findings.

Current filtering:

- CVSS >= 7.0
- CVE published in the last 10 years
- Top 3 CVEs per product

Output:

```text
collector/output/cve_findings/cve_findings_latest.json
```

The Streamlit Findings and Dashboard pages merge configuration findings and CVE findings into a combined operator view.

### 4.13 AI Enrichment

AI enrichment is optional and separate from the core collector path.

Relevant modules:

```text
collector/ai/
tools/run_ai_enrichment.py
```

The AI phase uses a local Ollama endpoint by default:

```text
http://localhost:11434/api/generate
```

Default model:

```text
gemma2:9b
```

AI enrichment produces:

- Host-level risk explanations
- Key risk drivers
- Remediation priorities
- Remediation guidance
- AI graph nodes for explanations and remediation plans

Run command:

```powershell
python tools\run_ai_enrichment.py
```

The collector can also run AI enrichment inline:

```powershell
python -m collector.main --with-ai
```

For reliability, the recommended workflow is:

1. Run the collector without AI
2. Confirm core graph health
3. Run AI enrichment separately

This prevents slow AI calls from blocking the core graph and findings outputs.

## 5. Installation And Setup

### 5.1 Fresh Windows Setup

Prerequisites:

- Windows 10 or 11
- Python 3.11 or newer on PATH
- PowerShell
- Internet access for dependency installation
- Optional: Ollama for AI enrichment

From the project root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
```

This script:

1. Checks Python availability
2. Creates `.venv`
3. Upgrades pip
4. Installs dependencies from `requirements.txt`
5. Runs `tools/preflight_check.py`

### 5.2 Starting The GUI

Run:

```powershell
.\scripts\run_gui.ps1
```

If script execution is blocked by the Windows execution policy, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_gui.ps1
```

Or double-click:

```text
START_SAGE_CH.bat
```

The app opens in a browser through Streamlit.

### 5.3 Preflight Check

Run:

```powershell
.\.venv\Scripts\python.exe tools\preflight_check.py
```

The preflight check verifies:

- Required Python modules
- Required project files
- Latest consolidated output
- Latest batch ID
- Kuzu DB existence

### 5.4 Required Python Packages

Declared in:

```text
requirements.txt
```

Important packages:

- `streamlit`
- `pandas`
- `plotly`
- `networkx`
- `kuzu`
- `requests`
- `psutil`
- `reportlab`

### 5.5 Recommended Installation Workflow For A New PC

Use this workflow when installing SAGE-CH on a different Windows computer.

1. Copy the entire `sage-ch` project folder to the new computer.
2. Install Python 3.11 or newer from `python.org` or the Microsoft Store.
3. During Python installation, enable **Add Python to PATH**.
4. Open PowerShell.
5. Change directory into the project root.
6. Run the setup script:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
```

7. Wait for dependency installation to complete.
8. Run the preflight check:

```powershell
.\.venv\Scripts\python.exe tools\preflight_check.py
```

9. Start the GUI:

```powershell
.\scripts\run_gui.ps1
```

If PowerShell blocks the script, use:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_gui.ps1
```

10. Open Pipeline Health in the Streamlit sidebar and confirm that the latest output files are detected.

If the graph database does not load after moving computers, rebuild it:

```powershell
.\.venv\Scripts\python.exe tools\rebuild_kuzu_from_consolidated.py
```

### 5.6 Manual Dependency Installation

If the setup script cannot be used, install dependencies manually:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe tools\preflight_check.py
```

Use the virtual environment Python executable for project commands:

```powershell
.\.venv\Scripts\python.exe -m collector.main
```

### 5.7 Optional AI Setup

AI enrichment is optional. The core collector, findings, Kuzu graph, CVE findings, and GUI can operate without AI.

To use AI enrichment:

1. Install Ollama.
2. Start Ollama.
3. Pull the configured model:

```powershell
ollama pull gemma2:9b
```

4. Confirm the model is available:

```powershell
ollama list
```

5. Run AI enrichment after the core collector has completed:

```powershell
.\.venv\Scripts\python.exe tools\run_ai_enrichment.py
```

If AI is unavailable, do not treat that as a failure of SAGE-CH. The system is intentionally designed so the authoritative rule-based findings and core graph are available without the AI layer.

### 5.8 Installation Validation Checklist

After setup, confirm the following:

- `requirements.txt` installed without errors.
- `tools/preflight_check.py` completes.
- `collector/output/` exists.
- `collector/output/graph/sage_ch_kuzu.db` exists or can be rebuilt.
- Streamlit starts successfully.
- Pipeline Health loads in the GUI.
- Dashboard displays host and finding counts.
- Graph page can render a host neighborhood.
- Findings page displays CIS and CVE findings.

### 5.9 Portable Thumb Drive Deployment

SAGE-CH can be packaged so the target Windows computers do not need Python installed.

The portable deployment model uses three packages:

- `SAGE-CH-Collector-Windows`
- `SAGE-CH-Agent-Windows`
- `SAGE-CH-Agent-Linux`

The Windows collector package contains:

- SAGE-CH source code
- Streamlit GUI
- Collector pipeline
- Tools
- Documentation
- Embedded portable Python runtime
- Installed Python dependencies
- Batch launcher scripts

The Windows endpoint agent package contains:

- Windows agent source code
- Shared utility modules
- Embedded portable Python runtime
- A double-click launcher for the endpoint agent
- A report collection helper

The Linux endpoint package contains:

- Linux agent source code
- Shared utility modules
- A shell launcher

Important note:

Windows packages can be made fully portable because Microsoft provides an embeddable Python runtime. Linux systems vary more by distribution and architecture. For Linux endpoints with no Python installed, build a Linux executable on a compatible Linux machine using PyInstaller or ship a distribution-specific Python runtime. Many Linux systems already include Python 3, in which case the provided shell launcher is sufficient.

Build the portable Windows package from the development machine:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_portable_windows.ps1
```

Build the package and include existing demo outputs:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_portable_windows.ps1 -IncludeOutputs
```

Output folder:

```text
dist/sage-ch-portable/
```

Copy the contents of `dist/sage-ch-portable/` to a thumb drive.

### 5.10 Installing Collector From Thumb Drive

On the collector computer:

1. Insert the thumb drive.
2. Copy `SAGE-CH-Collector-Windows` to a local folder, or run it directly from the thumb drive.
3. Open the folder.
4. Run:

```text
RUN_PREFLIGHT.bat
```

5. If preflight succeeds, run:

```text
START_COLLECTOR_GUI.bat
```

6. Streamlit starts using the embedded Python runtime.

No system Python installation is required on the collector computer when using the portable package.

Collector package launchers:

| Launcher | Purpose |
| --- | --- |
| `START_COLLECTOR_GUI.bat` | Starts the Streamlit GUI |
| `RUN_COLLECTOR.bat` | Runs the core collector |
| `RUN_PREFLIGHT.bat` | Checks portable package health |
| `REBUILD_KUZU.bat` | Rebuilds Kuzu from consolidated JSON |

### 5.11 Installing Windows Agents From Thumb Drive

On a Windows endpoint:

1. Insert the thumb drive.
2. Copy `SAGE-CH-Agent-Windows` to the endpoint, or run it from the thumb drive.
3. Open the folder.
4. Run:

```text
RUN_WINDOWS_AGENT.bat
```

5. The agent writes output under:

```text
app/agents/windows/output/
```

6. Run:

```text
COLLECT_REPORTS.bat
```

7. Copy the created JSON report from:

```text
reports/
```

8. Move that report to the collector computer:

```text
SAGE-CH-Collector-Windows/app/collector/input/incoming/
```

The Windows agent package does not require Python to be installed on the endpoint.

### 5.12 Installing Linux Agents From Thumb Drive

On a Linux endpoint with Python 3 available:

1. Copy `SAGE-CH-Agent-Linux` to the endpoint.
2. Open a terminal.
3. Run:

```bash
chmod +x run_linux_agent.sh
./run_linux_agent.sh
```

Output path:

```text
app/agents/linux/output/
```

Copy the endpoint report JSON to the collector input folder.

For Linux endpoints without Python, use one of these options:

- Build a Linux executable on a compatible Linux machine using PyInstaller.
- Ship a distro-specific Python runtime with the Linux agent.
- Install Python 3 through the distribution package manager.

The recommended final-project deployment path is:

- Fully portable Windows collector package
- Fully portable Windows agent package
- Linux source agent package, with Python 3 expected or a Linux executable built separately

### 5.13 Portable Deployment Workflow

Recommended thumb drive workflow:

1. Build portable package on the development computer.
2. Copy `dist/sage-ch-portable/` to the thumb drive.
3. On the collector computer, run `START_COLLECTOR_GUI.bat`.
4. On each Windows endpoint, run `RUN_WINDOWS_AGENT.bat`.
5. Copy endpoint JSON reports into the collector input folder.
6. On the collector computer, run `RUN_COLLECTOR.bat`.
7. Open the GUI.
8. Review Pipeline Health.
9. Review Dashboard, Hosts, Findings, and Graph.
10. Run `REBUILD_KUZU.bat` if graph health is not clean.

## 6. CLI Usage

### 6.1 Run Windows Agent

```powershell
python -m agents.windows.main
```

Output:

```text
agents/windows/output/
```

### 6.2 Run Linux Agent

```bash
python3 -m agents.linux.main
```

Output:

```text
agents/linux/output/
```

### 6.3 Move Reports Into Collector Input

Copy endpoint report JSON files into:

```text
collector/input/incoming/
```

### 6.4 Run Network Discovery

Review scope first:

```text
config/discovery_scope.json
```

Then run:

```powershell
python tools\network_discovery.py
```

Output:

```text
outputs/discovery/
```

### 6.5 Run Core Collector

Recommended command:

```powershell
.\scripts\run_collector.ps1
```

Equivalent direct command:

```powershell
python -m collector.main
```

This performs:

- Batch claiming
- Validation
- Normalization
- Discovery correlation
- CIS/rule findings
- Core graph construction
- Kuzu persistence
- Output file creation

### 6.6 Full CLI Workflow From Fresh Endpoint Reports

Use this sequence when running a complete assessment from the command line.

1. Run endpoint agents on authorized systems.

Windows endpoint:

```powershell
python -m agents.windows.main
```

Linux endpoint:

```bash
python3 -m agents.linux.main
```

2. Copy endpoint reports into collector input:

```text
collector/input/incoming/
```

3. Review network discovery scope:

```text
config/discovery_scope.json
```

4. Run network discovery if authorized:

```powershell
python tools\network_discovery.py
```

5. Run the core collector:

```powershell
python -m collector.main
```

6. Build software and vulnerability snapshots:

```powershell
python tools\create_software_snapshot.py
python tools\update_cve_snapshot.py
python tools\correlate_cves_to_findings.py
```

7. Rebuild Kuzu if graph health is not clean:

```powershell
python tools\rebuild_kuzu_from_consolidated.py
```

8. Optionally run AI enrichment:

```powershell
python tools\run_ai_enrichment.py
```

9. Start the GUI:

```powershell
streamlit run gui\app.py
```

### 6.7 Full CLI Workflow Using Existing Demo Files

If the project already includes collector outputs and you only need to demonstrate or inspect the completed system:

1. Run preflight:

```powershell
python tools\preflight_check.py
```

2. Rebuild Kuzu if needed:

```powershell
python tools\rebuild_kuzu_from_consolidated.py
```

3. Start Streamlit:

```powershell
streamlit run gui\app.py
```

4. Open the following pages:

- Dashboard
- Pipeline Health
- Hosts
- Findings
- Graph
- Actions

This workflow is useful for final project review because it uses the existing completed dataset rather than requiring a fresh endpoint collection run.

### 6.8 Command Reference

| Task | Command |
| --- | --- |
| Setup Windows environment | `powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1` |
| Start GUI | `.\scripts\run_gui.ps1` |
| Start GUI if script execution is blocked | `powershell -ExecutionPolicy Bypass -File .\scripts\run_gui.ps1` |
| Run preflight | `python tools\preflight_check.py` |
| Run Windows agent | `python -m agents.windows.main` |
| Run Linux agent | `python3 -m agents.linux.main` |
| Run discovery | `python tools\network_discovery.py` |
| Run core collector | `python -m collector.main` |
| Run collector with AI | `python -m collector.main --with-ai` |
| Create software snapshot | `python tools\create_software_snapshot.py` |
| Update CVE snapshot | `python tools\update_cve_snapshot.py` |
| Correlate CVEs | `python tools\correlate_cves_to_findings.py` |
| Rebuild Kuzu | `python tools\rebuild_kuzu_from_consolidated.py` |
| Run AI enrichment | `python tools\run_ai_enrichment.py` |

### 6.6 Run Collector With AI Inline

```powershell
.\scripts\run_collector.ps1 -WithAI
```

Equivalent:

```powershell
python -m collector.main --with-ai
```

This is supported, but for reliability the recommended workflow is to run AI enrichment separately.

### 6.7 Run AI Enrichment Separately

```powershell
python tools\run_ai_enrichment.py
```

This reads the latest consolidated dataset and latest findings, then adds AI explanation/remediation outputs.

### 6.8 Run CVE Pipeline

Run software snapshot:

```powershell
python tools\create_software_snapshot.py
```

Update CVE snapshot:

```powershell
python tools\update_cve_snapshot.py
```

Generate CVE findings:

```powershell
python tools\correlate_cves_to_findings.py
```

### 6.9 Rebuild Kuzu From Latest Consolidated Dataset

If Kuzu is empty or inconsistent:

```powershell
python tools\rebuild_kuzu_from_consolidated.py
```

This reloads the latest `mapped_graph` into:

```text
collector/output/graph/sage_ch_kuzu.db
```

### 6.10 Run Preflight

```powershell
python tools\preflight_check.py
```

Use this before demos, grading, or moving to another PC.

## 7. GUI Usage

Start the GUI:

```powershell
.\scripts\run_gui.ps1
```

If PowerShell blocks script execution, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_gui.ps1
```

The sidebar provides the main navigation.

### 7.1 Home

The Home page provides:

- Project title and purpose
- Current host/finding metrics
- Graph persistence status
- Latest batch ID
- Primary workflow
- Data source summary

Use this page as the first screen for a demo.

### 7.2 Dashboard

The Dashboard is the main security posture page.

It shows:

- Overall posture message
- Host count
- Finding count
- Critical and high findings
- CVE finding count
- Highest-risk hosts
- Graph source and graph counts
- Vulnerability intelligence summary
- Weakest CIS Controls
- Severity distribution
- Priority findings

Use the Dashboard to explain assessment results at an executive or evaluator level.

### 7.3 Hosts

The Hosts page is used for host-level inspection.

Typical uses:

- Review assessed hosts
- Filter by host attributes
- Inspect software counts
- Inspect vulnerability counts
- Open host-level findings
- Review AI explanation/remediation for a host when available
- Export host reports when report buttons are available

Use this page when you want to drill down from overall posture into one endpoint.

### 7.4 Findings

The Findings page is used for triage and review.

It combines:

- Configuration findings from the rule engine
- CVE findings from the vulnerability correlation pipeline

Typical filters include:

- Finding type
- Severity
- Host
- Category
- CIS Control

Finding records may include:

- Host
- Severity
- Title
- Category
- Status
- Evidence
- Recommendation
- CVE ID
- CVSS score
- AI explanation

Use this page for detailed security review.

### 7.5 Graph

The Graph page visualizes relationships among graph entities.

It can use:

- Kuzu, when graph persistence is healthy
- Consolidated JSON fallback, when Kuzu is unavailable

The page shows:

- Graph source
- Node counts
- Edge counts
- Host-centered graph controls
- Rendered host neighborhood
- Rendered nodes and edges
- Assessment summary

Typical workflow:

1. Select a center host
2. Choose node types to include
3. Adjust max nodes
4. Inspect relationships among hosts, software, findings, controls, evidence, services, explanations, and remediation nodes

### 7.6 Batches

The Batches page shows recent output files and latest batch summary.

It is useful for:

- Confirming which batch is loaded
- Finding output files
- Checking finding totals
- Checking graph persistence status

### 7.7 Actions

The Actions page runs operational tasks from the GUI.

Available actions include:

- Run Collector
- Run AI Enrichment
- Rebuild Kuzu
- Create Software Snapshot
- Update CVE Snapshot
- Generate CVE Findings
- Run Full CVE Pipeline

Recommended GUI workflow:

1. Place endpoint reports in `collector/input/incoming`
2. Open Actions
3. Run Collector
4. Open Pipeline Health
5. Confirm core graph is complete
6. Optionally run AI Enrichment
7. Optionally run CVE pipeline
8. Review Dashboard, Findings, Hosts, and Graph

### 7.8 Pipeline Health

Pipeline Health is the operational status page.

It shows:

- Latest batch
- Collector status
- Core graph persistence status
- AI enrichment status
- Kuzu availability
- JSON graph node/edge counts
- Kuzu graph node/edge counts
- Incoming file count
- Processing batch count
- Processed batch count
- Failed batch count
- Stuck processing batches
- Latest output file paths
- Latest collector log lines

Use this page after every collector or AI run.

### 7.9 Settings

The Settings page shows project path and environment status information.

Use it to confirm:

- Collector paths
- Input/output paths
- Kuzu path
- Log path
- Basic health status

## 8. Output Files

Primary collector outputs are written under:

```text
collector/output/
```

Important files:

```text
consolidated_dataset_<batch>_<timestamp>.json
findings_dataset_<batch>_<timestamp>.json
assessment_summary_<batch>_<timestamp>.json
scoreboard_report_<batch>_<timestamp>.md
ai_host_explanations_<batch>_<timestamp>.json
ai_remediation_plan_<batch>_<timestamp>.md
```

Graph database:

```text
collector/output/graph/sage_ch_kuzu.db
```

CVE outputs:

```text
collector/output/software_snapshot/software_snapshot_latest.json
collector/output/cve_snapshot/cve_snapshot_latest.json
collector/output/cve_findings/cve_findings_latest.json
```

Collector audit log:

```text
collector/output/collector_audit.log
```

## 9. Moving To Another PC

To move SAGE-CH to another PC:

1. Copy the entire project folder.
2. Make sure existing demo files are included if you want the GUI to show current results:

   ```text
   collector/output/
   collector/input/processed/
   collector/manifests/
   outputs/discovery/
   ```

3. On the new PC, run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
   ```

4. Start the GUI:

   ```powershell
   .\scripts\run_gui.ps1
   ```

   If script execution is blocked, run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\run_gui.ps1
   ```

5. Open Pipeline Health.

6. If Kuzu is missing or empty, open Actions and click:

   ```text
   Rebuild Kuzu
   ```

The GUI can still fall back to consolidated JSON when Kuzu is unavailable, but the Graph page works best when Kuzu is rebuilt.

## 10. Troubleshooting

### 10.1 Streamlit Will Not Start

Run:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
```

Then:

```powershell
.\scripts\run_gui.ps1
```

If script execution is blocked, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_gui.ps1
```

If it still fails, run:

```powershell
.\.venv\Scripts\python.exe tools\preflight_check.py
```

### 10.2 Missing Python Module

Symptoms:

```text
ModuleNotFoundError
```

Fix:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 10.3 Empty Dashboard

Likely cause:

- No collector outputs exist
- Demo files were not copied to the new PC

Fix:

1. Copy existing files, or
2. Place endpoint reports in `collector/input/incoming`
3. Run the collector

### 10.4 Empty Graph

Likely causes:

- Kuzu DB is missing
- Kuzu DB is empty
- Graph persistence failed

Fix from GUI:

```text
Actions -> Rebuild Kuzu
```

Fix from CLI:

```powershell
python tools\rebuild_kuzu_from_consolidated.py
```

### 10.5 Batch Stuck In Processing

Pipeline Health shows processing batches.

This can happen if:

- Collector was interrupted
- AI phase took too long
- Python process was killed

Current recommendation:

- Do not manually delete the batch unless you understand the state.
- Review `collector/output/collector_audit.log`.
- Check whether a result manifest exists in `collector/manifests`.
- Re-run from a clean incoming batch when appropriate.

### 10.6 AI Enrichment Fails

Likely causes:

- Ollama is not running
- `gemma2:9b` is not installed
- Local LLM endpoint is unavailable

Check Ollama:

```powershell
ollama list
```

Pull model:

```powershell
ollama pull gemma2:9b
```

Run AI enrichment again:

```powershell
python tools\run_ai_enrichment.py
```

The core collector and graph can still work without AI.

### 10.7 NVD CVE Update Is Slow Or Fails

Likely causes:

- Network access unavailable
- NVD rate limiting
- API timeout

Recommendation:

- Avoid repeated CVE snapshot updates.
- Use existing `cve_snapshot_latest.json` for demos.
- Run CVE update only when needed.

## 11. Security And Safety Notes

SAGE-CH is designed for controlled assessment use.

Important safety properties:

- Endpoint agents are read-only.
- Network discovery is allowlisted.
- Discovery defaults should be reviewed before use.
- CVE correlation is high-signal but not version-perfect.
- AI remediation output should be reviewed before operational use.
- The system is not a replacement for enterprise EDR, vulnerability scanners, or configuration management tools.
