# SAGE-CH

Endpoint security data collection framework (Windows + Linux).  
Agents collect system info and output JSON reports.

## Run Windows Agent

From project root:
python -m agents.windows.main


## Run Linux Agent

From project root:
python3 -m agents.linux.main


Reports are written to:
agents/<os>/output/
Format:
endpoint_report_YYYYMMDD_HHMM.json