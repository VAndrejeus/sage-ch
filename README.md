# SAGE-CH

Cross-platform endpoint cyber hygiene collection framework.

SAGE-CH currently includes:
- Windows endpoint agent
- Linux endpoint agent
- Central collector (early phase)

Agents collect system information in read-only mode and output structured JSON reports.  
The collector ingests JSON reports and produces a consolidated dataset.

## Run Windows Agent

From project root:

python -m agents.windows.main

## Run Linux Agent

From project root:

python3 -m agents.linux.main

## Run Collector

From project root:

python -m collector.main

On Linux:

python3 -m collector.main

## Output Locations

Windows agent reports:

agents/windows/output/

Linux agent reports:

agents/linux/output/

Collector input folder:

collector/input/

Collector output folder:

collector/output/

## Report Format

Endpoint reports:

endpoint_report_YYYYMMDD_HHMM.json

Collector output:

consolidated_dataset_YYYYMMDD_HHMM.json

## Notes

- Agents run in read-only mode.
- Windows and Linux outputs are being normalized to a shared schema.
- Copy endpoint report JSON files into `collector/input/` before running the collector.