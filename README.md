# Threat Intelligence Automation — Python, MISP & Docker

An automated threat intelligence processing pipeline built with Python, MISP, Docker, and macOS LaunchAgent.

## Project Overview

This project demonstrates how security teams can automate the collection, validation, deduplication, and management of Indicators of Compromise (IOCs).

The pipeline processes a local training feed, prepares a structured MISP event, securely connects to a self-hosted MISP instance, checks for existing events, and generates execution reports.

## Key Features

- Automated threat intelligence collection from a JSON training feed
- IOC validation for IP addresses, domains, and URLs
- Case-insensitive domain deduplication
- MISP event creation through the REST API
- Duplicate event detection and prevention
- HTTPS certificate verification
- API authentication through environment variables
- JSON execution reports and application logging
- Automated scheduling using macOS LaunchAgent
- Python unit tests

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.12 | Automation and data processing |
| MISP 2.5.50 | Threat intelligence management |
| Docker | Local MISP infrastructure |
| PyMISP | MISP API integration |
| JSON | Indicator feeds and execution reports |
| unittest | Automated validation tests |
| macOS LaunchAgent | Scheduled pipeline execution |
| Git & GitHub | Version control and documentation |

## Pipeline Architecture

```text
Local Training Feed
        |
        v
Collect Indicators
        |
        v
Validate & Deduplicate
        |
        v
Prepare MISP Event
        |
        v
Secure HTTPS API Connection
        |
        v
Check Existing MISP Events
        |
        +---- Event Exists --> Skip Duplicate
        |
        +---- New Event ----> Import into MISP
        |
        v
Generate JSON Report
        |
        v
Write Execution Logs
```

## Project Structure

```text
Threat-Intel-Automation/
├── src/
│   ├── main.py
│   ├── collect_indicators.py
│   ├── validate_indicators.py
│   ├── prepare_misp_event.py
│   ├── import_misp_event.py
│   ├── check_duplicate_event.py
│   ├── report_generator.py
│   └── logger.py
├── tests/
│   └── test_indicators.py
├── scripts/
│   └── run_pipeline.sh
├── data/
├── reports/
├── logs/
├── requirements.txt
├── .gitignore
└── README.md
```

The MISP Docker installation is maintained locally and excluded from this repository.

## Setup

1. Install Python 3.12 and Docker.
2. Set up a local MISP instance.
3. Clone this repository.
4. Create and activate a Python virtual environment.
5. Install dependencies:

```bash
pip install -r requirements.txt
```

6. Configure the following environment variables in a local `.env` file:

```dotenv
MISP_URL=https://localhost:8443
MISP_API_KEY=YOUR_READ_ONLY_KEY
MISP_IMPORT_API_KEY=YOUR_IMPORT_KEY
```

7. Configure certificate verification using your trusted local MISP certificate.

Never commit API keys, passwords, private certificates, or environment files.

## Running the Pipeline

```bash
python src/main.py
```

## Running Unit Tests

```bash
python -m unittest discover -s tests -v
```

## Example Test Results

The local training feed contains seven indicators.

| Metric | Result |
|---|---|
| Indicators collected | 7 |
| Valid indicators | 3 |
| Duplicates filtered | 2 |
| Invalid indicators filtered | 2 |
| Unit tests | 7 passed |
| MISP event | Successfully created |
| Duplicate prevention | Verified |
| HTTPS verification | Enabled |
| LaunchAgent manual execution | Successful |

## Scheduling

The pipeline is configured to run daily at 9:00 AM using a macOS LaunchAgent.

The scheduler invokes `scripts/run_pipeline.sh`, which executes the Python pipeline and records its results.

The scheduled run requires the Mac and local MISP service to be available.

## Security Considerations

- API keys are stored outside source code.
- HTTPS certificate verification is enabled.
- Generated reports and logs are excluded from Git.
- Private SSL keys and local Docker configuration are excluded.
- Training events are kept unpublished and restricted to the local organization.
- Duplicate prevention reduces redundant MISP events.

## Current Scope

This project currently uses a controlled local training feed with simulated indicators.

Future enhancements could include live threat intelligence feeds, scheduled enrichment, additional IOC
