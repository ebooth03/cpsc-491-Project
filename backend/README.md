# Vulnerability Scanner Backend

Backend/API skeleton for the CPSC 491 Vulnerability Scanner.

The backend connects the project's scan engine, vulnerability detection
component, persistence layer, and frontend through shared data contracts
and API endpoints.

`POST /scans` runs the real scan engine in the background. Results are
kept in memory; the database, authentication, and CVE/NVD matching are
not implemented yet.

## Current Scope

Implemented:

- FastAPI application skeleton
- API routing structure
- Configuration structure
- Repository/data-access placeholder
- Shared Pydantic data contracts
- Five scan API routes with input validation
- Scan engine integration with background execution (KAN-102)
- API, contract, and integration tests

Not implemented:

- Database persistence (scans are lost when the backend restarts)
- Authentication/authorization
- CVE/NVD retrieval or matching
- Scan cancellation
- Live progress percentages (status is queued, running, then final)

## Project Structure

```text
app/
├── config/       # Backend configuration
├── models/       # Shared Pydantic data contracts
├── repository/   # Data-access layer
├── routes/       # FastAPI routes
└── main.py       # Application entry point

tests/            # API tests
```

## Shared Data Contracts

Sprint 1 establishes four shared contracts:

1. Scan configuration
2. Scan result
3. Vulnerability finding
4. Scan status

These contracts are defined in:

```text
app/models/contracts.py
```

They are intended to establish the interfaces between the backend,
scan engine, vulnerability detection component, and frontend.

Scanner-specific values may change as the contracts are finalized with
the owners of those components.

## Requirements

- Python 3.11+
- pip

## Setup

Clone the repository:

```bash
git clone <repository-url>
cd <repository-directory>/backend
```

Create a virtual environment.

### macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run the API

```bash
uvicorn app.main:app --reload
```

The API will run at:

```text
http://127.0.0.1:8000
```

FastAPI documentation:

```text
http://127.0.0.1:8000/docs
```

## Run Tests

```bash
pytest
```

## Initial API

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/scans` | Submit a scan configuration |
| GET | `/scans` | List scans |
| GET | `/scans/{scan_id}` | Retrieve a scan |
| GET | `/scans/{scan_id}/status` | Retrieve scan status |
| GET | `/scans/{scan_id}/results` | Retrieve scan results |

## Scan Execution

`POST /scans` validates the scan configuration, records the scan as
`queued`, and returns `201` immediately. The scan engine then runs in a
FastAPI background task (`app/services/scan_runner.py`):

```text
queued -> running -> completed | failed
```

Poll `GET /scans/{scan_id}/status` until the status is final, then read
`GET /scans/{scan_id}/results`. Engine output is converted into the
shared contracts with the scan engine's `backend_adapter`.

Notes:

- The engine's host discovery probes ports 22, 80 and 443. A host with
  none of them open is reported as not responding and its port scan is
  skipped; the result explains this in `errors`.
- Ports are scanned one at a time. Filtered ports wait the full
  `timeout`, so large ranges against remote hosts can take a long time.
- Backend tests replace the engine with a fake (`tests/conftest.py`),
  so they never touch the network.

## Next Backend Work

Future work will add persistence and scanner integration behind these
interfaces without requiring other components to depend directly on
those implementations.