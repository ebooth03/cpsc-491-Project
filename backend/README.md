# Vulnerability Scanner Backend

Backend/API skeleton for the CPSC 491 Vulnerability Scanner.

The backend connects the project's scan engine, vulnerability detection
component, persistence layer, and frontend through shared data contracts
and API endpoints.

This Sprint 1 version establishes those interfaces only. It does not
implement the scanner, database, authentication, or CVE/NVD matching.

## Current Scope

Implemented:

- FastAPI application skeleton
- API routing structure
- Configuration structure
- Repository/data-access placeholder
- Shared Pydantic data contracts
- Five initial scan API routes
- Sample request/response data
- Basic API tests

Not implemented:

- Scanner integration
- Database persistence
- Authentication/authorization
- CVE/NVD retrieval or matching
- Background scan execution
- Real-time status updates

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

## Stub Behavior

All five endpoints currently return fixed sample data.

`POST /scans` accepts and validates the shared scan-configuration
contract, but it does not start a scanner or save anything.

The other endpoints do not query a database.

This is intentional. The purpose of this Sprint 1 skeleton is to give
the scanner, vulnerability-detection, frontend, and testing work a
stable backend interface to develop against.

## Next Backend Work

Future work will add persistence and scanner integration behind these
interfaces without requiring other components to depend directly on
those implementations.