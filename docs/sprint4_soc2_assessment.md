# Sprint 4 – SOC 2 Security Control Verification

**Control Owner:** Jonathan Nunez  
**Project:** Vulnerability Scanner  
**SOC 2 Alignment:** CC7.1 – Input Validation and Resource Limits

## Control Objective

Ensure that invalid scan configurations and excessive scanning requests are rejected before execution to reduce unintended network activity, resource exhaustion, and application instability.

## Security Risks

The assessed risks include invalid IPv4 addresses, out-of-range TCP ports, reversed port ranges, excessive TCP scan sizes, unsupported scan configuration options, unrestricted concurrent scanning, and uncontrolled API request handling.

## Assessment Procedures and Results

| Control Requirement | Test Procedure | Actual Result | Status |
|---|---|---|---|
| IPv4 validation | Submit invalid IPv4 targets through POST /scans | Invalid targets rejected with HTTP 422; engine not invoked | Passed |
| TCP port boundaries | Submit ports outside 1–65535 | Invalid ranges rejected with HTTP 422 | Passed |
| Port-range ordering | Submit a reversed TCP port range | Rejected with HTTP 422 | Passed |
| Maximum scan size | Submit ranges of 1,024 and 1,025 ports | 1,024 accepted; 1,025 rejected | Passed |
| Supported options | Submit empty and unsupported options | Empty accepted; unsupported rejected with HTTP 422 | Passed |
| Concurrency restrictions | Submit a request with two reservations occupied | Additional request rejected with HTTP 429 | Passed |
| Controlled rejection | Inspect engine calls and scan storage after invalid requests | No engine execution or scan records created | Passed |

## Automated Test Execution

**KAN-106 Security Tests**

Command: `PYTHONPATH=backend:. python -m pytest backend/tests/test_soc2_security_controls.py -v`

Result: **16 passed, 1 warning.**

**Full Project Regression Suite**

Command: `PYTHONPATH=backend:. python -m pytest -q`

Result: **374 passed, 1 warning.**

## Supporting Evidence

**KAN-103 – Maximum TCP Scan Size**
- [Jira KAN-103](https://ebooth03.atlassian.net/browse/KAN-103)
- [Pull Request #35](https://github.com/ebooth03/cpsc-491-Project/pull/35)
- [Successful CI/CD](https://github.com/ebooth03/cpsc-491-Project/actions/runs/41549770315)

**KAN-104 – Supported Scan Options**
- [Jira KAN-104](https://ebooth03.atlassian.net/browse/KAN-104)
- [Successful CI/CD](https://github.com/ebooth03/cpsc-491-Project/actions/runs/41552205037)

**KAN-105 – Concurrent Scan Limits**
- [Jira KAN-105](https://ebooth03.atlassian.net/browse/KAN-105)
- `backend/tests/test_scan_concurrency.py`
- 13 dedicated tests passed; 358 regression tests passed across five consecutive runs.

**KAN-106 – Security Testing and Evidence**
- [Jira KAN-106](https://ebooth03.atlassian.net/browse/KAN-106)
- `backend/tests/test_soc2_security_controls.py`
- 16 dedicated security tests passed; 374 full regression tests passed.

## Remaining Security Gaps

The concurrency limiter currently operates within a single backend process. Deployments using multiple workers or server instances would require shared coordination to enforce a global limit.

The existing in-memory scan history is not persistent across backend restarts.

## Interim Assessment Status

**Locally Verified – CI/CD verification pending for KAN-105 and KAN-106.**

The selected input-validation and resource-limit controls passed the executed local security tests. The assessment does not establish full SOC 2 compliance.