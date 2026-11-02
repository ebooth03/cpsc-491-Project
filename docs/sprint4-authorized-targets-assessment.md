# Sprint 4 Interim Assessment: Authorized Scan Targets

Contributor: Daniel Salaita
Assessment date: November 2, 2026

## Control and risk

Restrict POST /scans to explicitly approved IPv4 targets and require
an explicit authorization acknowledgement before creating scan records
or scheduling scanner activity.

Risk: A valid IPv4 address could previously be submitted without
checking whether the target was approved for scanning.

## Acceptance criteria

1. An approved target with Boolean true acknowledgement is accepted.
2. Missing, false, or non-Boolean acknowledgement is rejected.
3. Targets outside the server-configured allowlist are rejected.
4. Missing or malformed allowlist configuration blocks scanning.
5. Rejected requests never call the scan engine or create scan records.
6. Client-supplied options cannot override the server allowlist.
7. The frontend starts with an unchecked acknowledgement checkbox,
   blocks unchecked submission, and sends Boolean true when checked.

## Assessment procedures

Use API integration tests with the existing FakeScanEngine to observe
whether requests reach the scanner. For rejected requests, assert the
HTTP status, zero engine calls, and unchanged scan storage.

Use negative testing for missing/false/malformed acknowledgement,
unapproved targets, invalid IPv4 input, and missing/malformed allowlists.
Use positive testing for approved targets, multiple allowlist entries,
and whitespace normalization.

Use jsdom frontend tests to verify unchecked submission makes no
request and checked submission sends the expected acknowledgement.
Run the backend and frontend regression suites.

## Actual local results

- Authorization tests: 22 passed.
- Full backend suite, including authorization tests: 140 passed.
- Full frontend suite: 30 passed.
- Backend runs reported one Starlette TestClient deprecation warning.
- Scanner calls were mocked; no live network scan was performed.

Test sources:
- ../backend/tests/test_scan_authorization.py
- ../frontend/tests/scan-states.test.cjs

## Interim status

Implemented and locally verified for the POST /scans API entry point
and frontend acknowledgement behavior.

Overall assessment remains partially verified pending PR review,
CI evidence, and deployment configuration verification.

An acknowledgement is a user declaration; it does not independently
prove ownership or permission. This change does not implement user
authentication, role-based authorization, a durable approval/audit
record, or enforcement for direct CLI/engine invocation.

## Configuration

Set SCANNER_APPROVED_TARGETS in the backend process environment to a
comma-separated list of explicitly approved individual IPv4 addresses.
CIDR ranges and IPv6 entries are not supported by this control.
Missing, empty, or malformed configuration blocks API scans.

Example for an explicitly approved local test target:
    export SCANNER_APPROVED_TARGETS="127.0.0.1"

API clients must include:
    "options": {"authorization_acknowledged": true}

The frontend collects this declaration using an unchecked checkbox.
Configure actual targets only after their approval has been established.

## Remaining work and evidence links

- Link the Sprint 4 Jira implementation, testing, and assessment tasks.
- Link the pull request and its reviewed commit.
- Link the CI run and retained test reports.
- Verify the deployed backend uses the intended approved-target list.
- Record the target approval source, approver, scope, and validity period.
- Track authentication, durable audit records, and other scan entry
  points as follow-up gaps.
- Add this assessment and evidence links to the group Google Doc.
