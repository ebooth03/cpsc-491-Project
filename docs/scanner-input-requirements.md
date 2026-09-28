# Scanner Input Requirements

**Jira:** KAN-15 — Define Scanner Input Requirements  
**Project:** CPSC 491 Vulnerability Scanner

## 1. Purpose

Define the inputs required by the scanner and document the expected behavior for validating those inputs and producing scan results.

## 2. Current Inputs

### Target

The Scanner class accepts a target as a non-empty string.

The TCP scanning functions accept a target string representing an IPv4 address.

Target validation currently checks that the string is non-empty but does not verify that it is a valid IP address or hostname.

### Ports

The Scanner class accepts a collection of ports.

- At least one port must be provided.
- Each port must be an integer between 1 and 65535.

The TCP scanning functions accept an individual port or a start and end port for a range.

### Timeout

The TCP scanning and host discovery functions accept a timeout value.

The default timeout is 0.5 seconds.

### Host Discovery

Host discovery accepts a target and an optional timeout.

It probes TCP ports 22, 80, and 443 to determine whether the host appears reachable.

## 3. Current Output

The Scanner class returns a list of dictionaries containing:

- target
- port
- state
- service

The scan engine also defines structured result models:

- ServiceResult: port, protocol, state, service, product, and version
- HostResult: address, state, and services
- ScanResult: target, status, hosts, and optional error

## 4. Input Validation Requirements

The scanner should:

- Reject missing or empty targets.
- Validate port values and ensure they fall within the valid range of 1–65535.
- Require at least one port for a scan.
- Validate timeout values to prevent invalid configurations.
- Handle unreachable targets and connection errors gracefully.
- Provide clear error messages for invalid inputs.

## 5. Proposed Inputs for Future Development

The following inputs require confirmation from the team:

| Input | Purpose |
|---|---|
| Hostname support | Allow scanning targets specified by hostname |
| Port ranges | Allow users to configure ranges of ports |
| Protocol selection | Determine whether scanning supports TCP only or additional protocols |
| Scan timeout | Allow users to configure how long a probe waits |
| Service detection | Determine whether service identification is optional or automatic |

## 6. Questions for Team Agreement

1. Should targets support hostnames in addition to IPv4 addresses?
2. What ports should be scanned by default?
3. Should the scanner support TCP only or both TCP and UDP?
4. Should timeout values be configurable by the user?
5. Should service identification run automatically after port scanning?
6. Which result model should be used as the standard output between components?

## 7. Acceptance Criteria

- Current scanner inputs and behavior are documented.
- Required and optional inputs are identified.
- Input validation expectations are documented.
- Expected scan output is described.
- Open design questions are identified for team agreement.
