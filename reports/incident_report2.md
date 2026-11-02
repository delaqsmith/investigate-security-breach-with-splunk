# Incident Report: SOC-001

Analyst: Dela Smith
Date investigated: 2026-11-02
Status: Investigation documented; remediation not verified
Classification: Suspected Endpoint Compromise / Command-and-Control Activity
Severity: High (investigative assessment)

## Executive Summary

Splunk analysis identified unusual process execution activity on the Windows endpoint BSTOLL-L.froth.ly. Analysis of Windows Security Event Logs revealed elevated process creation activity involving powershell.exe and cmd.exe. Further examination identified Base64-encoded PowerShell commands and system reconnaissance activity involving netstat, reg query, and wmic. The combination of encoded PowerShell execution and reconnaissance behavior was consistent with activity associated with the PowerShell Empire command-and-control (C2) framework.

## Key Findings

- Compromised Host: BSTOLL-L.froth.ly |
- Malware Type: PowerShell Empire C2 |
- Key Evidence: Encoded PowerShell with -enc, -noP, -sta, -w 1 flags |
- Reconnaissance: netstat, reg query, wmic commands executed post-compromise |

## MITRE ATT&CK Mapping
- Execution T1059.001 (Command and Scripting Interpreter: PowerShell). Evidence: encoded PowerShell commands executed on BSTOLL-L.
- Defense Evasion T1027 (Obfuscated Files or Information). Evidence: Base64-encoded payloads using the -enc flag.
- Defense Evasion T1562.001 (Impair Defenses: Disable or Modify Tools). Evidence: PowerShell profile bypass using the -noP flag.
- Discovery T1082 (System Information Discovery). Evidence: reg query and wmic commands for host enumeration.
- Discovery T1049 (System Network Connections Discovery). Evidence: netstat commands to map open ports.
- Command and Control T1071.001 (Application Layer Protocol: Web Protocols). Evidence: C2 communication over HTTP/HTTPS.

## Recommendations

1. **Immediate**: Isolate BSTOLL-L from the network to prevent further C2 communication
2. **Short-term**: Reset credentials for the compromised user account and all accounts that logged into BSTOLL-L
3. **Medium-term**: Deploy PowerShell script block logging (Event ID 4104) and constrained language mode
4. **Long-term**: Implement application whitelisting to prevent unauthorized PowerShell execution patterns