# Microsoft Sentinel SOC Investigation & Detection Lab

> Built to understand how SOC analysts investigate real authentication attacks — from initial telemetry through detection engineering, incident response, and endpoint threat hunting — using a live Azure environment with actual external attack traffic.

---

## Table of Contents

- [Lab Overview](#lab-overview)
- [Environment & Architecture](#environment--architecture)
- [Phase 1 — Initial Telemetry Analysis](#phase-1--initial-telemetry-analysis)
- [Phase 2 — Authentication Anomaly Investigation](#phase-2--authentication-anomaly-investigation)
- [Phase 3 — Source IP & Attacker Behavior Analysis](#phase-3--source-ip--attacker-behavior-analysis)
- [Phase 4 — Failed & Successful Login Correlation](#phase-4--failed--successful-login-correlation)
- [Phase 5 — Logon Type Analysis](#phase-5--logon-type-analysis)
- [Phase 6 — Detection Engineering](#phase-6--detection-engineering)
- [Phase 7 — Incident Response](#phase-7--incident-response)
- [Phase 8 — Endpoint Threat Hunting](#phase-8--endpoint-threat-hunting)
- [Incident Report](#incident-report)
- [Key Findings](#key-findings)
- [What This Detection Misses](#what-this-detection-misses)
- [Skills Demonstrated](#skills-demonstrated)

---

## Lab Overview

This lab simulates a realistic Tier 1 SOC analyst workflow using Microsoft Sentinel, Microsoft Defender, and a live Windows Server VM deployed on Azure. Rather than using a pre-built dataset, this environment was exposed to the internet and collected **real external attack traffic**, including active brute-force attempts from external IP addresses.

The lab covers the full investigation lifecycle:
- Telemetry collection and baseline review
- Anomaly identification and authentication investigation
- Attacker behavior analysis and pattern recognition
- Custom detection rule engineering with MITRE ATT&CK mapping
- Incident triage and severity assessment
- Endpoint pivot to check for post-authentication execution

**Timeframe:** May 4–7, 2026  
**Environment:** Azure (live, internet-exposed Windows Server VM)  
**Primary Tool:** Microsoft Sentinel + Microsoft Defender XDR  
**Query Language:** KQL (Kusto Query Language)

---

## Environment & Architecture

| Component | Details |
|---|---|
| Virtual Machine | Windows Server 2022, deployed via Azure |
| Log Source | Windows Security Events via Azure Monitor Agent (AMA) |
| SIEM | Microsoft Sentinel (soc-lab-workspace) |
| Data Table | SecurityEvent |
| Connector | Windows Security Events via AMA |
| Retention | 30 days analytics tier |

The VM was intentionally internet-exposed to generate real telemetry. Within hours of deployment, external scanning and brute-force activity began — providing authentic attack data to investigate rather than simulated or pre-packaged logs.

---

## Phase 1 — Initial Telemetry Analysis

**Objective:** Establish a baseline of what event types are present in the environment before diving into specific investigations.

### KQL Query
```kql
SecurityEvent
| summarize EventCount=count() by EventID
| sort by EventCount desc
```

### Findings

The query returned 11 distinct Event ID types. Key events observed:

| Event ID | Description | Count | Significance |
|---|---|---|---|
| 4688 | Process Creation | 81 | Tracks new process execution — key for endpoint hunting |
| 4673 | Privileged Service Called | 31 | Privilege usage activity |
| 4627 | Group Membership Information | 15 | Account group context |
| 4624 | Successful Logon | 15 | Confirmed authentication events |
| 4672 | Special Privileges Assigned | 15 | Admin-level logon indicator |
| 4625 | Failed Logon | (investigated below) | Primary attack indicator |

**Analyst Note:** The high volume of Event ID 4688 (process creation) relative to successful logons warranted a separate endpoint investigation in Phase 8. The presence of 4672 alongside 4624 indicated privileged account activity requiring correlation.

---

## Phase 2 — Authentication Anomaly Investigation

**Objective:** Identify which accounts were being targeted by failed authentication attempts and assess whether the pattern was consistent with automated attack tooling.

### KQL Query
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by TargetUserName
| sort by FailedAttempts desc
```

### Findings

| TargetUserName | FailedAttempts | Assessment |
|---|---|---|
| administrator | 14 | Default admin account — high-value target |
| scanner | 13 | Non-existent account — automated tool behavior |
| scans | 13 | Non-existent account — automated tool behavior |
| scan | 13 | Non-existent account — automated tool behavior |
| socadmin | 12 | Lab account — targeted specifically |
| Test | 2 | Common default account guess |

**Key Insight:** The accounts `scanner`, `scans`, and `scan` do not exist in this environment. Attempts against non-existent accounts with near-identical names and identical attempt counts is a strong indicator of **automated credential stuffing or scanning tooling** — not a human attacker manually guessing passwords. This pattern is commonly associated with tools that iterate through wordlists.

---

## Phase 3 — Source IP & Attacker Behavior Analysis

**Objective:** Identify the source IP addresses responsible for the failed authentication activity and assess the volume and distribution of attempts.

### KQL Query
```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts=count() by IpAddress
| sort by Attempts desc
```

### Findings

| Source IP | Failed Attempts | Assessment |
|---|---|---|
| 45.142.193.145 | 55 | Primary attacker — high-volume automated scanning |
| 67.161.220.109 | 12 | Secondary source — lower volume activity |

**Analyst Note:** IP 45.142.193.145 was responsible for the majority of attack volume at 55 attempts. This IP was flagged for further correlation in Phase 4 to determine whether any successful authentication followed the failed attempts — which would indicate a successful brute-force compromise.

---

## Phase 4 — Failed & Successful Login Correlation

**Objective:** Correlate Event ID 4625 (failed logon) with Event ID 4624 (successful logon) by source IP to determine whether any attacker IP successfully authenticated after repeated failures — the key indicator of a successful brute-force attack.

### KQL Query
```kql
SecurityEvent
| where EventID in (4624, 4625)
| summarize EventCount=count() by IpAddress, EventID
| sort by EventCount desc
```

### Findings

| IpAddress | EventID | EventCount | Assessment |
|---|---|---|---|
| — | 4624 | 174 | Internal/system logons (no external IP) |
| 45.142.193.145 | 4625 | 55 | Failed attempts only — no successful logon |
| 67.161.220.109 | 4625 | 12 | Failed attempts only |
| 67.161.220.109 | 4624 | 6 | Successful logons — requires investigation |

**Critical Finding:** IP 45.142.193.145, responsible for 55 failed attempts, shows **zero successful logons** — indicating the brute-force attack was unsuccessful against this environment. However, IP 67.161.220.109 shows **both 12 failed attempts AND 6 successful logons**, which required further investigation to determine whether the successful logons were related to the failed attempts or represented legitimate activity.

**Analyst Decision:** The 174 successful logons with no associated external IP are consistent with internal system processes and service account activity — assessed as legitimate after reviewing logon types in Phase 5.

---

## Phase 5 — Logon Type Analysis

**Objective:** Analyze the logon type distribution of failed authentication attempts to understand the attack vector and distinguish remote attacks from local activity.

### KQL Query
```kql
SecurityEvent
| where EventID == 4625
| summarize Count=count() by LogonType
| sort by Count desc
```

### Findings

| Logon Type | Count | Description | Assessment |
|---|---|---|---|
| Type 3 | 58 | Network logon | Remote authentication over network — confirms external attack vector |
| Type 7 | 6 | Unlock logon | Workstation unlock attempts |
| Type 10 | 3 | Remote Interactive (RDP) | Direct RDP connection attempts |

**Key Insight:** The overwhelming majority of failed logons (58 of 67) were **Type 3 Network logons**, confirming these were remote network-based authentication attempts rather than local or RDP-based attacks. This is consistent with automated credential stuffing tools that target SMB or network authentication services rather than interactive RDP sessions.

---

## Phase 6 — Detection Engineering

**Objective:** Build a custom detection rule in Microsoft Sentinel that would automatically alert on this behavior going forward, with proper MITRE ATT&CK mapping, severity classification, and response guidance.

### Detection Rule Configuration

| Setting | Value |
|---|---|
| Detection Name | Excessive Failed Logons From Single IP |
| Frequency | Every Hour |
| Lookback Period | 1 Hour |
| Severity | High |
| Category | Credential Access |
| MITRE Technique | T1110 — Brute Force |

### Detection Query
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
```

**Detection Logic:** Flags any single source IP that generates more than 10 failed logon attempts within any 5-minute window — a threshold calibrated to catch automated tooling while avoiding false positives from legitimate users mistyping passwords.

### Alert Description
> *"Microsoft Sentinel detected excessive failed authentication attempts originating from a single source IP within a short time window. This behavior may indicate brute-force or password spraying activity targeting Windows accounts."*

### Recommended Response Actions
1. Investigate the source IP against threat intelligence feeds
2. Review affected accounts for suspicious authentication activity
3. Determine whether any successful logons occurred after repeated failures
4. Assess whether brute-force behavior is present
5. Consider blocking the source IP at the firewall
6. Reset credentials for targeted accounts
7. Enable MFA for affected accounts

---

## Phase 7 — Incident Response

**Objective:** Triage the incident generated by the custom detection rule and document the investigation workflow.

### Incident Details

| Field | Value |
|---|---|
| Incident ID | IR-001 |
| Title | Excessive Failed Logons Detected From Single IP |
| Severity | High |
| Status | Active |
| First Activity | May 7, 2026 — 2:55 AM |
| Incident Created | May 7, 2026 — 6:52 PM |
| Source IP | 45.142.193.145 |
| Affected Asset | win-sec-events (Azure VM) |

### Triage Workflow

**Step 1 — Alert Validation**
Reviewed the triggered incident in Sentinel. Confirmed the alert fired correctly based on the detection rule threshold. Single active alert, 1 affected asset.

**Step 2 — Severity Assessment**
Rated High based on: external source IP, volume of attempts (55), targeting of default admin account, and automated tooling indicators. Downgrade to Medium would be appropriate if threat intel confirms the IP as a known benign scanner.

**Step 3 — Compromise Assessment**
Correlated Event ID 4624 against 4625 for the source IP. Confirmed **no successful logons from 45.142.193.145** — attack was unsuccessful. Primary compromise risk ruled out.

**Step 4 — Scope Assessment**
Attack isolated to single source IP targeting single VM. No lateral movement indicators observed. No internal propagation detected.

**Step 5 — Escalation Decision**
Given no confirmed compromise and no lateral movement, this incident would be classified as **contained, no further escalation required** in a real environment. Recommended actions: IP block, credential review, MFA enforcement.

---

## Phase 8 — Endpoint Threat Hunting

**Objective:** Pivot from authentication analysis to endpoint telemetry to determine whether any command execution occurred on the target system — a critical step in ruling out post-authentication activity.

**Analyst Reasoning:** Even though Phase 4 showed no successful logons from the primary attacking IP, a thorough investigation requires checking whether any process execution occurred that could indicate a different attack vector or pre-existing compromise.

### KQL Query
```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName contains "cmd.exe"
| project TimeGenerated, Account, Computer, NewProcessName, CommandLine
| sort by TimeGenerated desc
```

### Findings

| TimeGenerated | Account | Computer | NewProcessName | CommandLine |
|---|---|---|---|---|
| May 6, 2026 8:00:35 | WORKGROUP\win-sec-eve | win-sec-events | C:\Windows\System32\cmd.exe | cmd.exe |

**Assessment:** One instance of cmd.exe execution observed, executed under the local system account during morning hours. The execution context (system account, morning timestamp, no suspicious command line arguments) is consistent with **normal system or scheduled task activity** — not adversarial execution. Assessed as benign after reviewing account context and timing.

**Analyst Note:** In a real environment this finding would be cross-referenced against the change management calendar and system administrators would be asked to confirm whether this aligns with scheduled maintenance activity.

---

## Incident Report

**Incident ID:** IR-001  
**Date:** May 7, 2026  
**Analyst:** Nawid Farani  
**Severity:** High (Initial) → Medium (Post-Investigation)  
**Status:** Closed — No Compromise Confirmed  

---

### Executive Summary

On May 7, 2026, Microsoft Sentinel generated a High severity alert for excessive failed logon attempts originating from external IP 45.142.193.145 against the soc-lab Azure Windows Server environment. Investigation confirmed the activity was consistent with automated credential stuffing tooling targeting default Windows account names. No successful authentication from the attacking IP was observed. A secondary IP (67.161.220.109) showing both failed and successful logons was assessed as legitimate based on logon context. Endpoint threat hunting found no evidence of malicious process execution. The attack was unsuccessful and the environment was not compromised.

---

### Timeline

| Time | Event |
|---|---|
| May 4, 2026 2:00 PM | Azure VM deployed, AMA connector configured |
| May 6, 2026 7:48 PM | Last telemetry received from AMA connector |
| May 7, 2026 2:55 AM | First brute-force activity from 45.142.193.145 |
| May 7, 2026 6:22 PM | Source IP analysis completed — 55 attempts identified |
| May 7, 2026 6:52 PM | Custom detection rule fires — Incident IR-001 created |
| May 7, 2026 6:52 PM | Incident triaged — no compromise confirmed |

---

### Indicators of Compromise

| Indicator | Type | Value | Disposition |
|---|---|---|---|
| 45.142.193.145 | Source IP | 55 failed logon attempts | Malicious — automated scanner |
| 67.161.220.109 | Source IP | 12 failed, 6 successful logons | Investigated — assessed benign |
| administrator | TargetUserName | 14 failed attempts | Targeted — no compromise |
| scanner / scans / scan | TargetUserName | 13 attempts each | Automated wordlist — accounts don't exist |

---

### Root Cause

Internet-exposed Windows Server VM with default RDP/SMB ports accessible. Automated scanning tools actively probe exposed Azure VMs for default credentials within hours of deployment.

---

### Recommendations

1. **Immediate:** Block 45.142.193.145 at the NSG (Network Security Group) level
2. **Short term:** Restrict RDP and SMB access to known IP ranges only
3. **Short term:** Enable MFA on all accounts with network logon permissions
4. **Long term:** Implement account lockout policy — lock after 5 failed attempts in 10 minutes
5. **Long term:** Deploy Just-In-Time VM access via Microsoft Defender for Cloud

---

## Key Findings

- **67 total failed authentication attempts** from 2 external source IPs over a 16-hour window
- **Automated tooling confirmed** — username pattern (scanner, scans, scan) with identical attempt counts indicates scripted credential stuffing, not manual attack
- **No successful compromise** — primary attacking IP (45.142.193.145) shows zero successful logons
- **Attack vector confirmed as Type 3 Network logon** (86% of attempts) — remote network-based attack, not RDP
- **Endpoint pivot clean** — one cmd.exe execution found, assessed as legitimate system activity
- **Detection gap identified** — 16 hours elapsed between first attack activity (2:55 AM) and incident creation (6:52 PM) due to detection rule being created after initial activity

---

## What This Detection Misses

A strong analyst thinks critically about the limits of their own detections. This rule has known gaps:

**Low and slow attacks** — An attacker making 2-3 attempts per hour over several days would never hit the threshold of 10 failures in 5 minutes. A time-based detection with a longer lookback would be needed.

**Password spraying** — Spraying one password across many accounts from one IP would generate high 4625 volume and would be caught. But spraying from many IPs with few attempts each (distributed spray) would evade this detection entirely.

**Credential stuffing from rotating IPs** — Botnets that rotate source IPs with each attempt would never trigger a single-IP threshold rule. Detecting this requires user-based anomaly detection rather than IP-based thresholds.

**Post-authentication activity** — This detection only catches the brute force attempt itself. A separate detection on Event ID 4624 followed by 4688 (process creation) within a short window would be needed to catch successful compromise followed by execution.

---

## Skills Demonstrated

| Skill | Evidence |
|---|---|
| Azure VM Deployment | Deployed Windows Server 2022, configured soc-lab-rg resource group |
| SIEM Configuration | Connected AMA connector, verified SecurityEvent table ingestion |
| KQL Query Development | 7 distinct investigation queries written and executed |
| Authentication Investigation | Event ID 4624/4625 correlation, logon type analysis |
| Attacker Behavior Analysis | Identified automated tooling via username pattern recognition |
| Detection Engineering | Custom rule with threshold logic, MITRE mapping, alert enrichment |
| MITRE ATT&CK Mapping | T1110 Brute Force — Credential Access |
| Incident Triage | Severity assessment, compromise determination, escalation decision |
| Endpoint Threat Hunting | Event ID 4688 process creation analysis, cmd.exe investigation |
| Incident Documentation | Full IR report with timeline, IOCs, root cause, recommendations |
| Detection Gap Analysis | Identified 4 specific evasion techniques this detection would miss |
