# Microsoft Sentinel SOC Investigation & Detection Lab

> I deployed an internet-exposed Windows Server VM on Azure to collect real security telemetry. Within hours a real external threat actor found it and launched a brute force attack. This documents the full investigation — from initial reconnaissance detection through threat intelligence confirmation — using Microsoft Sentinel, KQL, and live Azure infrastructure.

---

## Table of Contents

- [Lab Overview](#lab-overview)
- [Environment & Architecture](#environment--architecture)
- [Understanding the Data — Two Separate Stories](#understanding-the-data--two-separate-stories)
- [Phase 1 — Initial Telemetry Baseline](#phase-1--initial-telemetry-baseline)
- [Phase 2 — Failed Authentication Investigation](#phase-2--failed-authentication-investigation)
- [Phase 3 — Attack Timeline Analysis](#phase-3--attack-timeline-analysis)
- [Phase 4 — Source IP Analysis](#phase-4--source-ip-analysis)
- [Phase 5 — Threat Intelligence Enrichment](#phase-5--threat-intelligence-enrichment)
- [Phase 6 — Failed vs Successful Login Correlation](#phase-6--failed-vs-successful-login-correlation)
- [Phase 7 — Logon Type Analysis](#phase-7--logon-type-analysis)
- [Phase 8 — Detection Engineering](#phase-8--detection-engineering)
- [Phase 9 — Incident Response & Triage](#phase-9--incident-response--triage)
- [Phase 10 — Endpoint Threat Hunting](#phase-10--endpoint-threat-hunting)
- [Incident Report — IR-001](#incident-report--ir-001)
- [What This Detection Misses](#what-this-detection-misses)
- [Key Takeaways](#key-takeaways)

---

## Lab Overview

This lab was built to simulate real Tier 1 SOC analyst workflows using Microsoft Sentinel and live Azure infrastructure. Unlike labs that use pre-packaged datasets, this environment was intentionally internet-exposed to collect authentic attack telemetry.

What I didn't plan for — within hours of deployment, a real external threat actor found the VM and launched a brute force attack. This turned a learning exercise into a real investigation.

**What this lab demonstrates:**
- Live Azure VM deployment and SIEM configuration
- Real external attack detection and investigation
- Separating analyst-generated noise from real threat actor activity
- Threat intelligence enrichment using AbuseIPDB
- KQL-based detection engineering with MITRE ATT&CK mapping
- Full incident response workflow from detection to closure
- Endpoint threat hunting via process creation analysis

**Timeframe:** May 4–8, 2026
**Environment:** Azure (live, internet-exposed Windows Server VM)
**Tools:** Microsoft Sentinel, Microsoft Defender XDR, AbuseIPDB
**Query Language:** KQL (Kusto Query Language)

---

## Environment & Architecture

| Component | Details |
|---|---|
| Virtual Machine | Windows Server 2022 — deployed via Azure |
| Resource Group | soc-lab-rg |
| Log Source | Windows Security Events via Azure Monitor Agent (AMA) |
| SIEM | Microsoft Sentinel (soc-lab-workspace) |
| Data Table | SecurityEvent |
| Connector | Windows Security Events via AMA |
| Retention | 30 days analytics tier |

The VM was deployed and intentionally left internet-exposed to generate real telemetry. The Azure Monitor Agent (AMA) was configured to stream all Windows Security Events into Microsoft Sentinel in real time. This setup mirrors how enterprise SOC environments collect endpoint telemetry.

---

## Understanding the Data — Two Separate Stories

One of the most important skills in SOC work is separating your own activity from real threat actor activity. This investigation contained both — and distinguishing between them was a critical part of the analysis.

| Activity | Source IP | Logon Type | What it was |
|---|---|---|---|
| Analyst activity | 67.161.220.109 | Type 10 (RDP) | Me connecting to my VM via Windows Remote Desktop on my MacBook — including intentional failed logins during setup |
| Real external attack | 45.142.193.145 | Type 3 (Network) | Automated brute force bot that found the internet-exposed VM |

This separation was identified by running a combined IP and logon type query:

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by IpAddress, LogonType
| sort by FailedAttempts desc
```

**Results:**

| IpAddress | LogonType | FailedAttempts |
|---|---|---|
| 45.142.193.145 | 3 | 55 |
| 67.161.220.109 | 7 | 13 |
| 67.161.220.109 | 3 | 3 |
| 67.161.220.109 | 10 | 3 |

The Type 10 failures from 67.161.220.109 were my own RDP sessions. The 55 Type 3 failures from 45.142.193.145 were real external attack traffic — nothing to do with me.

---

## Phase 1 — Initial Telemetry Baseline

**Objective:** Before investigating specific threats, establish what event types are present in the environment to understand the full picture of activity.

```kql
SecurityEvent
| summarize EventCount=count() by EventID
| sort by EventCount desc
```

**Results:**

| Event ID | Description | Count |
|---|---|---|
| 4688 | Process Creation | 81 |
| 4673 | Privileged Service Called | 31 |
| 4627 | Group Membership Information | 15 |
| 4624 | Successful Logon | 15 |
| 4672 | Special Privileges Assigned | 15 |
| 4625 | Failed Logon | (investigated below) |

**Analyst Note:** The volume of Event ID 4688 (process creation) warranted a separate endpoint investigation. The presence of 4672 alongside 4624 indicated privileged account logons that required correlation.

---

## Phase 2 — Failed Authentication Investigation

**Objective:** Identify which accounts were being targeted and determine whether the pattern indicated automated tooling or manual attack activity.

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by TargetUserName
| sort by FailedAttempts desc
```

**Results:**

| TargetUserName | FailedAttempts | Assessment |
|---|---|---|
| administrator | 14 | Default admin — high value target |
| scanner | 13 | Does not exist — automated wordlist |
| scans | 13 | Does not exist — automated wordlist |
| scan | 13 | Does not exist — automated wordlist |
| socadmin | 12 | Lab account — specifically targeted |
| Test | 2 | Common default account guess |

**Key Finding:** Accounts named scanner, scans, and scan do not exist on this machine. Three non-existent accounts being targeted with identical attempt counts is a strong indicator of automated credential stuffing tooling cycling through a wordlist — not a human manually guessing passwords.

---

## Phase 3 — Attack Timeline Analysis

**Objective:** Understand exactly when the attack started, how it evolved, and what the timing pattern reveals about the threat actor's behavior.

```kql
SecurityEvent
| where EventID == 4625
| where IpAddress == "45.142.193.145"
| summarize Attempts=count() by bin(TimeGenerated, 1h)
| sort by TimeGenerated asc
```

**Results:**

| Time | Attempts | Assessment |
|---|---|---|
| May 6, 2026 9:00 AM | 1 | Initial reconnaissance probe |
| May 7, 2026 12:00 PM | 2 | Follow-up probing |
| May 7, 2026 2:00 AM | 52 | Full brute force assault |

**Critical Finding:** This timeline reveals a classic automated attack progression:

1. **Reconnaissance** — Single probe on May 6th to confirm the machine was alive and responding
2. **Verification** — Two attempts on May 7th afternoon to test response
3. **Full assault** — 52 attempts at 2:00 AM when network traffic is low and detection response is slower

The 2AM timing is a well-known pattern in automated attack campaigns. Botnets deliberately schedule heavy attack activity during off-hours to avoid real-time detection and response. This timing behavior alone is a strong indicator of sophisticated automated tooling rather than a casual attacker.

---

## Phase 4 — Source IP Analysis

**Objective:** Identify and profile the attacking IP addresses.

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts=count() by IpAddress
| sort by Attempts desc
```

**Results:**

| Source IP | Attempts | Assessment |
|---|---|---|
| 45.142.193.145 | 55 | Primary attacker — confirmed malicious |
| 67.161.220.109 | 12 | Analyst activity — RDP sessions |

---

## Phase 5 — Threat Intelligence Enrichment

**Objective:** Enrich the investigation by looking up the attacking IP in a global threat intelligence database to determine whether this is a known malicious actor.

**Tool used:** AbuseIPDB (abuseipdb.com)
**IP investigated:** 45.142.193.145

**AbuseIPDB Results:**

| Field | Value |
|---|---|
| Reports | 353 |
| Abuse Confidence | 100% |
| ISP | Limited Network LTD |
| Usage Type | Data Center / Web Hosting / Transit |
| ASN | AS214295 |
| Country | Netherlands |
| City | Amsterdam, North Holland |

**Finding:** This IP has been reported 353 times by security teams and researchers worldwide with 100% confidence of abuse. The data center / web hosting usage type confirms this is rented VPS infrastructure — commonly used to host automated attack tooling and botnets.

This is not a casual attacker. This is confirmed malicious infrastructure that has been flagged by hundreds of organizations globally.

**Analyst Note:** Threat intelligence enrichment is a standard SOC workflow. When an alert fires with a suspicious IP, analysts look it up in threat intel platforms like AbuseIPDB, VirusTotal, or Shodan to determine whether the IP is a known bad actor. This context directly influences severity assessment and response decisions.

---

## Phase 6 — Failed vs Successful Login Correlation

**Objective:** Determine whether the attacking IP successfully authenticated after the brute force attempts — the key question in any brute force investigation.

```kql
SecurityEvent
| where EventID in (4624, 4625)
| summarize EventCount=count() by IpAddress, EventID
| sort by EventCount desc
```

**Results:**

| IpAddress | EventID | EventCount | Assessment |
|---|---|---|---|
| — | 4624 | 174 | Internal system logons |
| 45.142.193.145 | 4625 | 55 | Failed attempts only |
| 67.161.220.109 | 4625 | 12 | Analyst RDP failures |
| 67.161.220.109 | 4624 | 6 | Analyst successful RDP sessions |

**Critical Finding:** IP 45.142.193.145 shows 55 failed attempts and **zero successful logons**. The brute force attack completely failed. The VM was not compromised.

The 174 successful logons with no external IP are internal system processes and service accounts — assessed as legitimate after logon type analysis.

---

## Phase 7 — Logon Type Analysis

**Objective:** Use logon type data to determine what service or process the attacker was targeting — answering the question of whether this was an application-level attack or a direct OS authentication attack.

```kql
SecurityEvent
| where EventID == 4625
| summarize Count=count() by LogonType
| sort by Count desc
```

**Results:**

| Logon Type | Count | Description |
|---|---|---|
| Type 3 | 58 | Network logon |
| Type 7 | 6 | Unlock |
| Type 10 | 3 | Remote Interactive (RDP) |

**Investigation Conclusion:** The logon type distribution directly answers what service was being targeted.

- **Type 3 (86% of attempts)** = Network authentication — the attacker was hitting Windows network authentication services directly, not a web application, not SQL Server, not a specific business application. This is consistent with SMB or NTLM-based credential attacks targeting the OS authentication layer.
- **Type 10 (3 attempts)** = These were my own RDP sessions from my Mac — not attacker activity.

This finding changes the remediation priority. The primary response should focus on restricting network authentication exposure (SMB, NTLM hardening) rather than solely RDP controls.

---

## Phase 8 — Detection Engineering

**Objective:** Build a custom detection rule that would automatically alert on this behavior in the future with proper MITRE ATT&CK mapping and actionable response guidance.

**Detection Rule Configuration:**

| Setting | Value |
|---|---|
| Detection Name | Excessive Failed Logons From Single IP |
| Frequency | Every Hour |
| Lookback Period | 1 Hour |
| Severity | High |
| Category | Credential Access |
| MITRE Technique | T1110 — Brute Force |

**Detection Query:**
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
```

**Detection Logic:** Flags any source IP generating more than 10 failed logon attempts within a 5-minute window. Threshold calibrated to catch automated tooling while avoiding false positives from users mistyping passwords.

**Alert Description:**
> Microsoft Sentinel detected excessive failed authentication attempts from a single source IP within a short time window. This may indicate brute force or password spraying activity targeting Windows accounts.

**Recommended Response Actions:**
1. Look up source IP in AbuseIPDB and VirusTotal
2. Correlate Event ID 4624 against 4625 to check for successful logons
3. Review targeted account names for automated wordlist patterns
4. Analyze logon types to identify what service is being targeted
5. Block source IP at the NSG level if confirmed malicious
6. Reset credentials for targeted accounts
7. Enable MFA on all accounts with network logon permissions

---

## Phase 9 — Incident Response & Triage

**Objective:** Triage the incident generated by the detection rule and document the full investigation workflow.

**Incident Details:**

| Field | Value |
|---|---|
| Incident ID | IR-001 |
| Title | Excessive Failed Logons Detected From Single IP |
| Severity | High |
| Status | Active |
| First Activity | May 7, 2026 — 2:55 AM |
| Incident Created | May 7, 2026 — 6:52 PM |
| Source IP | 45.142.193.145 |
| Affected Asset | win-sec-events |

**Triage Steps:**

**Step 1 — Alert Validation:** Confirmed detection rule fired correctly. Single active alert, 1 affected asset.

**Step 2 — Threat Intel Check:** Looked up 45.142.193.145 on AbuseIPDB. 353 reports, 100% abuse confidence. Confirmed malicious infrastructure.

**Step 3 — Severity Assessment:** Rated High based on confirmed malicious IP, 55 attempts, targeting of default admin account, and 2AM timing pattern consistent with automated attack campaigns.

**Step 4 — Compromise Assessment:** Correlated 4624 vs 4625 for attacking IP. Zero successful logons from 45.142.193.145. Attack failed. No compromise.

**Step 5 — Service Identification:** Logon type 3 confirmed attacker was targeting Windows network authentication — not a specific application.

**Step 6 — Scope Assessment:** Attack isolated to single IP targeting single VM. No lateral movement. No internal propagation.

**Step 7 — Escalation Decision:** No confirmed compromise, no lateral movement. Classified as contained. Recommended actions: IP block at NSG, credential review, MFA enforcement, SMB restriction.

---

## Phase 10 — Endpoint Threat Hunting

**Objective:** Pivot from authentication analysis to endpoint telemetry to confirm no command execution occurred — ruling out alternative compromise vectors beyond the brute force attempt.

**Analyst Reasoning:** Even with no successful logons from the attacking IP, a thorough investigation requires checking whether any process execution occurred via a different attack vector.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName contains "cmd.exe"
| project TimeGenerated, Account, Computer, NewProcessName, CommandLine
| sort by TimeGenerated desc
```

**Results:**

| Time | Account | Computer | Process | CommandLine |
|---|---|---|---|---|
| May 6, 2026 8:00 AM | WORKGROUP\win-sec-eve | win-sec-events | C:\Windows\System32\cmd.exe | cmd.exe |

**Assessment:** Single cmd.exe execution under local system account during morning hours. No suspicious command line arguments. Timing and account context consistent with normal system or scheduled task activity. Assessed as benign.

**Analyst Note:** In a production environment this would be cross-referenced against the change management calendar and confirmed with system administrators.

---

## Incident Report — IR-001

**Incident ID:** IR-001
**Date:** May 7, 2026
**Analyst:** Nawid Farani
**Severity:** High → Medium (post-investigation)
**Status:** Closed — No Compromise Confirmed

---

### Executive Summary

On May 7, 2026 at 2:55 AM, an automated threat actor operating from IP 45.142.193.145 — a confirmed malicious data center host in Amsterdam with 353 AbuseIPDB reports and 100% abuse confidence — launched a brute force attack against the soc-lab Azure Windows Server VM.

The attack began with a single reconnaissance probe on May 6th, followed by low-volume verification attempts, before escalating to 52 attempts in a single hour at 2AM — a timing pattern consistent with automated botnet activity designed to evade real-time detection.

Investigation confirmed the attack was unsuccessful. No successful authentication from the attacking IP was observed. Logon type analysis identified the attack targeted Windows network authentication services (Type 3) directly — not a specific application. Endpoint threat hunting found no evidence of malicious process execution. The environment was not compromised.

---

### Attack Timeline

| Time | Event |
|---|---|
| May 4, 2026 2:00 PM | Azure VM deployed, AMA connector configured |
| May 6, 2026 9:00 AM | First reconnaissance probe from 45.142.193.145 (1 attempt) |
| May 7, 2026 12:00 PM | Follow-up verification (2 attempts) |
| May 7, 2026 2:00 AM | Full brute force assault (52 attempts in 1 hour) |
| May 7, 2026 6:52 PM | Detection rule fires — Incident IR-001 created |
| May 7, 2026 6:52 PM | Investigation completed — no compromise confirmed |

---

### Indicators of Compromise

| Indicator | Type | Details | Disposition |
|---|---|---|---|
| 45.142.193.145 | Malicious IP | 55 failed logons, 353 AbuseIPDB reports, 100% abuse confidence, Amsterdam NL | Block at NSG |
| administrator | Targeted account | 14 failed attempts | Review, enforce MFA |
| scanner / scans / scan | Wordlist accounts | 13 attempts each, accounts don't exist | Confirms automated tooling |

---

### Root Cause

Internet-exposed Windows Server VM with network authentication services accessible from the public internet. Automated scanning infrastructure probed and targeted the VM within 24 hours of deployment.

---

### Recommendations

| Priority | Action |
|---|---|
| Immediate | Block 45.142.193.145 at the Azure NSG level |
| Short term | Restrict SMB and NTLM exposure to known IP ranges |
| Short term | Enable MFA on all accounts with network logon permissions |
| Short term | Enforce NTLMv2, disable NTLM where possible |
| Long term | Implement account lockout — lock after 5 failures in 10 minutes |
| Long term | Enable Just-In-Time VM access via Microsoft Defender for Cloud |
| Long term | Disable SMBv1 entirely |

---

## What This Detection Misses

A strong analyst thinks critically about the limits of their own detections. This rule has known gaps:

**Low and slow attacks** — An attacker making 2-3 attempts per hour over several days would never hit the 10-failure-in-5-minutes threshold. A longer lookback window with a lower threshold would be needed to catch this.

**Distributed password spraying** — An attacker spraying one password across many accounts from many different IPs would never trigger a single-IP threshold rule. Detecting this requires user-based anomaly detection across multiple source IPs.

**Credential stuffing from rotating IPs** — Botnets that rotate source IPs with each attempt would evade this detection entirely. Each IP would only generate 1-2 attempts — well below threshold.

**Post-authentication activity** — This rule catches the brute force attempt but not what happens after a successful login. A separate detection correlating Event ID 4624 followed by 4688 (process creation) within a short window would be needed to catch successful compromise followed by execution.

**2AM timing gap** — The attack began at 2:55 AM and the incident wasn't created until 6:52 PM — a 16-hour gap. In a real environment an on-call SOC analyst or automated SOAR response would need to close this gap.

---

## Key Takeaways

- A real external threat actor found and attacked this VM within 24 hours of deployment — no simulation required
- The attacking IP was confirmed malicious via AbuseIPDB — 353 global reports, 100% abuse confidence
- Attack timing (2AM escalation) matched known botnet behavior patterns
- Logon type analysis was the key to identifying what service was being targeted — Type 3 network logons confirmed OS-level network authentication attack, not an application-level attack
- Separating analyst-generated activity (Type 10 RDP from my Mac) from real attacker activity (Type 3 network from external IP) is a fundamental SOC skill
- The brute force attack failed completely — zero successful logons from the attacking IP
- Threat intelligence enrichment transformed a suspicious IP into a confirmed known threat actor

---

*Built by Nawid Farani — CS Student at Western Governors University | Security+ | AWS SAA | Splunk Core*
*Actively seeking Tier 1 SOC roles in Utah*
*linkedin.com/in/nawid6 | github.com/nawidtechlabs*
| Incident Documentation | Full IR report with timeline, IOCs, root cause, recommendations |
| Detection Gap Analysis | Identified 4 specific evasion techniques this detection would miss |
