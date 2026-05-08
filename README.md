# Microsoft Sentinel SOC Investigation & Detection Lab

> I deployed an internet-exposed Windows Server VM on Azure to collect real security telemetry. Within hours, real external threat actors found it and launched brute force attacks. This documents the full investigation — from initial telemetry through threat intelligence confirmation, layered detection engineering, and real-time monitoring — using Microsoft Sentinel, Microsoft Defender, and live Azure infrastructure.

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
- [Phase 8 — Detection Engineering (Defender)](#phase-8--detection-engineering-defender)
- [Phase 9 — Incident Response & Triage](#phase-9--incident-response--triage)
- [Phase 10 — Endpoint Threat Hunting](#phase-10--endpoint-threat-hunting)
- [Phase 11 — Sentinel Analytics Rules](#phase-11--sentinel-analytics-rules)
- [Phase 12 — Threat Intelligence Watchlist](#phase-12--threat-intelligence-watchlist)
- [Phase 13 — Sentinel Workbook & Second Threat Actor Discovery](#phase-13--sentinel-workbook--second-threat-actor-discovery)
- [Incident Report — IR-001](#incident-report--ir-001)
- [Full Threat Actor Summary](#full-threat-actor-summary)
- [Detection Program Summary](#detection-program-summary)
- [What This Detection Misses](#what-this-detection-misses)
- [Key Takeaways](#key-takeaways)

---

## Lab Overview

This lab was built to simulate real Tier 1 SOC analyst workflows using Microsoft Sentinel and live Azure infrastructure. Unlike labs that use pre-packaged datasets, this environment was intentionally internet-exposed to collect authentic attack telemetry.

What I didn't plan for — within hours of deployment, real external threat actors found the VM and launched brute force attacks. A Sentinel Workbook built later in the investigation surfaced a second threat actor that wasn't discovered during the initial investigation — proving the value of continuous monitoring and visualization.

**What this lab demonstrates:**
- Live Azure VM deployment and SIEM configuration
- Real external attack detection and investigation
- Separating analyst-generated noise from real threat actor activity
- Threat intelligence enrichment using AbuseIPDB
- KQL-based detection engineering with MITRE ATT&CK mapping
- Layered detection — fast attacks and low and slow attacks
- Threat intelligence watchlist integration
- Sentinel Workbook dashboard for real-time monitoring
- Full incident response workflow from detection to closure
- Endpoint threat hunting via process creation analysis

**Timeframe:** May 4–8, 2026
**Environment:** Azure — live, internet-exposed Windows Server VM
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
| Real external attack | 45.142.193.145 | Type 3 (Network) | Automated brute force bot — confirmed malicious |
| Real external scan | 137.184.111.6 | Type 3 (Network) | BinaryEdge internet scanner — confirmed malicious |

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

The Type 10 failures from 67.161.220.109 were my own RDP sessions. The 55 Type 3 failures from 45.142.193.145 were real external attack traffic. The third IP (137.184.111.6) was surfaced later by the Sentinel Workbook.

---

## Phase 1 — Initial Telemetry Baseline

**Objective:** Establish a baseline of what event types are present before investigating specific threats.

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
| 4625 | Failed Logon | Investigated below |

**Analyst Note:** High volume of Event ID 4688 warranted a separate endpoint investigation. Presence of 4672 alongside 4624 indicated privileged account logons requiring correlation.

---

## Phase 2 — Failed Authentication Investigation

**Objective:** Identify which accounts were targeted and determine whether the pattern indicated automated tooling.

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

**Key Finding:** Accounts named scanner, scans, and scan do not exist on this machine. Three non-existent accounts targeted with identical attempt counts is a strong indicator of automated credential stuffing tooling cycling through a wordlist.

---

## Phase 3 — Attack Timeline Analysis

**Objective:** Understand exactly when the attack started, how it evolved, and what the timing pattern reveals about the threat actor.

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
| May 7, 2026 12:00 PM | 2 | Follow-up verification |
| May 7, 2026 2:00 AM | 52 | Full brute force assault |

**Critical Finding:** Classic automated attack progression. Single probe to confirm the machine was alive. Follow-up verification. Full assault at 2AM when network traffic is low and detection response is slower. The 2AM timing is a well-known pattern in automated botnet campaigns.

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
| 67.161.220.109 | 19 | Analyst activity — RDP sessions |
| 137.184.111.6 | 1 | Secondary threat actor — surfaced by workbook |

---

## Phase 5 — Threat Intelligence Enrichment

**Objective:** Enrich the investigation by looking up attacking IPs in a global threat intelligence database.

### IP 1 — 45.142.193.145

| Field | Value |
|---|---|
| Reports | 353 |
| Abuse Confidence | 100% |
| ISP | Limited Network LTD |
| Usage Type | Data Center / Web Hosting / Transit |
| Country | Netherlands |
| City | Amsterdam, North Holland |

**Assessment:** Confirmed malicious data center infrastructure. Rented VPS commonly used to host automated brute force tooling. 353 reports from security teams worldwide.

### IP 2 — 137.184.111.6

| Field | Value |
|---|---|
| Reports | 390 |
| Abuse Confidence | 100% |
| ISP | DigitalOcean, LLC |
| Usage Type | Data Center / Web Hosting / Transit |
| Hostname | prod-boron-nyc1-4.do.binaryedge.ninja |
| Country | United States |
| City | North Bergen, New Jersey |

**Assessment:** BinaryEdge internet scanning infrastructure. BinaryEdge continuously scans the entire internet mapping exposed services. This IP probed the VM on May 8th — surfaced by the Sentinel Workbook during the monitoring phase.

**Analyst Note:** Threat intelligence enrichment is a standard SOC workflow. When an alert fires with a suspicious IP, analysts look it up in threat intel platforms like AbuseIPDB, VirusTotal, or Shodan to determine whether the IP is a known bad actor. This context directly influences severity assessment and response decisions.

---

## Phase 6 — Failed vs Successful Login Correlation

**Objective:** Determine whether any attacking IP successfully authenticated after brute force attempts.

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
| 45.142.193.145 | 4625 | 55 | Failed attempts only — no compromise |
| 67.161.220.109 | 4625 | 12 | Analyst RDP failures |
| 67.161.220.109 | 4624 | 6 | Analyst successful RDP sessions |

**Critical Finding:** IP 45.142.193.145 shows 55 failed attempts and zero successful logons. The brute force attack completely failed. The VM was not compromised.

---

## Phase 7 — Logon Type Analysis

**Objective:** Use logon type data to determine what service the attacker was targeting.

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

**Investigation Conclusion:** Type 3 network logons (86% of attempts) indicate the attacker was hitting Windows network authentication services directly — not a web application, not SQL Server, not a specific business application. This is consistent with SMB or NTLM-based attacks targeting the OS authentication layer. The Type 10 failures were my own RDP sessions from my Mac — not attacker activity. This finding changes the remediation priority toward restricting network authentication exposure rather than solely RDP controls.

---

## Phase 8 — Detection Engineering (Defender)

**Objective:** Build a custom detection rule in Microsoft Defender to automatically alert on brute force behavior.

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

**Step 3 — Severity Assessment:** Rated High based on confirmed malicious IP, 55 attempts, targeting of default admin account, and 2AM timing consistent with automated botnet activity.

**Step 4 — Compromise Assessment:** Correlated 4624 vs 4625 for attacking IP. Zero successful logons. Attack failed. No compromise.

**Step 5 — Service Identification:** Logon type 3 confirmed attacker targeted Windows network authentication directly — not a specific application.

**Step 6 — Scope Assessment:** Attack isolated to single IP targeting single VM. No lateral movement. No internal propagation.

**Step 7 — Escalation Decision:** No confirmed compromise, no lateral movement. Classified as contained. Recommended actions: IP block at NSG, credential review, MFA enforcement, SMB restriction.

---

## Phase 10 — Endpoint Threat Hunting

**Objective:** Pivot from authentication analysis to endpoint telemetry to rule out post-authentication execution.

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

**Assessment:** Single cmd.exe execution under local system account during morning hours. No suspicious command line arguments. Timing and account context consistent with normal system activity. Assessed as benign.

---

## Phase 11 — Sentinel Analytics Rules

**Objective:** Build native Sentinel Analytics Rules to provide SIEM-level detection coverage beyond Defender custom detections.

### Rule 1 — Brute Force Detection (High Severity)

| Setting | Value |
|---|---|
| Name | Brute Force Detection — Excessive Failed Logons From Single IP |
| Severity | High |
| MITRE | T1110 — Brute Force / Credential Access |
| Frequency | Every 5 minutes |
| Lookback | 5 minutes |
| Status | Enabled |

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| extend ThreatLevel = "High"
| extend MITRETechnique = "T1110 - Brute Force"
| extend AttackVector = "Network Authentication"
```

### Rule 2 — Low and Slow Brute Force Detection (Medium Severity)

Built specifically to address the detection gap identified in the initial investigation — attackers who stay under the 10-attempt threshold to evade fast detection rules.

| Setting | Value |
|---|---|
| Name | Low and Slow Brute Force Detection |
| Severity | Medium |
| MITRE | T1110 — Brute Force / Credential Access |
| Frequency | Every 1 hour |
| Lookback | 1 hour |
| Status | Enabled |

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by IpAddress, bin(TimeGenerated, 1h)
| where FailedAttempts between (3 .. 9)
| extend ThreatLevel = "Medium"
| extend DetectionType = "Low and Slow Brute Force"
| extend MITRETechnique = "T1110 - Brute Force"
```

**Detection Logic:** Catches IPs making 3-9 attempts per hour — staying just under the fast detection threshold but still exhibiting suspicious behavior over time. Together these two rules provide layered coverage across fast and slow attack patterns.

**Active Rules Dashboard:** 2 active rules — High (1), Medium (1) — both mapped to T1110, both Credential Access.

---

## Phase 12 — Threat Intelligence Watchlist

**Objective:** Build a Sentinel Watchlist of confirmed malicious IPs so they are automatically flagged on any future activity across the environment.

**Watchlist:** Malicious-IPs
**Items:** 1 (45.142.193.145)

**Watchlist Query:**
```kql
let MaliciousIPs = _GetWatchlist('Malicious-IPs')
| project IPAddress;
SecurityEvent
| where IpAddress in (MaliciousIPs)
| project TimeGenerated, EventID, IpAddress, TargetUserName, LogonType
| sort by TimeGenerated desc
```

**Results:** 55 items returned — every single event from the confirmed malicious IP automatically flagged. All Event ID 4625, all LogonType 3, all targeting automated wordlist accounts, all timestamped during the 2AM attack window.

**Why this matters:** In a real SOC environment, watchlists allow analysts to automatically surface known bad actors across all future alerts without manually looking up every IP. Once an IP is confirmed malicious it gets added to the watchlist and flagged automatically on every future event.

---

## Phase 13 — Sentinel Workbook & Second Threat Actor Discovery

**Objective:** Build a Sentinel Workbook to visualize attack data and support ongoing monitoring. The workbook surfaced a second threat actor not identified during the initial investigation.

**Workbook Query:**
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by IpAddress
| sort by FailedAttempts desc
| render barchart
```

**Workbook Results:**

| IP Address | Failed Attempts | Assessment |
|---|---|---|
| 45.142.193.145 | 55 | Primary attacker — previously investigated |
| 67.161.220.109 | 19 | Analyst activity — RDP sessions |
| 137.184.111.6 | 1 | NEW — second threat actor discovered |

**New Finding:** IP 137.184.111.6 was not identified during the initial investigation. The Workbook visualization surfaced it automatically. Investigation confirmed:
- Event ID 4625, LogonType 3, May 8, 2026 9:58 AM
- AbuseIPDB: 390 reports, 100% abuse confidence
- DigitalOcean infrastructure — BinaryEdge internet scanner
- North Bergen, New Jersey

This demonstrates exactly why continuous monitoring and visualization matters in SOC environments — dashboards surface things you didn't know to look for.

---

## Incident Report — IR-001

**Incident ID:** IR-001
**Date:** May 7, 2026
**Analyst:** Nawid Farani
**Severity:** High → Medium (post-investigation)
**Status:** Closed — No Compromise Confirmed

### Executive Summary

On May 7, 2026 at 2:55 AM, an automated threat actor operating from IP 45.142.193.145 — confirmed malicious infrastructure in Amsterdam with 353 AbuseIPDB reports and 100% abuse confidence — launched a brute force attack against the soc-lab Azure Windows Server VM. The attack began with a single reconnaissance probe on May 6th, followed by low-volume verification, before escalating to 52 attempts in one hour at 2AM — consistent with automated botnet behavior designed to evade real-time detection. Investigation confirmed no successful authentication. The environment was not compromised. A second threat actor (137.184.111.6) was subsequently identified via Sentinel Workbook monitoring.

### Attack Timeline

| Time | Event |
|---|---|
| May 4, 2026 2:00 PM | Azure VM deployed, AMA connector configured |
| May 6, 2026 9:00 AM | First probe from 45.142.193.145 (1 attempt) |
| May 7, 2026 12:00 PM | Follow-up verification (2 attempts) |
| May 7, 2026 2:00 AM | Full brute force assault (52 attempts in 1 hour) |
| May 7, 2026 6:52 PM | Detection rule fires — Incident IR-001 created |
| May 7, 2026 6:52 PM | Investigation completed — no compromise confirmed |
| May 8, 2026 9:58 AM | Second threat actor (137.184.111.6) probes VM |
| May 8, 2026 | Workbook built — second IP surfaced automatically |

### Indicators of Compromise

| Indicator | Type | Details | Disposition |
|---|---|---|---|
| 45.142.193.145 | Malicious IP | 55 failed logons, 353 AbuseIPDB reports, 100% confidence, Amsterdam NL | Block at NSG |
| 137.184.111.6 | Malicious IP | 1 probe, 390 AbuseIPDB reports, 100% confidence, BinaryEdge scanner NJ | Block at NSG |
| administrator | Targeted account | 14 failed attempts | Review, enforce MFA |
| scanner / scans / scan | Wordlist accounts | 13 attempts each — accounts don't exist | Confirms automated tooling |

### Recommendations

| Priority | Action |
|---|---|
| Immediate | Block 45.142.193.145 and 137.184.111.6 at the Azure NSG level |
| Short term | Restrict SMB and NTLM exposure to known IP ranges |
| Short term | Enable MFA on all accounts with network logon permissions |
| Short term | Enforce NTLMv2, disable NTLM where possible |
| Long term | Implement account lockout — lock after 5 failures in 10 minutes |
| Long term | Enable Just-In-Time VM access via Microsoft Defender for Cloud |
| Long term | Disable SMBv1 entirely |

---

## Full Threat Actor Summary

| IP | Attempts | AbuseIPDB Reports | Confidence | Location | Infrastructure | Attack Type |
|---|---|---|---|---|---|---|
| 45.142.193.145 | 55 | 353 | 100% | Amsterdam, Netherlands | Limited Network LTD | Automated brute force botnet |
| 137.184.111.6 | 1 | 390 | 100% | New Jersey, USA | DigitalOcean / BinaryEdge | Internet scanning |

Both confirmed malicious. Both data center infrastructure. Both Type 3 network logon attacks targeting Windows network authentication directly.

---

## Detection Program Summary

| Detection | Platform | Severity | Technique | Coverage |
|---|---|---|---|---|
| Excessive Failed Logons From Single IP | Microsoft Defender | High | T1110 | Fast brute force — 10+ attempts in 5 min |
| Brute Force Detection — Excessive Failed Logons | Sentinel Analytics | High | T1110 | Fast brute force — 10+ attempts in 5 min |
| Low and Slow Brute Force Detection | Sentinel Analytics | Medium | T1110 | Slow attacks — 3-9 attempts per hour |
| Malicious-IPs Watchlist | Sentinel Watchlist | N/A | N/A | Known bad IP automatic flagging |

Four detection layers covering fast attacks, slow attacks, and known malicious infrastructure — across both Defender and Sentinel.

---

## What This Detection Misses

**Low and slow attacks below 3 attempts per hour** — An attacker making 1-2 attempts per hour over several days would evade even the low and slow rule. User behavior analytics would be needed.

**Distributed password spraying** — Spraying from many IPs with few attempts each would evade all single-IP threshold rules. Multi-source correlation detection would be required.

**Credential stuffing from rotating IPs** — Botnets rotating IPs with each attempt would never trigger per-IP thresholds.

**Post-authentication activity** — These detections catch the brute force attempt but not what happens after a successful login. A separate rule correlating 4624 followed by 4688 within a short window would be needed.

**16-hour detection gap** — First attack activity at 2:55 AM, incident created at 6:52 PM. In production an on-call analyst or automated SOAR response would need to close this gap.

---

## Key Takeaways

- Two real external threat actors found and attacked this VM — no simulation required
- Both attacking IPs confirmed malicious via AbuseIPDB — 353 and 390 global reports respectively
- Attack timing (2AM escalation) matched known botnet behavior patterns
- Logon type analysis was the key to identifying what service was targeted — Type 3 confirmed OS-level network authentication attack
- Separating analyst activity (Type 10 RDP) from real attacker activity (Type 3 network) is a fundamental SOC skill
- The brute force attack failed completely — zero successful logons from either attacking IP
- Sentinel Workbook visualization surfaced a second threat actor not found during manual investigation
- Layered detection coverage — fast and slow attack rules — addresses known evasion techniques

---

*Built by Nawid Farani — CS Student at Western Governors University*
*Security+ | AWS Solutions Architect Associate | Splunk Core Certified User*
*Actively seeking Tier 1 SOC roles in Utah*
*linkedin.com/in/nawid6 | github.com/nawidtechlabs*
