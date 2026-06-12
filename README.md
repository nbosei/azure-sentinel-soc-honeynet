# 🛡️ Azure Sentinel SOC & Honeynet — Live Attack Monitoring Lab

## Overview

This project involved building a **Security Operations Center (SOC)** and **Honeynet** inside Microsoft Azure to capture and analyze real-world cyberattacks in a live cloud environment. The goal was to simulate a vulnerable environment, attract real threat actors, monitor their activity using a cloud-native SIEM, and visualize attack origins on a global map.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Microsoft Azure                  │
│                                                     │
│   ┌─────────────┐       ┌──────────────────────┐   │
│   │  Honeypot   │──────▶│  Log Analytics       │   │
│   │  Windows VM │       │  Workspace           │   │
│   │  (exposed)  │       └──────────┬───────────┘   │
│   └─────────────┘                  │               │
│                                    ▼               │
│                        ┌───────────────────────┐   │
│                        │  Microsoft Sentinel   │   │
│                        │  (SIEM)               │   │
│                        │  - Attack map         │   │
│                        │  - Alerts             │   │
│                        │  - Geo visualization  │   │
│                        └───────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## What I Built

- Deployed a **Windows Virtual Machine** in Azure configured as a honeypot — intentionally exposed to the internet with minimal firewall restrictions to attract real attackers
- Created a **Log Analytics Workspace** to ingest logs from the honeypot VM, including Windows Security Event logs and failed login attempts
- Configured **Microsoft Sentinel (SIEM)** to connect to the Log Analytics Workspace and monitor incoming log data in real time
- Wrote a **custom PowerShell script** that:
  - Parsed Windows Event Logs for failed RDP and login attempts
  - Extracted attacker IP addresses from the logs
  - Called a **geolocation API** to resolve each IP to a country, city, and coordinates
  - Forwarded enriched log data back to Log Analytics with geographic fields
- Built a **custom Sentinel Workbook** (attack map) using KQL queries to plot attacker geolocations on a world map in real time
- Observed and documented live attacks from multiple countries within hours of deployment

---

## Technologies Used

| Tool | Purpose |
|------|---------|
| Microsoft Azure | Cloud platform |
| Azure Virtual Machines | Honeypot host |
| Microsoft Sentinel | SIEM — threat detection & visualization |
| Log Analytics Workspace | Log ingestion & querying |
| PowerShell | Custom log parsing & geolocation script |
| KQL (Kusto Query Language) | Sentinel queries & workbook rules |
| IP Geolocation API | Resolving attacker IPs to map coordinates |
| Windows Event Viewer | Source of raw security event logs |

---

## Key Results

- Captured **live brute-force RDP attacks** from multiple countries within the first few hours of deployment
- Successfully plotted attacker origins on a **real-time global attack map** inside Azure Sentinel
- Demonstrated end-to-end log ingestion pipeline from raw Windows events → enriched geo data → SIEM visualization
- Gained hands-on experience with **SIEM alert configuration**, **KQL query writing**, and **cloud security monitoring workflows**

---

## Skills Demonstrated

- Cloud infrastructure provisioning (Azure VMs, networking, NSGs)
- SIEM configuration and management (Microsoft Sentinel)
- Custom log enrichment via PowerShell scripting
- KQL query writing for threat detection
- Security monitoring and incident triage
- Threat intelligence (geolocation, attack pattern recognition)

---

## What I Learned

This project reinforced how quickly an exposed system attracts real-world attacks — within minutes of disabling firewall rules, brute-force attempts began arriving from across the globe. It gave me practical experience with the full SOC analyst workflow: ingesting logs, writing detection rules, investigating alerts, and presenting threat data in a meaningful way to stakeholders.

---

## Related Certifications

- CompTIA Security+
- Cybersecurity Certificate — University of Minnesota
- M.S. Cybersecurity & Information Assurance (In Progress) — WGU

---

*Project completed as part of the LevelD Cybersecurity Masterclass.*
