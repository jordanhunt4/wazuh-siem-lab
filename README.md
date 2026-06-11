# Wazuh SIEM Home Lab

A home lab built to simulate real-world security monitoring using Wazuh, deployed on Ubuntu Server with a Windows 11 endpoint. Built as part of an active transition into cybersecurity.

## Overview

This project demonstrates deployment of a SIEM (Security Information and Event Management) system from scratch, including agent enrollment, endpoint telemetry collection via Sysmon, and custom detection rule writing mapped to MITRE ATT&CK.

## Tools Used

- Wazuh 4.7 (Manager, Indexer, Dashboard)
- Ubuntu Server 22.04 LTS
- Windows 11 Enterprise (evaluation)
- Sysmon with SwiftOnSecurity config
- VirtualBox

## Architecture

Host machine (Windows) running two VMs:
- Ubuntu Server — Wazuh Manager + Indexer + Dashboard
- Windows 11 — Wazuh Agent + Sysmon

VMs communicate over a VirtualBox Host-Only network segment, isolated from the external internet.

## Detection Rules

| Rule ID | Description | MITRE ATT&CK |
|---|---|---|
| 100002 | Brute force — 5+ failed logins in 2 minutes | T1110 |
| 100003 | New user added to Administrators group | T1136 |
| 100004 | Outbound connection to suspicious port (4444, 1337, 8888) | T1071 |

## Write-ups

- [Brute Force Detection](writeups/01-brute-force.md)
- [New Admin Account](writeups/02-new-admin-account.md)
- [Suspicious Port Detection](writeups/03-suspicious-port.md)

## Results

All three rules successfully triggered and generated alerts in the Wazuh dashboard during testing. Sysmon provided process-level and network-level telemetry that enriched the alert data beyond default Windows Event Logs.
