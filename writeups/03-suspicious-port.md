# Detection: Outbound Connection to Suspicious Port

## Objective
Detect when an endpoint attempts an outbound network connection to ports commonly associated with command and control (C2) frameworks, such as Metasploit (4444) or other attacker infrastructure.

## MITRE ATT&CK
- Technique: T1071 — Application Layer Protocol
- Tactic: Command and Control

## Log Source
- Sysmon Event ID 3 — Network Connection
- Requires Sysmon installed with network monitoring enabled

## Rule Logic
Wazuh rule 100004 triggers when Sysmon logs an outbound connection attempt to ports 4444, 1337, 8888, or 9001 — all commonly used by attacker tooling and C2 frameworks. The rule fires regardless of whether the connection succeeds, capturing the attempt itself.

```xml
<rule id="100004" level="10">
  <if_sid>61613</if_sid>
  <field name="win.eventdata.destinationPort">^(4444|1337|8888|9001)$</field>
  <description>Outbound connection to suspicious port — possible C2</description>
  <group>network_anomaly,</group>
</rule>
```

## Test Procedure
1. Opened PowerShell on the Windows 11 agent VM
2. Ran: `Test-NetConnection -ComputerName 8.8.8.8 -Port 4444`
3. Connection failed at the network level (expected — port is blocked externally)
4. Sysmon logged the connection attempt regardless of outcome
5. Wazuh picked up the Sysmon event and generated a level 12 alert in the dashboard

## Result
Alert triggered successfully. Sysmon captured the outbound connection attempt at the process level, demonstrating that detection does not rely on the connection succeeding — the attempt itself is sufficient to generate an alert.

## False Positive Considerations
- Some legitimate development tools use non-standard ports that could overlap
- Gaming or P2P applications occasionally use high ports in these ranges
- In production, destination IP reputation scoring would add context to reduce noise

## Tuning Ideas
- Expand the port list based on threat intelligence feeds
- Add destination IP lookups against known C2 infrastructure blocklists
- Correlate with process name to identify which application made the connection
