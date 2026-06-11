# Detection: New User Added to Administrators Group

## Objective
Detect when a new user account is added to the local Administrators group, which could indicate privilege escalation or unauthorized account creation by an attacker.

## MITRE ATT&CK
- Technique: T1136 — Create Account
- Tactic: Persistence, Privilege Escalation

## Log Source
- Windows Security Event Log
- Event ID 4732 — A member was added to a security-enabled local group

## Rule Logic
Wazuh rule 100003 triggers when Event ID 4732 is detected and the target group is the Administrators group. This is a level 12 alert, reflecting the high severity of unexpected privilege changes.

```xml
<rule id="100003" level="12">
  <if_sid>18153</if_sid>
  <field name="win.system.eventID">4732</field>
  <field name="win.eventdata.targetUserName">Administrators</field>
  <description>User added to local Administrators group</description>
  <group>account_changes,privilege_escalation,</group>
</rule>
```

## Test Procedure
1. Opened PowerShell as Administrator on the Windows 11 agent VM
2. Created a test user: `net user testuser Password123 /add`
3. Added to Administrators group: `net localgroup Administrators testuser /add`
4. Observed alert in Wazuh dashboard correlating to account modification events

## Result
Wazuh detected the group membership change and generated alerts under rules 60109, 60160, 60110, and 60170 — built-in rules covering account creation and group modification events. The activity was successfully flagged and visible in the Security Events view.

## False Positive Considerations
- Legitimate IT administrators adding new staff accounts could trigger this
- Scheduled provisioning scripts that create accounts would generate alerts
- In production, a change management process would be used to distinguish authorized from unauthorized changes

## Tuning Ideas
- Maintain an allowlist of authorized admin accounts and suppress alerts for those
- Correlate with after-hours activity to increase signal fidelity
- Integrate with a ticketing system to auto-verify if a change request exists
