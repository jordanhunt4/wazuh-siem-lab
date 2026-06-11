# Detection: Brute Force Login Attempts

## Objective
Detect when an attacker attempts to guess a user's password by making repeated failed login attempts in a short time window.

## MITRE ATT&CK
- Technique: T1110 — Brute Force
- Tactic: Credential Access

## Log Source
- Windows Security Event Log
- Event ID 4625 — An account failed to log on

## Rule Logic
Wazuh rule 100002 triggers when 5 or more failed login attempts are detected from the same source IP within a 2 minute window. The rule chains off Wazuh's built-in authentication failure detection (SID 60122) and uses the frequency and timeframe fields to establish the threshold.

```xml
<rule id="100002" level="10" frequency="5" timeframe="120">
  <if_matched_sid>60122</if_matched_sid>
  <same_srcip />
  <description>Multiple Windows login failures from same source (possible brute force)</description>
  <group>authentication_failures,</group>
</rule>
```

## Test Procedure
1. Pressed Win + L on the Windows 11 agent VM to reach the lock screen
2. Entered an incorrect password 5 times consecutively
3. Observed alert firing in Wazuh dashboard under Security Events within 30 seconds

## Result
Alert triggered at level 10. Wazuh correlated the repeated failures and flagged the source as a potential brute force attempt.

## False Positive Considerations
- A legitimate user who forgets their password could trigger this rule
- In a production environment, the threshold could be raised to 10 attempts or the timeframe extended to reduce noise
- Allowlisting known internal IPs would reduce false positives in a corporate environment

## Tuning Ideas
- Increase frequency threshold for workstations, lower it for servers
- Add geo-based alerting to flag failures from unexpected locations
- Correlate with successful login after failures to detect successful brute force
