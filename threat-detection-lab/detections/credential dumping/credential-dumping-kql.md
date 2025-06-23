# Detection – Credential Dumping via LSASS Access (Mimikatz)

**MITRE ATT&CK ID:** T1003.001  
**Tool Tested:** Mimikatz  
**Platform:** Windows  
**Data Source:** Microsoft Sentinel / Windows Security Events / Sysmon

---

## KQL Query – Sentinel

```kql
SecurityEvent
| where EventID == 10 or EventID == 4688
| where ProcessName has "mimikatz" or ProcessName has "procdump" or ProcessCommandLine has "lsass"
| project TimeGenerated, Computer, Account, ProcessName, CommandLines
```
---

## Detection Logic

- Look for process execution with suspicious access to `lsass.exe`
- Includes known dumpers like `procdump64.exe`, `taskmgr`, or tools abusing legitimate access

---

## Alert Logic Recommendation

- **Triage Priority:** High (Likely post-exploitation behavior)
- **Suppression Rules:** Suppress trusted admin activity on golden images if confirmed safe
- **Action:** Isolate host, inspect memory dump behavior, collect forensics

---

## Validated In Lab

Successfully detected Mimikatz when accessing LSASS memory  
Triggered alerts in Defender & Sentinel correlated with ATT&CK technique `T1003.001`
