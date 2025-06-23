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
| project TimeGenerated, Computer, Account, ProcessName, CommandLine


