# Detection – Credential Dumping via LSASS Access (Mimikatz)

**MITRE ATT&CK ID:** T1003.001  
**Tool Tested:** Mimikatz  
**Platform:** Windows  
**Data Source:** Splunk (WinEventLog:Security)

---

## SPL Query – Splunk

```spl
index=windows sourcetype=WinEventLog:Security
(EventCode=4688 OR EventCode=10)
(ProcessName="*mimikatz*" OR ProcessName="*procdump*" OR CommandLine="*lsass*")
| table _time, ComputerName, User, ProcessName, CommandLine
```

---

## Detection Logic

- Filters for known tools that access `lsass.exe` (e.g., Mimikatz, Procdump)
- Matches on Event IDs for process creation and access events

---

## Alert Logic Recommendation

- **Triage Priority:** High
- **Action:** Investigate process ancestry, isolate host, validate with endpoint telemetry

---

## Validated In Lab

Detected Mimikatz execution in test scenarios  
Verified visibility via Windows logs and SPL query matches
