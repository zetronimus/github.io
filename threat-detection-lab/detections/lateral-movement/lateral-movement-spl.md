# Detection – Lateral Movement via PsExec (Splunk SPL)

**MITRE ATT&CK ID:** T1021.002  
**Tool Tested:** PsExec / Impacket  
**Platform:** Windows  
**Data Source:** Splunk (WinEventLog:Security)

---

## SPL Query – Splunk

```spl
index=windows sourcetype=WinEventLog:Security
(EventCode=5140 OR EventCode=4688)
(Object_Name="\\\\ADMIN$" OR CommandLine="*psexec*")
| table _time, ComputerName, User, Object_Name, CommandLine
```

---

## Detection Logic

- Detects share access to ADMIN$ or C$ drives (lateral movement channels)
- PsExec invocation captured via command-line flags or binary execution

---

## Alert Logic Recommendation

- **Triage Priority:** High
- **Action:** Correlate with Event ID 7045 (service creation), isolate endpoint, inspect remote tools

---

## Validated In Lab

Detected lateral access and PsExec executions from multiple tools
Matched known Impacket and Microsoft Sysinternals PsExec activity
