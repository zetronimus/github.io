# Parent Process Anomaly Detection

**Description**: Detects suspicious parent-child process relationships, such as `winword.exe` spawning `cmd.exe` — commonly used in phishing payloads or malware delivery.

---

## Use Case
- Identify LOLBin abuse (e.g., Excel or Word launching CMD)
- Useful for catching macro-based malware

---

## Detection Logic
### Sigma

```yaml
detection:
  selection:
    ParentImage|endswith:
      - '\\winword.exe'
      - '\\excel.exe'
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
  condition: selection
```

### KQL

```
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("WINWORD.EXE", "EXCEL.EXE")
| where FileName in~ ("cmd.exe", "powershell.exe")
```

### Splunk

```
index=main sourcetype=windows_process
ParentImage IN ("*\\winword.exe", "*\\excel.exe") 
Image IN ("*\\cmd.exe", "*\\powershell.exe")
```

### MITRE ATT&CK

T1059.001 – PowerShell
T1027 – Obfuscated Files or Information
