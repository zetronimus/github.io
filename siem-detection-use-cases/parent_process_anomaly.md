# Parent Process Anomaly Detection

**Description**: Detects suspicious parent-child process relationships, such as `winword.exe` spawning `cmd.exe` — common in phishing and macro-based malware.

---

### Use Case
- Identify LOLBins (living-off-the-land binaries) abuse
- Catch unusual behavior chains (e.g., `excel.exe` → `powershell.exe`)

---

### Detection Logic 

#Sigma

```
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

#MKQL

```
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("WINWORD.EXE", "EXCEL.EXE")
| where FileName in~ ("cmd.exe", "powershell.exe")
```

#Splunk

```
index=main sourcetype=windows_process
ParentImage IN ("*\\winword.exe", "*\\excel.exe") 
Image IN ("*\\cmd.exe", "*\\powershell.exe")
```
