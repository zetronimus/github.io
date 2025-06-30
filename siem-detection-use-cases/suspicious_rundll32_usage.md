# Suspicious Rundll32 Usage
---

**Description**: Detects rare or suspicious `rundll32.exe` command line arguments — commonly used for LOLBin attacks or fileless malware execution.

---

## Use Case
- Flag abuse of trusted Windows binaries
- Detect early-stage malware attempts using `rundll32`

---

## Detection Logic

```yaml
detection:
  selection:
    Image|endswith: '\\rundll32.exe'
    CommandLine|contains:
      - 'javascript'
      - 'shell32.dll,ShellExec_RunDLL'
  condition: selection
```

### KQL

```kql
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("javascript", "ShellExec_RunDLL")
```

### SPL

```spl
index=main sourcetype=windows_process
Image=*rundll32.exe*
CommandLine IN ("*javascript*", "*ShellExec_RunDLL*")
```

### MITRE ATT&CK

T1218.011 – Signed Binary Proxy Execution: Rundll32
