# Encoded Powershell Detection

**Description**: Flags PowerShell commands using base64-encoded payloads, often used in obfuscated malware or red team simulations.

---

## Use Case
- Detect attempts to bypass AV and EDR visibility
- Works well on command line telemetry or process logs

---

## Detection Logic

### Sigma

```yaml
detection:
  selection:
    CommandLine|contains:
      - 'powershell'
      - '-enc'
      - '-encodedcommand'
  condition: selection
```

### KQL

```kql
DeviceProcessEvents
| where ProcessCommandLine has "powershell"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
```

### SPL

```spl
index=main sourcetype=windows_process
Image=*powershell* 
CommandLine IN ("*-enc*", "*-encodedcommand*")
```

### MITRE ATT&CK

T1059 – Command and Scripting Interpreter
T1203 – Exploitation for Client Execution
