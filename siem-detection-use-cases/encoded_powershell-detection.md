
---

### Encoded PowerShell Command Detection

**Description**: Flags PowerShell commands using base64-encoded payloads, a common obfuscation tactic used by malware and red teams.

---

### Use Case
- Detect attacks bypassing traditional signature-based AV
- Useful for both on-host EDR and SIEM log analysis

---

Detection Logic

Sigma

```
detection:
  selection:
    CommandLine|contains:
      - 'powershell'
      - '-enc'
      - '-encodedcommand'
  condition: selection
  ```

#KQL

```
DeviceProcessEvents
| where ProcessCommandLine has "powershell"
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
```

#SPL

```
index=main sourcetype=windows_process
Image=*powershell* 
CommandLine IN ("*-enc*", "*-encodedcommand*")
```

#MITRE ATT&CK

T1059 – Command and Scripting Interpreter
T1203 – Exploitation for Client Execution
