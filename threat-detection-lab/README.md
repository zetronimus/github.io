# Threat Detection Lab

This project simulates real-world adversary behavior to test detection capabilities across SIEM and EDR tools. It’s designed for blue teamers and detection engineers to validate detection logic using MITRE ATT&CK techniques.

---

## Lab Setup

| Component     | Description                              |
|---------------|------------------------------------------|
| Host OS       | Windows 10 / Server 2019                 |
| Tools         | Cobalt Strike (legit or emulated), Mimikatz, PsExec, PowerShell |
| Logging       | Sysmon, Windows Event Logs, PowerShell Logs |
| SIEM          | Microsoft Sentinel / Splunk              |
| EDR           | CrowdStrike Falcon / Defender for Endpoint |
| Environment   | Hyper-V, Proxmox, or VirtualBox (your choice) |

---

## Simulated Attacks

### 1. C2 over HTTPS
- **Tool:** Cobalt Strike (or custom HTTPS backdoor)
- **ATT&CK:** `T1071.001` – Application Layer Protocol: Web Protocols
- **Detection:** Unusual outbound traffic, PowerShell spawning hidden processes

### 2. Lateral Movement via SMB
- **Tool:** PsExec / SMBExec
- **ATT&CK:** `T1021.002` – Remote Services: SMB/Windows Admin Shares
- **Detection:** Admin share access from unusual hosts, Event ID 4624/4672

### 3. Credential Dumping
- **Tool:** Mimikatz
- **ATT&CK:** `T1003.001` – LSASS Memory
- **Detection:** Access to LSASS, signed binary abuse, Process access attempts

### 4. Persistence via Scheduled Task
- **Tool:** `schtasks`, registry run keys
- **ATT&CK:** `T1053.005`, `T1547.001`
- **Detection:** New scheduled task creation, registry autorun changes

---

## Use Cases

Each attack includes:
- Sample telemetry
- MITRE ATT&CK mapping
- Detection rule snippets (KQL/SPL/Sigma)
- Recommended alert logic

---

## Resources

- [MITRE ATT&CK Navigator](https://attack.mitre.org/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Red Canary Blog](https://redcanary.com/blog/)

---

## Coming Soon

- `/logs/` – Sample logs and EDR telemetry
- `/detections/` – Sigma rules + KQL/SPL conversions
- `/playbooks/` – Triage and containment guides
- `/screenshots/` – Observed behaviors from live runs

---

> Built as part of my ongoing threat detection and blue team skill development. Contributions welcome!
