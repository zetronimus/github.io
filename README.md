# Hi, I'm Zetron

I'm a cybersecurity professional with over 8 years of experience in threat detection, incident response, cloud security, and security operations. I specialize in building and tuning detections, leading incident investigations, and designing secure environments across Azure and AWS.

---

## My Focus Areas

- **Incident Response** – Performing rapid triage, containment, and recovery for security incidents across hybrid environments
- **Threat Hunting** – Developing proactive detection logic based on MITRE ATT&CK and current threat intel
- **Cloud Security** – Securing Azure and AWS infrastructure, identity, and workload configurations
- **EDR & SIEM Operations** – Deep hands-on work with tools like CrowdStrike, SentinelOne, Splunk, and Microsoft Sentinel
- **Security Automation** – Writing detection rules, scripts, and playbooks to streamline SOC processes
- **Frameworks** – Strong knowledge of NIST, CIS Benchmarks, SOC 2, and MITRE ATT&CK

---

## Featured Projects

### [Threat Detection Lab](./threat-detection-lab/README.md)
A home lab designed to emulate adversary behaviors and validate detection rules across multiple environments. Includes simulated attacks such as:
- Command and Control (C2) over HTTPS using Cobalt Strike
- Lateral movement via SMB and PsExec
- Credential dumping with Mimikatz
- Privilege escalation and scheduled task persistence
These attack scenarios are used to test SIEM rules and EDR detections mapped to MITRE ATT&CK.

### [Incident Response Playbooks](./incident-response-playbooks/README.md)
A collection of IR playbooks for ransomware, phishing, insider threat, and cloud account compromise scenarios. 

➡[View Sample Ransomware Playbook](./incident-response-playbooks/ransomware-playbook.md) – Documents containment, eradication, and recovery steps with mapped MITRE ATT&CK tactics and response time objectives.

➡[View Sample Phishing Playbook](./incident-response-playbooks/phishing-playbook.md) – Covers email header analysis, credential reset workflows, and downstream account compromise detection.

### [SIEM Detection Use Cases](./siem-detection-use-cases/README.md)
Microsoft Sentinel & Splunk KQL/SPL queries mapped to MITRE ATT&CK to detect common TTPs.

**KQL Sample – Suspicious PowerShell Execution**:
```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName has "powershell.exe"
  and CommandLine has_any ("-enc", "-nop", "iex", "bypass")
| project TimeGenerated, Computer, Account, CommandLine
```

**SPL Sample – Suspicious PowerShell Use**:
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688
| where process_name="powershell.exe"
| search CommandLine="*-enc*" OR CommandLine="*-nop*" OR CommandLine="*iex*"
| table _time, user, ComputerName, CommandLine
```

These use cases detect obfuscated or encoded PowerShell usage commonly associated with malicious activity.

### [Threat Intelligence Enrichment Tool](./threat-intel-enrichment/README.md)
A Python script to enrich IOC data using VirusTotal and Shodan APIs.

**Sample Code – VirusTotal Hash Lookup**:
```python
import requests

API_KEY = 'YOUR_API_KEY'
HASH = '44d88612fea8a8f36de82e1278abb02f'

url = f'https://www.virustotal.com/api/v3/files/{HASH}'
headers = {
    "x-apikey": API_KEY
}

response = requests.get(url, headers=headers)
if response.status_code == 200:
    data = response.json()
    print(f"Malicious Detections: {data['data']['attributes']['last_analysis_stats']['malicious']}")
else:
    print("Error with request:", response.status_code)
```
This tool automates IOC lookups to support incident enrichment and threat correlation workflows.

---

## Let’s Connect
- [LinkedIn](https://linkedin.com/in/zetron-cakha)
- Hack The Box: `@zetronimus`

---

> This page is a living document — more tools and research will be added as I continue building.
