# Ransomware Incident Response Playbook

**Objective**: Contain, eradicate, and recover from ransomware attacks while preserving evidence and minimizing downtime.

---

## Phase 1: Detection & Initial Triage

- **Common Indicators**:
  - Files with unusual extensions (e.g., `.locked`, `.crypt`)
  - Ransom notes in user directories
  - Large amounts of disk write activity
  - Suspicious PowerShell or WMI activity

- **Relevant MITRE ATT&CK Techniques**:
  - `T1486` – Data Encrypted for Impact
  - `T1059` – Command and Scripting Interpreter
  - `T1204` – User Execution

- **Initial Actions**:
  - Isolate affected endpoints from the network
  - Notify the IR team and executive leadership
  - Begin evidence collection (memory, disk, logs)

---

## Phase 2: Investigation

- Review EDR logs to trace patient zero
- Identify execution method and payload dropper
- Analyze attacker lateral movement
- Correlate artifacts across systems (e.g., ransom notes, registry entries, new services)

---

## Phase 3: Containment & Eradication

- Reset passwords for impacted accounts
- Block malicious hashes and IPs in EDR/firewall
- Remove persistence mechanisms (e.g., scheduled tasks, services)
- Patch exploited vulnerabilities

---

## Phase 4: Recovery

- Validate and restore from known-good backups
- Reimage compromised systems if needed
- Monitor post-restoration behavior for anomalies

---

## Phase 5: Lessons Learned

- Update detection rules (e.g., add Sigma/YARA signatures)
- Conduct internal post-mortem
- Provide training to users to avoid similar incidents
