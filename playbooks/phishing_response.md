# Phishing Incident Response Playbook

**Objective**: Detect, analyze, and respond to phishing emails targeting users to steal credentials or deploy malware.

---

## Phase 1: Detection & Reporting

- **Sources**:
  - User-reported suspicious email
  - EDR email threat detections
  - SIEM alerts (e.g., abnormal login locations)

- **Relevant MITRE ATT&CK Techniques**:
  - `T1566.001` – Spearphishing Attachment
  - `T1566.002` – Spearphishing Link
  - `T1110` – Brute Force (post-phish credential use)

---

## Phase 2: Investigation

- Review email headers and body
- Sandbox or manually detonate attachments/URLs
- Check user activity post-click
- Query SIEM/EDR for indicators and spread

---

## Phase 3: Containment

- Revoke or reset credentials
- Block malicious sender domains and IPs
- Remove emails from mailboxes via EWS/Graph API
- Notify affected users

---

## Phase 4: Recovery

- Monitor user activity
- Re-enable services once threats are cleared
- Brief employees on phishing awareness

---

## Phase 5: Lessons Learned

- Improve detection rules (URL filtering, mail flow rules)
- Conduct awareness training
- Submit indicators to threat intel feeds
