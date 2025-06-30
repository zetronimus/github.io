# Threat Intelligence Enrichment Tool

This Python script enriches IOC (Indicator of Compromise) data using open-source threat intelligence APIs like VirusTotal and Shodan.

---

## Features

- Lookup file hashes in VirusTotal
- Query Shodan for open ports and vulnerabilities on IPs
- Designed for use in investigations, detections, and threat intelligence enrichment

---

## Sample Usage

### VirusTotal Hash Lookup

```python
import requests

API_KEY = 'YOUR_API_KEY'
HASH = '44d88612fea8a8f36de82e1278abb02f'

url = f'https://www.virustotal.com/api/v3/files/{HASH}'
headers = { 'x-apikey': API_KEY }

response = requests.get(url, headers=headers)
if response.status_code == 200:
    data = response.json()
    print("Malicious Detections:", data['data']['attributes']['last_analysis_stats']['malicious'])
else:
    print("Error:", response.status_code)
