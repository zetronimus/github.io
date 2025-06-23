title: Lateral Movement via PsExec
id: 9f2d1b86-ec90-4f26-926f-35f8c4c39c19
status: experimental
description: Detects use of PsExec or remote ADMIN$ share access for lateral movement
author: Your Name
date: 2025/06/22
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'psexec'
    Image|endswith:
      - 'psexec.exe'
  selection2:
    ShareName|contains:
      - '\\ADMIN$'
  condition: selection or selection2
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.002
falsepositives:
  - Legitimate administrative access
  - Patch deployment tools
