title: LSASS Access for Credential Dumping
id: 4133dc38-122c-4f3e-8b93-acc2bcb96e21
status: experimental
description: Detects potential credential dumping through suspicious access to LSASS
author: zetronimus
date: 2025/06/22
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'lsass'
    Image|endswith:
      - 'procdump.exe'
      - 'procdump64.exe'
      - 'taskmgr.exe'
      - 'mimikatz.exe'
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1003.001
falsepositives:
  - System diagnostics
  - Admin debugging tools
