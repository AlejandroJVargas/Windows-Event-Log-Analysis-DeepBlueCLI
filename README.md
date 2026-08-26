
# Windows Event Log Threat Hunting & Forensics (DeepBlueCLI)

## 1. Executive Summary
This project demonstrates rapid endpoint triage and proactive threat hunting using **DeepBlueCLI** and **PowerShell** across Windows Security, System, and Sysmon Event Logs (`.evtx`). The investigation analyzes real-world attack artifacts—including credential harvesting, brute-force password spraying, encoded command execution, and defense evasion attempts—mapped directly to the **MITRE ATT&CK** matrix.

---

## 2. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Target Event ID | Detection Scope |
| :--- | :--- | :--- | :--- | :--- |
| **Credential Access** | `T1110.003` | Password Spraying | Security `4625` | Repeated failed logon bursts across multiple accounts. |
| **Credential Access** | `T1003.001` | LSASS Memory Dumping (Mimikatz) | Sysmon `1`, `10` | Suspicious process access targeting `lsass.exe`. |
| **Execution** | `T1059.001` | PowerShell Obfuscation & Encoded Commands | PowerShell `4104` / `4688` | Base64-encoded strings and suspicious CLI arguments. |
| **Defense Evasion** | `T1070.001` | Clear Windows Event Logs | Security `1102` / System `104` | Audit log clearing to destroy digital evidence. |

---

## 3. Investigation & Artifact Analysis

### 3.1. Password Spraying & Brute Force Detection
```powershell
.\DeepBlue.ps1 .\evtx-attack-samples\Security\password-spray-4625.evtx
