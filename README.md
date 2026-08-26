
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
| **Defense Evasion** | `T1562.002` | Disable Windows Event Logs | Security `7040` | EventLog service configuration state changes. |

---

## 3. Investigation & Artifact Analysis

### 3.1. Password Spraying & Brute Force Detection
```powershell
.\DeepBlue.ps1 .\evtx-attack-samples\Security\password-spray-4625.evtx
```

**Log Clearing Pre-check:** **Event 1102** triggered at **4/30/2019 4:27:00 PM**, indicating the Security log was intentionally cleared immediately prior to the spray.

**Exploitation Artifact:** At **4/30/2019 4:27:40 PM**, **Event 4648** (A logon was attempted using explicit credentials) was detected in rapid succession, identifying an automated password spraying sequence against domain accounts.

---

### 3.2 Credential Dumping Via Mimikatz
```powershell
.\DeepBlue.ps1 .\evtx\mimikatz-privesc-hashdump.evtx
```

**Anti-Forensics:** **Event 1102** logged at **4/30/2019 3:08:22 PM**, representing manual audit log destruction.

**Privilege Abuse:** Seven seconds later (**4/30/2019 3:08:29 PM**), **Event 4673** (A privileged service was called) flagged **SeDebugPrivilege** abuse commonly leveraged by **Mimikatz** to access lsass.exe memory spaces for credential extraction.

---

### 3.3 Obfuscated PowerShell Execution (Invoke-Obfuscation)
```powershell
.\DeepBlue.ps1 .\evtx\Powershell-Invoke-Obfuscation-encoding-menu.evtx
```

**Analysis of Script Block Logging (Event ID 4104)** on **8/30/2017** revealed an array of progressive obfuscation layers generated via **Invoke-Obfuscation**:

**Hex/ASCII Array Reassembly (4:13:38 PM - 4:13:52 PM):**

**Detection:** Command lines with low alphanumeric ratios (45%–56%).

**Mechanism:** **Base-16** hexadecimal strings and **ASCII** decimal arrays converted at runtime via [Char][Convert]::ToInt16(), resolved through environment variable indexing ($env:ComSpec[4,15,25] to build iex).

**Octal & Binary Encoding (4:14:33 PM - 4:14:51 PM):**

**Detection:** String payloads exceeding 1000 bytes with 75% zeros and ones.

**Mechanism:** Multi-delimiter string splitting (-split 'o' -split '&' -split 'r') piping into base-2/base-8 runtime converters.

**SecureString / Crypto Streams (4:15:23 PM):**

**Detection:** 500+ consecutive **Base64** characters and long command line alerts.

**Mechanism:** Decryption via [Runtime.InteropServices.Marshal]::PtrToStringBSTR() combined with AES-encrypted SecureString structures.

**Special Character & Whitespace Insertion (4:15:43 PM - 4:16:25 PM):**

**Detection:** Alphanumeric symbol ratios dropping as low as 3% to 6%.

**Mechanism:** Variable substitution and XOR operations (-BXor "0x5d"), using character array indexing (''.IndexOf.ToString()[106,482,184]) to dynamically construct iex without invoking raw string literals.

---

### 3.4 Defense Evasion via Event Log Service Disruption
```powershell
.\DeepBlue.ps1 .\evtx\disablestop-eventlog.evtx
```

**Log Purging:** **Event 104** detected in the System log at **4/27/2019 6:04:25 PM**, capturing an explicit log wipe.

**Service Tampering:** **Event 7040** observed between **6:04:32 PM and 6:04:51 PM**, registering a start-type change in the Windows Event Log service (from Auto Start to Disabled), followed by service termination to halt telemetry collection.
