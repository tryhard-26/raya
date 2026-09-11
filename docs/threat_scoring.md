# Threat Scoring & MITRE ATT&CK Mapping

In automated security operations, binary "match" vs "no-match" decisions are insufficient. Raya calculates a **composite threat score (0–100)**, an analyst-facing **threat level badge**, and aggregates a **MITRE ATT&CK kill-chain progression**.

---

## 1. Threat Levels

| Threat Level | Score Range | Meaning | Typical Automated Action |
| :--- | :--- | :--- | :--- |
| `CLEAN` | 0 | No suspicious patterns or structural anomalies detected. | Allow through pipeline. |
| `LOW RISK` | 1 – 29 | Informational or low-severity indicators. | Log to telemetry. |
| `SUSPICIOUS` | 30 – 59 | Medium-severity indicators or anomalous section entropy. | Route to analyst queue for manual inspection. |
| `HIGH RISK` | 60 – 79 | High-severity rule matches combined with binary anomalies. | Quarantine / block sample. |
| `MALICIOUS` | 80 – 100 | Critical malware family detection, active RWX payloads, or dangerous API manipulation. | Immediate host isolation / automated C2 block. |

---

## 2. Threat Scoring Algorithm

The composite score is calculated dynamically based on:

### A. Rule Severities
* `Critical`: **+70 points**
* `High`: **+40 points**
* `Medium`: **+20 points**
* `Low`: **+10 points**
* `Info`: **+3 points**

### B. Behavioral Forensics
* `ApiCallArgument` match (e.g. `PAGE_EXECUTE_READWRITE` / `0x40`): **+15 points**

### C. Structural & Statistical Anomalies
* Global entropy > 7.8 (strongly compressed or encrypted): **+15 points**
* Global entropy > 7.2 (packed or high-density code): **+10 points**
* Presence of an RWX section (Read, Write, Execute): **+20 points**
* Registered TLS callbacks (anti-analysis / pre-main execution): **+10 points**
* Anomalous section count (> 10 sections): **+10 points**

The final composite score is capped at 100 points.

---

## 3. MITRE ATT&CK Kill-Chain Mapping

When rules define a `technique` attribute (e.g. `technique = "T1486"`), Raya correlates the techniques and constructs a kill-chain progression:

```
ATT&CK Chain: Privilege Escalation / Injection -> Defense Evasion (Obfuscation) -> Impact (Ransomware)
```

### Supported Technique-to-Tactic Mappings

* `T1055`: Privilege Escalation / Injection
* `T1059`: Execution
* `T1071`: Command and Control (C2)
* `T1486`: Impact (Ransomware)
* `T1547`: Persistence
* `T1027`: Defense Evasion (Obfuscation)
* `T1036`: Defense Evasion (Masquerading)
* `T1082`: Discovery
* `T1003`: Credential Access
* `T1566`: Initial Access
