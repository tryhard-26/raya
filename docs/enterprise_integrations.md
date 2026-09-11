# Enterprise Integrations: SARIF & STIX 2.1

Raya natively exports detection results to standard cybersecurity interchange formats for seamless integration with GitHub Code Scanning, SIEMs, SOAR platforms, and Threat Intelligence Platforms (TIPs).

---

## 1. OASIS SARIF v2.1.0 (`--format sarif`)

The **Static Analysis Results Interchange Format (SARIF)** enables direct integration into GitHub Advanced Security, CI/CD pipelines, and security dashboards.

```bash
raya scan sample.exe --rules rules/ --format sarif > scan_results.sarif
```

### SARIF Features in Raya

* **Markdown Messages**: Rich GitHub-rendered tables detailing the triggered rule, SHA-256 hash, and clickable MITRE ATT&CK links.
* **Exact Byte Offsets**: Populates `relatedLocations` with precise `byteOffset` fields pointing to pattern occurrences inside the artifact.
* **Properties Bag**: Includes threat scores, threat levels, file hashes, and matched indicators.

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Raya",
          "version": "0.1.0"
        }
      },
      "results": [
        {
          "ruleId": "ransomware_wannacry",
          "level": "error",
          "message": {
            "markdown": "**Rule:** `ransomware_wannacry` (Critical)\n**Target:** `sample.exe` (SHA-256: `ed01ebfb...`)\n**MITRE ATT&CK:** [T1486](https://attack.mitre.org/techniques/T1486/)\n\n### Evidence Indicators\n- Pattern $tasksche (1 hit(s) at [0xf4d8])\n- Pattern $icacls (1 hit(s) at [0xf4fc])",
            "text": "ransomware_wannacry: Detects WannaCry ransomware artifacts"
          },
          "properties": {
            "threatScore": 85,
            "threatLevel": "MALICIOUS",
            "attackTactics": ["Impact (Ransomware)"]
          },
          "relatedLocations": [
            {
              "id": 1,
              "physicalLocation": {
                "artifactLocation": { "uri": "sample.exe" },
                "region": { "byteOffset": 62680 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## 2. OASIS STIX 2.1 (`--format stix`)

The **Structured Threat Information Expression (STIX™ 2.1)** format enables direct ingestion into TIPs (OpenCTI, MISP, ThreatConnect) and SOC playbooks.

```bash
raya scan sample.exe --rules rules/ --format stix > threat_intel.json
```

### STIX 2.1 Domain Objects (SDOs) in Raya

1. **File Cyber Observable Object (SCO)**:
   * Hashes: MD5, SHA-1, SHA-256, IMPHASH, SSDEEP.
   * File size and canonical identifier.
2. **Indicator SDO**:
   * Name, labels, and STIX patterning expression: `[file:hashes.'SHA-256' = '...']`.
   * Calibrated confidence score (30–95).
   * External reference to MITRE ATT&CK technique URL.
   * Extended properties (`x_raya_threat_score`, `x_raya_threat_level`, `x_raya_matched_indicators`).
3. **Relationship SDO**:
   * `relationship_type`: `"indicates"`.
   * Graph edge linking the `indicator--...` SDO to the `file--...` SCO.

```json
{
  "type": "bundle",
  "id": "bundle--raya-scan-...",
  "objects": [
    {
      "type": "file",
      "spec_version": "2.1",
      "id": "file--ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
      "hashes": {
        "SHA-256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "IMPHASH": "68f013d7437aa653a8a98a05807afeb1",
        "SSDEEP": "98304:hNFz51uBWtdUzAV9fGO3ibJJGmRp:jFl1OWLUzArfGQ0fzRp"
      }
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--raya-0-ransomware_wannacry",
      "confidence": 95,
      "name": "ransomware_wannacry",
      "external_references": [
        { "source_name": "mitre-attack", "external_id": "T1486", "url": "https://attack.mitre.org/techniques/T1486/" }
      ],
      "x_raya_threat_score": 85,
      "x_raya_threat_level": "MALICIOUS"
    },
    {
      "type": "relationship",
      "spec_version": "2.1",
      "id": "relationship--raya-0-ransomware_wannacry",
      "relationship_type": "indicates",
      "source_ref": "indicator--raya-0-ransomware_wannacry",
      "target_ref": "file--ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
    }
  ]
}
```
