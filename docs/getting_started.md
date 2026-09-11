# Getting Started with Raya

This guide gets you up and running with Raya in under 5 minutes.

---

## 1. Installation

### Option A: Via Cargo (Crates.io)

```bash
cargo install raya
```

### Option B: Build from Source

```bash
git clone https://github.com/tryhard-26/raya.git
cd raya
cargo build --release
cargo install --path .
```

Verify your installation:

```bash
raya --version
```

---

## 2. Basic Commands Cheatsheet

| Task | Command |
| :--- | :--- |
| **Scan a single file** | `raya scan sample.exe --rules rules/` |
| **Scan an entire directory** | `raya scan /path/to/samples/ --rules rules/` |
| **Scan stdin (stream / pipe)** | `cat sample.bin \| raya scan - --rules rules/` |
| **Scan password-protected archive** | `raya scan drop.zip --rules rules/ --password infected` |
| **Export to OASIS SARIF v2.1.0** | `raya scan sample.exe --rules rules/ --format sarif > report.sarif` |
| **Export to OASIS STIX 2.1** | `raya scan sample.exe --rules rules/ --format stix > bundle.json` |
| **Export to Machine-Readable JSON** | `raya scan sample.exe --rules rules/ --format json > report.json` |
| **Precompile rules to binary cache** | `raya scan sample.exe --rules rules/ --save-rules compiled.rc` |
| **Scan using compiled rules** | `raya scan sample.exe --load-rules compiled.rc` |
| **Validate rule syntax** | `raya check rules/ --verbose` |
| **Execute test specification** | `raya test tests/fixtures/test_spec.json` |
| **Run pattern-matching benchmarks** | `raya bench --rules rules/` |

---

## 3. Your First Scan

Scan one of the bundled malware or test fixtures:

```bash
# Scan a real encrypted WannaCry ransomware archive
raya scan samples/malware/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.zip --rules rules/
```

Expected Terminal Output:

```text
Target:       samples/malware/...zip -> ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe
Size:         3514368 bytes
Type:         PE32
SHA256:       ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
IMPHASH:      68f013d7437aa653a8a98a05807afeb1
Entropy:      8.00 / 8.0
Threat Level: [MALICIOUS] (Score: 85/100)
ATT&CK Chain: Impact (Ransomware)

MATCHES (1 rule(s) triggered):

[CRITICAL] ransomware_wannacry (windows, ransomware)
  Description: Detects WannaCry ransomware artifacts, command execution strings, and drop mechanisms
  ATT&CK:      T1486
  Evidence:
    ✓ Pattern $tasksche (1 hit(s) at [0xf4d8])
    ✓ Pattern $icacls (1 hit(s) at [0xf4fc])
  Verdict Reason: Condition satisfied with 2 evidence indicator(s)
```

---

## 4. Writing Your First Rule

Create a file named `my_rule.raya`:

```raya
rule detect_suspicious_alloc : windows injection {
    meta:
        description = "Detects RWX memory allocation for shellcode staging"
        severity = "critical"
        technique = "T1055.002"

    strings:
        $va = "VirtualAlloc" ascii wide

    condition:
        pe.is_pe and (
            pe.api_call_arg("VirtualAlloc", 0x40)
            or (pe.has_rwx and pe.in_basic_block("push", "call"))
        )
}
```

Verify your rule syntax:

```bash
raya check my_rule.raya
```

Scan a target sample with your custom rule:

```bash
raya scan target_sample.exe --rules my_rule.raya
```

---

## 5. Next Steps

* Read the [Rule Authoring Guide](rule_writing_guide.md) to explore regex, hex wildcards, jump tokens, and AST expressions.
* Explore [Advanced Capabilities](advanced_capabilities.md) for basic-block scoping and API call argument tracking.
* Learn about [Threat Scoring & MITRE ATT&CK](threat_scoring.md) for automated triage metrics.
