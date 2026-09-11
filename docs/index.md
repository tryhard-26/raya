# Raya Documentation

Welcome to the official documentation for **Raya**, the Rust-native malware detection and binary pattern-matching engine.

---

## Navigation & Guides

* **[Quick Start & Basic Commands](getting_started.md)**: 5-minute setup, installation, and first scans.
* **[CLI Reference](cli_reference.md)**: Detailed reference for all CLI subcommands, flags, exit codes, and parameters.
* **[Rule Authoring Guide](rule_writing_guide.md)**: Writing Raya rules, string patterns, hex byte tokens, PE/ELF modules, and instruction disassembly.
* **[Advanced Binary Capabilities & Scoping](advanced_capabilities.md)**: Basic-block scoping, function-level boundaries, and static API call argument tracking.
* **[Threat Scoring & MITRE ATT&CK](threat_scoring.md)**: Composite 0–100 threat scoring, risk level classifications, and kill-chain mapping.
* **[Enterprise Formats: SARIF & STIX](enterprise_integrations.md)**: Exporting detections to OASIS SARIF v2.1.0 and OASIS STIX 2.1 Threat Intelligence Bundles.
* **[Architecture & Engine Internals](architecture.md)**: Memory safety, zero-panic guarantees, in-memory archive triage, and Pratt expression parsing.

---

## What Sets Raya Apart?

Unlike traditional pattern matchers, Raya is designed specifically for modern security operations, automated triage pipelines, and binary reverse engineering:

1. **Zero-Empty-Evidence Guarantee**: Every detection alert is backed by an evidence graph containing byte offsets, imported APIs, exported symbols, and deep section characteristics.
2. **Native In-Memory Archive & Encrypted Drop Triage**: Scans inside standard and AES-encrypted `.zip` files in-memory, automatically trying standard malware passwords (`infected`, `malware`, `password`, `clean`, `1234`) without dropping payloads to disk.
3. **Deep RWX Forensics**: Documents exact offending section names, Virtual Addresses (VA), Virtual Sizes, Raw Sizes, and permission characteristics bitmasks (`0xE0000060`).
4. **Basic-Block & Function Scoping**: Disassembles code via `iced-x86` and verifies that instruction sequences co-occur within the **same basic block** without crossing branch/jump boundaries.
5. **Static API Call Argument Tracking**: Detects critical API invocations prepared with dangerous constants (e.g. `VirtualAlloc` called with `PAGE_EXECUTE_READWRITE` / `0x40`).
6. **Composite Threat Scoring (0–100)**: Translates multi-indicator findings into a calibrated threat score and risk level (`CLEAN`, `LOW RISK`, `SUSPICIOUS`, `HIGH RISK`, `MALICIOUS`).
7. **Standards-Compliant Exports**: Direct output to OASIS SARIF v2.1.0 and OASIS STIX 2.1 JSON bundles for SIEM, SOAR, and GitHub Code Scanning pipelines.
8. **100% Rust Memory Safety**: Immune to the memory corruption vulnerabilities that historically plague C-based PE/ELF parsing engines.
