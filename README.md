# Raya

Rust-native malware detection and binary pattern-matching engine.

* **crates.io:** [crates.io/crates/raya](https://crates.io/crates/raya)
* **Repository:** [github.com/tryhard-26/raya](https://github.com/tryhard-26/raya)
* **License:** Apache-2.0

Raya is a static detection and binary pattern-matching engine engineered in Rust. It combines multi-pattern byte matching, regular expressions, deep Portable Executable (PE32/PE32+) and Executable and Linkable Format (ELF32/ELF64) inspection, x86/x64 instruction disassembly (`iced-x86`), and Shannon entropy calculation.

Every match produces an evidence trace detailing the exact string offsets, imported APIs, section flags, and entropy metrics that satisfied the rule conditions.

---

## Architectural Overview

```
                      ┌────────────────────────┐
                      │        Raya CLI        │
                      │ scan | check | test ...│
                      └───────────┬────────────┘
                                  │
           ┌──────────────────────┴──────────────────────┐
           ▼                                             ▼
┌──────────────────────┐                      ┌──────────────────────┐
│     Rule Parser      │                      │     Target File      │
│ Lexer & Pratt Parser │                      │  Format Det. / Hash  │
└──────────┬───────────┘                      └──────────┬───────────┘
           ▼                                             ▼
┌──────────────────────┐                      ┌──────────────────────┐
│    Compiled Rules    │                      │ Binary Context (AST) │
│ Strings / Conditions │                      │  PE / ELF / Entropy  │
└──────────┬───────────┘                      └──────────┬───────────┘
           │                                             │
           └──────────────────────┬──────────────────────┘
                                  ▼
                      ┌────────────────────────┐
                      │    Scanning Engine     │
                      │  Aho-Corasick / Regex  │
                      │   Evaluator & Trace    │
                      └───────────┬────────────┘
                                  ▼
                      ┌────────────────────────┐
                      │    Detection Report    │
                      │ Terminal (Ev.) / JSON  │
                      └────────────────────────┘
```

### Core Tenets

* **Zero-Panic Resilience:** All binary format decoders (PE, ELF) implement explicit bounds checking. Malformed, truncated, or deliberately corrupted files return safe diagnostics rather than aborting.
* **Extension-Independent Format Detection:** Files are classified based on authoritative magic bytes (`MZ` + `PE\0\0`, `\x7fELF`), preventing evasions through renaming (e.g., `payload.exe` named `image.png`).
* **High-Throughput Multi-Pattern Matching:** Literal patterns are matched via Aho-Corasick automata in single-pass linear time. Hex wildcards and regular expressions utilize byte-oriented finite automata.
* **Concurrency:** Recursive directory scans traverse files in parallel using work-stealing threads (`rayon`).

---

## Installation

### Install via Cargo (crates.io)

```bash
cargo install raya
```

### Install from Git

```bash
cargo install --git https://github.com/tryhard-26/raya.git
```

### Build from Source

```bash
git clone https://github.com/tryhard-26/raya.git
cd raya
cargo build --release
```

The optimized binary will be in `target/release/raya`. To install locally:

```bash
cargo install --path .
```

---

## CLI Reference

### 1. File & Directory Scanning (`raya scan`)

Scan an individual sample or an entire directory:

```bash
# Scan a single file using the starter rule pack
raya scan samples/malware.exe --rules rules/

# Scan streaming bytes from standard input (UNIX pipe)
cat payload.bin | raya scan -

# Recursively scan a directory in parallel with zero-copy memmap2
raya scan ./samples/ --rules rules/ --recursive

# Output machine-readable JSON for SIEM/orchestration pipelines
raya scan ./samples/ --rules rules/ --json

# Export standardized OASIS SARIF v2.1.0 for GitHub Security & CI/CD
raya scan ./samples/ --rules rules/ --format sarif

# Export OASIS STIX 2.1 Threat Intel Bundle (indicators & observed files)
raya scan ./samples/ --rules rules/ --format stix

# Scan live virtual memory of a running process (requires elevated privileges)
raya scan --pid 1337 --rules rules/

# Quiet mode for shell scripting (outputs <path>: <rule> on detection)
raya scan ./samples/ --rules rules/ --quiet

# Filter rules by tag
raya scan ./samples/ --rules rules/ --tag injection
```

**Exit Codes:**

* `0`: Clean (no rules matched)
* `1`: Detection (one or more rules triggered)
* `2`: Execution error (file unreadable, invalid rule syntax)

### 2. Pre-compiled Rule Cache (`raya compile`)

Pre-compile rule collections into a high-performance binary cache (`.rc`) for sub-millisecond rule loading:

```bash
# Compile rules into a binary cache
raya compile rules/ -o rules.rc

# Scan using the pre-compiled binary rule cache
raya scan samples/malware.exe -R rules.rc
```

### 2. Rule Validation (`raya check`)

Verify syntax, regex integrity, and structural validity of rule collections:

```bash
# Validate all rules in a directory
raya check rules/

# Verbose rule validation
raya check rules/ --verbose
```

### 3. Automated Rule Testing (`raya test`)

Execute regression test suites to guarantee positive detections and prevent false positives:

```bash
raya test tests/fixtures/test_spec.json
```

### 4. Performance Benchmarking (`raya bench`)

Measure throughput, scan latency, and rule compilation time:

```bash
raya bench tests/fixtures/ --rules rules/ --iterations 5
```

---

## Rule Language Specification

Raya detection rules are organized into `meta`, `strings`, and `condition` blocks:

```raya
rule process_injection : windows injection malware {
    meta:
        author = "Raya Research Team"
        description = "Detects characteristic Windows process injection API combinations"
        severity = "high"
        technique = "T1055"
        reference = "https://attack.mitre.org/techniques/T1055/"

    strings:
        $vae = "VirtualAllocEx" ascii wide
        $wpm = "WriteProcessMemory" ascii wide
        $crt = "CreateRemoteThread" ascii wide
        $stub = { 48 89 5C 24 ?? 48 89 ?? ?? 48 83 EC 20 }
        $b64 = /[A-Za-z0-9+\/]{80,}={0,2}/

    condition:
        ($vae and $wpm and $crt)
        or $stub
        or (2 of ($vae, $wpm, $crt) and pe.import("kernel32.dll", "VirtualAllocEx"))
}
```

### 1. Metadata Block (`meta:`)

* `author`: Author or research group.
* `description`: Detailed explanation of the threat or technique.
* `severity`: `info`, `low`, `medium`, `high`, `critical`.
* `technique`: MITRE ATT&CK technique mapping (e.g. `T1055`).
* Arbitrary key-value pairs (strings, integers, floats, booleans).

### 2. Strings Block (`strings:`)

* **Literal Strings:**

  ```text
  $str1 = "powershell" ascii
  $str2 = "VirtualAllocEx" wide        // Matches UTF-16LE encoding
  $str3 = "cmd.exe" ascii wide nocase  // Case-insensitive ASCII and UTF-16LE
  ```

* **Hexadecimal Byte Patterns:**
  Supports full byte wildcards (`??`) and high/low nibble wildcards (`4?`, `?8`):

  ```text
  $hex1 = { 48 8B ?? ?? 48 85 C0 }
  $hex2 = { 4? 8B ?4 24 }
  ```

* **Regular Expressions:**

  ```text
  $regex1 = /https?:\/\/[a-z0-9.\-]+\/beacon/i
  ```

### 3. Condition Block (`condition:`)

* **Boolean Logic:** `and`, `or`, `not`, parentheses `( ... )`.
* **String References:**
  * `$str`: True if pattern `$str` matched at least once.
  * `#str`: Match count of `$str` (e.g., `#str >= 3`).
  * `@str`: File byte offset of the first match of `$str` (e.g., `@str < 1024`).
* **Quantifiers:**
  * `2 of ($a, $b, $c)`
  * `2 of ($api_*)`
  * `all of them`
  * `any of them`
  * `none of them`
* **PE Executable Awareness (`pe.*`):**
  * `pe.is_pe`: Boolean indicating if target is a valid Portable Executable.
  * `pe.is_pe32_plus`: True for 64-bit PE32+ executables.
  * `pe.is_dll`: True if file is a dynamic link library.
  * `pe.is_signed`: True if file contains an Authenticode PKCS#7 digital signature.
  * `pe.has_rich_header`: True if Microsoft Rich Header compiler fingerprint is present.
  * `pe.has_rich_comp_id(30729)`: Matches compiler build ID in decrypted Rich Header.
  * `pe.number_of_sections`: Total number of sections.
  * `pe.has_rwx`: True if any section has Read-Write-Execute permissions.
  * `pe.import("kernel32.dll", "VirtualAllocEx")`: True if function is imported.
  * `pe.export("DllRegisterServer")`: True if function is exported.
  * `pe.section(".text").entropy > 7.2`: Queries section Shannon entropy.
  * `pe.section(".text").executable`: Section permission flag check.
  * `pe.section(".data").writable`: Section permission flag check.
* **ELF Executable Awareness (`elf.*`):**
  * `elf.is_elf`: Boolean indicating if target is a valid ELF executable.
  * `elf.is_64`: True for 64-bit ELF.
  * `elf.is_executable`: True for ET_EXEC binaries.
  * `elf.section(".text").executable`: Section permission flag check.
* **Mach-O Executable Awareness (`macho.*`):**
  * `macho.is_macho`: Boolean indicating if target is a valid Mach-O binary.
  * `macho.is_64`: True for 64-bit Mach-O (`0xFEEDFACF`).
  * `macho.is_fat`: True for Universal / FAT multi-architecture binaries (`0xCAFEBABE`).
  * `macho.is_signed`: True if file contains an embedded code signature (`LC_CODE_SIGNATURE`).
  * `macho.has_dylib("libSystem.B.dylib")`: Matches imported dynamic libraries (`LC_LOAD_DYLIB`).
  * `macho.has_segment("__TEXT")`: True if segment is defined.
  * `macho.has_section("__TEXT", "__text")`: True if specific section is present.
* **Entropy & Pattern Analysis:**
  * `entropy`: Global Shannon entropy across whole target ($0.0 - 8.0$).
  * `entropy.max_window_exceeds(512, 7.5)`: Sliding-window entropy exceeding threshold in any 512-byte cave.
  * `uint16(0) == 0x5a4d`: YARA-compatible byte inspection at file offset.
  * `$mz at 0`: Offset assertion for pattern match.
* **Global Target Attributes:**
  * `filesize`: File size in bytes (e.g., `filesize > 10MB`).
  * `entropy`: Whole-file Shannon entropy (0.0 to 8.0).

---

## Detection Explainability

Raya displays an evidence breakdown with every match:

```text
Target: samples/injection_sample.exe
Size:   2560 bytes
Type:   PE32+
SHA256: 308cef28bb96280421364a9b90030cd0482779a5a575bafcc03b09b3412df06a
Entropy: 1.43 / 8.0

MATCHES (1 rule(s) triggered):

[HIGH] process_injection (windows, injection, malware)
  Description: Detects characteristic Windows process injection API combinations
  ATT&CK:      T1055
  Evidence:
    ✓ Pattern $vae (1 hit(s) at [0x400])
    ✓ Pattern $wpm (1 hit(s) at [0x40f])
    ✓ Pattern $crt (1 hit(s) at [0x422])
  Verdict Reason: Condition satisfied with 3 evidence indicator(s)
```

In JSON output mode (`--json`), evidence is structured for ingestion:

```json
{
  "target": "samples/injection_sample.exe",
  "file_size": 2560,
  "file_type": "PE32+",
  "hashes": {
    "sha256": "308cef28bb96280421364a9b90030cd0482779a5a575bafcc03b09b3412df06a",
    "sha1": "75462994eccd43f583c178b59a41bafd54f0c063",
    "md5": "8f437d82a5ccdae226c60ff05aff960c"
  },
  "entropy": 1.4257,
  "matches": [
    {
      "rule": "process_injection",
      "severity": "high",
      "tags": ["windows", "injection", "malware"],
      "mitre_technique": "T1055",
      "matched_indicators": ["$vae", "$wpm", "$crt"],
      "evidence": [
        { "StringMatch": { "id": "$vae", "count": 1, "offsets": [1024] } },
        { "StringMatch": { "id": "$wpm", "count": 1, "offsets": [1039] } },
        { "StringMatch": { "id": "$crt", "count": 1, "offsets": [1058] } }
      ],
      "reason": "Condition satisfied with 3 evidence indicator(s)"
    }
  ],
  "scan_duration_ms": 4.12
}
```

---

## Safe Malware Research & Corpus Handling

In accordance with defensive engineering best practices:

1. **No Live Malware in Git:** Live, runnable malware samples must **never** be committed to the repository. The project maintains a cryptographic sample manifest at [`samples/manifest.json`](file:///Users/tryhard/Raya/samples/manifest.json) recording SHA-256 hashes, malware families, and expected rule matches.
2. **Static Scanning Only:** Raya does not execute files. Parsing is strictly passive.
3. **Dedicated Isolation:** External real-world malware corpora should be evaluated inside an isolated, non-networked analysis VM.

---

## Verification & Testing

Execute the test suite across all targets:

```bash
# Run unit and integration tests
cargo test --all-targets

# Run the automated rule verification harness
cargo run -- test tests/fixtures/test_spec.json

# Validate all bundled rules
cargo run -- check rules/ --verbose
```

---

## License

Dual-licensed under either the MIT License or the Apache License (Version 2.0).
