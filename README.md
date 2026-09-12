# Raya

Rust-native binary pattern matching, static triage, and forensic analysis engine.

[![Crates.io](https://img.shields.io/crates/v/raya.svg)](https://crates.io/crates/raya)
[![Documentation](https://docs.rs/raya/badge.svg)](https://docs.rs/raya)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/tryhard-26/raya/actions/workflows/ci.yml/badge.svg)](https://github.com/tryhard-26/raya/actions)

Raya is an industrial-grade static analysis, pattern-matching, and binary triage engine implemented in pure Rust. It combines a unified Aho-Corasick multi-string automaton, PCRE-compatible regular expressions, x86/x64 instruction disassembly via `iced-x86`, and zero-copy parsers for PE, ELF, and Mach-O executables.

The engine is engineered for security operations pipelines, automated artifact triage, incident response, and binary reverse engineering. Every detection produces concrete, structured evidence containing exact byte offsets, imported APIs, disassembled instructions, static arguments, and section characteristics.

---

## Quick Start

### Installation

Install via Cargo:

```bash
cargo install raya
```

Or compile from source:

```bash
git clone https://github.com/tryhard-26/raya.git
cd raya
cargo build --release
# The compiled executable is at target/release/raya
```

### Basic Commands

#### 1. Scan a Target Binary or Directory

Scan an artifact or directory against detection rules:

```bash
raya scan samples/malware/dropper.exe --rules rules/
```

#### 2. Deep Forensic Inspection Dashboard

Inspect file hashes (MD5, SHA-1, SHA-256, SSDEEP, Imphash, RichPV, Exphash), entropy heatmaps, section permissions, embedded crypto S-boxes, stack strings, and runtime metadata:

```bash
# Terminal visual triage report
raya inspect samples/malware/dropper.exe

# Structured JSON for automated ingestion
raya inspect samples/malware/dropper.exe --json
```

#### 3. Transpile Legacy YARA Signatures

Convert existing YARA rules (`.yar` / `.yara`) into native Raya rules (`.raya`):

```bash
raya convert signatures.yar -o rules/transpiled.raya
```

#### 4. Validate Rule Syntax

Verify rule parsing, AST construction, and pattern compilation:

```bash
raya check rules/ --verbose
```

---

## Command-Line Interface

### Usage

```text
raya [OPTIONS] <COMMAND>
```

### Subcommands

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `scan` | `<TARGET> --rules <PATH>` | Scans files, directories, stdin (`-`), or process memory (`--pid`). |
| `inspect` | `<TARGET> [--json]` | Interactive forensic inspection dashboard (hashes, entropy, headers, crypto, strings, runtimes). |
| `convert` | `<INPUT.yar> -o <OUTPUT.raya>` | Transpiles legacy YARA rules into native Raya detection rules. |
| `check` | `<RULES_PATH>` | Validates rule syntax, AST construction, and pattern compilation. |
| `compile` | `<RULES_PATH> -o <OUTPUT>` | Compiles text rules into a serialized binary cache for rapid loading. |
| `test` | `<SPEC_PATH>` | Runs automated rule verification against test fixture specifications. |
| `bench` | `--rules <PATH>` | Measures pattern-matching throughput and scan duration across samples. |

### Scan Options

```text
Arguments:
  <TARGET>                   File, directory, or '-' for standard input

Options:
  -r, --rules <PATH>         Path to a .raya rule file or directory containing rules [default: rules/]
  -f, --format <FORMAT>      Output format: terminal, json, sarif, stix [default: terminal]
  -o, --output <FILE>        Write output to file instead of stdout
  -c, --compiled <FILE>      Load pre-compiled binary rules
  -p, --password <PWD>       Password for encrypted archives (default list tried automatically)
      --pid <PID>            Scan process virtual memory (Linux/macOS)
      --all                  Scan all files without skipping known benign extensions
      --max-size <BYTES>     Skip files exceeding size limit (default: 100MB)
      --workers <NUM>        Thread pool size for directory scans [default: logical cores]
  -v, --verbose              Enable detailed debug logging
  -h, --help                 Print help information
```

### Exit Codes

* `0`: Scan completed successfully; no rules matched (clean).
* `1`: Scan completed successfully; one or more rules matched (detection).
* `2`: Execution error encountered (e.g. invalid arguments, unreadable path, malformed rule).

---

## Core Capabilities

### 1. In-Memory Encrypted Archive Triage
Raya identifies encrypted archive drops (ZipCrypto and WinZip AES-256) and brute-forces standard malware passwords (`infected`, `malware`, `password`, `clean`, `1234`) or user-supplied passwords entirely in RAM, inspecting nested payloads without disk I/O.

### 2. Zero-Empty-Evidence Guarantee
Traditional pattern matchers often report only a triggered rule name. Raya records structured evidence graphs for every match: exact byte offsets, imported APIs, exported symbols, entropy spikes, disassembled instruction addresses, and static call arguments.

### 3. Basic-Block & Function Scoping
Linear disassembly via `iced-x86` partitions instruction streams into strict basic blocks. The `pe.in_basic_block` heuristic verifies that instructions co-occur within the same straight-line block without crossing control flow or jump boundaries, eliminating file-level false positives.

### 4. Static API Call Argument Tracking
Analyzes instruction sequences preceding imported API invocations to track static parameter values. Detects dangerous constants passed to critical primitives, such as `PAGE_EXECUTE_READWRITE` (`0x40`) passed to `VirtualAlloc` or `VirtualProtect`.

### 5. Automated Stack String Deobfuscation
Tracks sequential immediate writes to stack frames (`mov [rbp - disp], imm`), sign-extends frame offsets, and reconstructs hidden ASCII and UTF-16LE strings without requiring dynamic emulation.

### 6. Cryptographic Constant & S-Box Identification
Multi-pattern scanner detecting compiled cryptographic primitives:
* AES forward and inverse S-boxes
* ChaCha20 / Salsa20 constants (`"expand 32-byte k"`)
* MD5 initialization vector constants (little and big-endian)
* SHA-256 initial hash values ($H_0$ through $H_7$)
* CRC32 IEEE 802.3 lookup table constants
* SM4 block cipher S-box

### 7. Microsoft PE Rich Header Forensics
Calculates the authentic Microsoft Rich header checksum from the DOS stub and compiler record entries. Identifies header tampering, forged build environments, or corrupted toolchains via `pe.rich_checksum_mismatch`.

### 8. Modern Runtime Introspection
* **.NET / CLR**: Parses BSJB metadata roots, `#US` user strings (C2 URLs, Base64 configs), type names, and method definitions via `dotnet.*`.
* **Go**: Parses `.gopclntab` structures, extracting compiler versions and package/function symbols via `go.*`.
* **Rust**: Identifies rustc commit hashes and statically linked crates (e.g. `reqwest`, `tokio`) via `rust.*`.

### 9. Zero-Copy Executable Parsers
High-throughput parsing of PE32/PE32+, ELF32/ELF64, and Mach-O (32-bit, 64-bit, and Universal FAT) binaries, extracting headers, section tables, entropy, import/export tables, TLS callbacks, and permission bitmasks (e.g. RWX).

### 10. Standards-Compliant Reporting
Native export to **OASIS SARIF v2.1.0** (GitHub Advanced Security compatible) and **OASIS STIX 2.1** Threat Intelligence indicator bundles.

---

## Rule Specification & DSL

Raya rules use a declarative domain-specific language (DSL) compatible with standard signature conventions.

### Structure

```raya
rule <identifier> : <tag1> <tag2> {
    meta:
        author = "<author>"
        description = "<description>"
        severity = "<info|low|medium|high|critical>"
        technique = "<MITRE_ATTACK_ID>"

    strings:
        $<id> = "<string>" [modifiers]
        $<id> = { <hex_tokens> }
        $<id> = /<regex>/ [modifiers]

    condition:
        <boolean_expression>
}
```

### String Modifiers

* `ascii`: Matches 8-bit ASCII characters (default).
* `wide`: Matches 16-bit little-endian UTF-16 characters.
* `nocase`: Case-insensitive comparison.
* `fullword`: Requires word boundaries around the match.
* `xor(min, max)`: Matches single-byte XOR transformations across specified keys.

### Hex Patterns

Hex patterns support byte literals, wildcard nibbles, jumps, and alternations:

```raya
$hex_stub = { 55 89 e5 [2-4] 83 ec ?? ( c3 | c9 c3 ) }
```

### Introspection Namespaces

* **PE (`pe.*`)**: `pe.is_pe`, `pe.is_dll`, `pe.imphash`, `pe.exphash`, `pe.has_rwx`, `pe.has_tls`, `pe.import("dll", "func")`, `pe.export("func")`, `pe.section(".text").entropy`, `pe.api_call_arg("API", 0x40)`, `pe.in_basic_block("push", "call")`, `pe.has_stack_string`, `pe.stack_string("str")`, `pe.has_rich_header`, `pe.rich_checksum_mismatch`.
* **.NET (`dotnet.*`)**: `dotnet.is_dotnet`, `dotnet.user_string("str")`, `dotnet.has_type("name")`, `dotnet.has_method("name")`, `dotnet.assembly_name`, `dotnet.clr_version`.
* **Crypto (`crypto.*`)**: `crypto.has("AES")`, `crypto.has("ChaCha20")`, `crypto.has("SHA-256")`, `crypto.constants_count`, `has_crypto`.
* **Go (`go.*`)**: `go.is_go`, `go.has_function("name")`, `go.has_package("name")`, `go.version`.
* **Rust (`rust.*`)**: `rust.is_rust`, `rust.has_crate("name")`, `rust.rustc_commit`.
* **ELF (`elf.*`)**: `elf.is_elf`, `elf.is_64`, `elf.has_nx`, `elf.import("symbol")`, `elf.section(".name").entropy`.
* **Mach-O (`macho.*`)**: `macho.is_macho`, `macho.is_fat`, `macho.cpu_type`, `macho.section(seg, sec).entropy`.

---

## Practical Examples

### 1. In-Memory Archive Drop Triage

Raya identifies encrypted archive drops, attempts extraction in memory using built-in passwords, and scans inner payloads without touching disk:

```bash
raya scan samples/malware/drop.zip --rules rules/
```

```text
Target:       samples/malware/drop.zip -> payload.exe
Size:         3514368 bytes
Type:         PE32
SHA256:       ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
IMPHASH:      68f013d7437aa653a8a98a05807afeb1
Entropy:      8.00 / 8.0
Threat Level: [MALICIOUS] (Score: 85/100)
ATT&CK Chain: Impact (Ransomware)

MATCHES (1 rule(s) triggered):

[CRITICAL] ransomware_wannacry (windows, ransomware)
  Description: Detects WannaCry ransomware artifacts and execution commands
  ATT&CK:      T1486
  Evidence:
    Pattern $tasksche (1 hit(s) at [0xf4d8])
    Pattern $icacls (1 hit(s) at [0xf4fc])
  Verdict Reason: Condition satisfied with 2 evidence indicator(s)
```

### 2. Static API Call Argument Tracking

Detect memory allocation primitives configured with executable permissions:

```raya
rule detect_rwx_allocation {
    meta:
        description = "Detects memory allocation with PAGE_EXECUTE_READWRITE"
        severity = "critical"
        technique = "T1055.002"

    condition:
        pe.is_pe and (
            pe.api_call_arg("VirtualAlloc", 0x40)
            or pe.api_call_arg("VirtualProtect", 0x40)
        )
}
```

Output:

```text
[CRITICAL] detect_rwx_allocation (windows, injection)
  Description: Detects memory allocation with PAGE_EXECUTE_READWRITE
  ATT&CK:      T1055.002
  Evidence:
    API Call Argument: VirtualAlloc!flProtect = 0x40 (PAGE_EXECUTE_READWRITE) at VA 0x140003785
  Verdict Reason: Condition satisfied with 1 evidence indicator(s)
```

### 3. PE Rich Header Integrity Verification

Detect forged or tampered Microsoft build environments:

```raya
rule detect_pe_rich_tampering {
    meta:
        description = "Identifies PE binaries with invalid Rich header checksums"
        severity = "high"
        technique = "T1027"

    condition:
        pe.is_pe and pe.has_rich_header and pe.rich_checksum_mismatch
}
```

### 4. Forensic Triage Dashboard (`raya inspect`)

```bash
raya inspect sample.exe
```

```text
================================================================================
RAYA BINARY INSPECTOR - FORENSIC TRIAGE REPORT: sample.exe
================================================================================
FILE METRICS:
  Size:      5407744 bytes
  Entropy:   6.3195 [████████░░] (NORMAL: Typical code/data)
  Format:    Windows Portable Executable 64-bit (PE32+)

CRYPTOGRAPHIC IDENTIFIERS:
  MD5:       221254977da4eec7b09733b68df6c15e
  SHA-1:     a6cc52298c629a8c1b58087dfc8e640c57b057ed
  SHA-256:   f162b54de2adfc72d78adb1dbada2dedda111ae0a5e2f6e9500f4f909664c5d2
  SSDEEP:    98304:QAwekl0GYEHhHjDPlSom/OK/m9swh0:4m/G0
  Imphash:   bef150eb555d7418b86eeff96306a880
  RichPV:    d01581b8e84b499ddb9d66221bfbb2ef

PORTABLE EXECUTABLE METADATA:
  Entry Point:      0x0033E480
  Image Base:       0x0000000140000000
  Authenticode:     Unsigned
  Rich Header:      Present (CHECKSUM MISMATCH (Suspected Forgery / Header Tampering))
  TLS Callbacks:    1 registered [0x1402D3810]

SECTION TABLE & ENTROPY BAR:
  Section      VirtSize    RawSize  Entropy         Heatmap  Flags
  ----------------------------------------------------------------------
  .text         3512336    3512832   6.2428    [████████░░]  R-X
  .rdata        1714760    1715200   5.7135    [███████░░░]  R--
  .data            8736       3584   2.2920    [███░░░░░░░]  RW-
  .pdata         130080     130560   6.3878    [████████░░]  R--
  .rsrc            1808       2048   5.0346    [██████░░░░]  R--
  .reloc          42480      42496   5.4679    [███████░░░]  R--

RUST RUNTIME METADATA:
  rustc Commit:  adf8d168af9334a8bf940824fcf4207d01e05ae5
  Linked Crates: regex
================================================================================
```

---

## Documentation

Comprehensive documentation is available in the [`docs/`](docs/index.md) directory and on [docs.rs/raya](https://docs.rs/raya):

* [Quick Start & Basic Commands](docs/getting_started.md)
* [CLI Reference Manual](docs/cli_reference.md)
* [Rule Authoring Guide](docs/rule_writing_guide.md)
* [Advanced Capabilities & Scoping](docs/advanced_capabilities.md)
* [Threat Scoring & MITRE ATT&CK](docs/threat_scoring.md)
* [Enterprise Integrations (SARIF & STIX)](docs/enterprise_integrations.md)
* [Architecture & Engine Internals](docs/architecture.md)

---

## License

Licensed under the Apache License, Version 2.0 (the "License").
You may obtain a copy of the License at [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0).
