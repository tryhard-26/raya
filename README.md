# Raya

Rust-native binary pattern matching and static triage engine.

[![Crates.io](https://img.shields.io/crates/v/raya.svg)](https://crates.io/crates/raya)
[![Documentation](https://img.shields.io/badge/docs-raya-blue.svg)](docs/index.md)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/tryhard-26/raya/actions/workflows/ci.yml/badge.svg)](https://github.com/tryhard-26/raya/actions)

Raya is a static analysis and binary pattern-matching engine implemented in Rust. It compiles pattern signatures and condition expressions into an Aho-Corasick automaton combined with regular expressions, x86/x64 linear disassembly via `iced-x86`, and executable file parsers for PE, ELF, and Mach-O.

The engine is designed for security operations pipelines, automated artifact triage, and reverse engineering. Detections produce structured evidence containing exact byte offsets, imported symbols, section characteristics, and disassembled instruction arguments.

---

## Technical Overview

* **Multi-Pattern Matching**: Compiles literal strings across all loaded rules into a single-pass Aho-Corasick automaton, executing alongside PCRE-compatible regular expressions and hex byte patterns with wildcard masks.
* **Executable Format Parsers**: Native zero-copy parsing for PE32/PE32+, ELF32/ELF64, and Mach-O (32-bit, 64-bit, and Universal/FAT) binaries. Extracts section headers, entropy, import/export tables, TLS callbacks, and permission flags (e.g. RWX).
* **Basic-Block Instruction Scoping**: Linear disassembly using `iced-x86`. Evaluates instruction sequences within single basic blocks, bounded by branch, jump, and call boundaries.
* **Static API Argument Tracking**: Identifies arguments supplied to imported APIs within basic blocks prior to call instructions (e.g. `PAGE_EXECUTE_READWRITE` / `0x40` passed to memory allocation primitives).
* **In-Memory Archive Extraction**: Decompresses and decrypts ZIP archives (ZipCrypto and AES-256) in memory without writing extracted payloads to disk.
* **Standardized Output**: Native formatting for terminal display, JSON, OASIS SARIF v2.1.0, and OASIS STIX 2.1 threat intelligence bundles.

---

## Installation

### From Crates.io

```bash
cargo install raya
```

### From Source

```bash
git clone https://github.com/tryhard-26/raya.git
cd raya
cargo build --release
```

The compiled binary is located at `target/release/raya`.

---

## Command-Line Interface

### Usage

```text
raya [OPTIONS] <COMMAND>
```

### Commands

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `scan` | `<TARGET> --rules <PATH>` | Scans a file, directory, stdin stream (`-`), or process memory (`--pid`). |
| `check` | `<RULES_PATH>` | Validates rule syntax, AST construction, and pattern compilation. |
| `compile` | `<RULES_PATH> -o <OUTPUT>` | Compiles rules into a serialized binary format for fast loading. |
| `test` | `<SPEC_PATH>` | Runs automated rule verification against test fixture specifications. |
| `bench` | `--rules <PATH>` | Measures pattern-matching throughput and scan duration across samples. |

### Scan Options

```text
Arguments:
  <TARGET>                   File, directory, or '-' for standard input

Options:
  -r, --rules <PATH>         Path to a .raya rule file or directory containing rules
  -f, --format <FORMAT>      Output format: text, json, sarif, stix [default: text]
  -o, --output <FILE>        Write output to file instead of stdout
  -c, --compiled <FILE>      Load pre-compiled binary rules
      --password <PWD>       Password for encrypted archives (default list tried automatically)
      --pid <PID>            Scan process virtual memory (Linux/macOS)
      --max-size <BYTES>     Skip files exceeding size limit
      --workers <NUM>        Thread pool size for directory scans [default: logical cores]
  -v, --verbose              Enable detailed debug logging
  -h, --help                 Print help information
```

### Exit Codes

* `0`: Scan completed successfully; no rules matched (clean).
* `1`: Scan completed successfully; one or more rules matched (detection).
* `2`: Execution error encountered (e.g. invalid arguments, unreadable path, malformed rule).

---

## Rule Specification

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
* `fullword`: Requires delimiters (non-alphanumeric boundaries) around the match.
* `xor(min, max)`: Matches single-byte XOR transformations across the specified key range.

### Hex Patterns

Hex patterns support byte literals, wildcards, jumps, and alternations:

```raya
$hex_stub = { 55 89 e5 [2-4] 83 ec ?? ( c3 | c9 c3 ) }
```

### Binary Introspection Namespaces

#### PE Introspection (`pe.`)

* `pe.is_pe`: Evaluates to `true` if the target is a valid PE32 or PE32+ binary.
* `pe.imphash`: Returns the MD5 import hash string.
* `pe.exphash`: Returns the MD5 export hash string.
* `pe.has_rwx`: Evaluates to `true` if any PE section possesses Read, Write, and Execute flags.
* `pe.has_tls`: Evaluates to `true` if the binary registers TLS callbacks.
* `pe.import(dll, function)`: Checks for the existence of an imported API.
* `pe.export(function)`: Checks for an exported symbol.
* `pe.section(name).entropy`: Computes Shannon entropy for the specified section.
* `pe.in_basic_block(mnemonic_a, mnemonic_b)`: Verifies instructions appear within the same basic block.
* `pe.api_call_arg(api_name, value)`: Tracks static arguments supplied to the specified API.

#### ELF Introspection (`elf.`)

* `elf.is_elf`: Evaluates to `true` if the target is an ELF32 or ELF64 binary.
* `elf.has_nx`: Evaluates to `true` if the stack segment is marked non-executable.
* `elf.import(symbol)`: Checks for a referenced dynamic symbol.
* `elf.section(name).entropy`: Computes Shannon entropy for the specified section.

#### Mach-O Introspection (`macho.`)

* `macho.is_macho`: Evaluates to `true` if the target is a Mach-O or Universal FAT binary.
* `macho.is_fat`: Evaluates to `true` if the binary contains multi-architecture slices.
* `macho.section(segment, section).entropy`: Computes entropy for the named segment/section.

---

## Examples

### 1. In-Memory Archive Triage

Raya identifies encrypted archive drops, attempts extraction in memory using built-in passwords (`infected`, `malware`, `password`, `clean`, `1234`) or user-supplied credentials, and scans inner payloads without disk I/O:

```bash
raya scan samples/malware/drop.zip --rules rules/ --format text
```

Output:

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
    ✓ Pattern $tasksche (1 hit(s) at [0xf4d8])
    ✓ Pattern $icacls (1 hit(s) at [0xf4fc])
  Verdict Reason: Condition satisfied with 2 evidence indicator(s)
```

### 2. Static API Call Argument Tracking

Rule:

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

Scan execution:

```bash
raya scan sample.exe --rules rules/
```

Output:

```text
MATCHES (1 rule(s) triggered):

[CRITICAL] detect_rwx_allocation (windows, injection)
  Description: Detects memory allocation with PAGE_EXECUTE_READWRITE
  ATT&CK:      T1055.002
  Evidence:
    ✓ API Call Argument: VirtualAlloc!flProtect = 0x40 (PAGE_EXECUTE_READWRITE) at VA 0x140003785
  Verdict Reason: Condition satisfied with 1 evidence indicator(s)
```

### 3. SARIF Export for CI/CD Pipelines

Export static findings directly into SARIF format for ingestion into GitHub Advanced Security:

```bash
raya scan target_directory/ --rules rules/ --format sarif -o results.sarif
```

---

## Performance & Architecture

* **Memory-Mapped I/O**: Files $\ge 16\text{ KB}$ are scanned using `memmap2`, avoiding kernel-to-user buffer copying.
* **Work-Stealing Concurrency**: Multi-file directories are partitioned across CPU cores using `rayon`.
* **Single-Pass String Matching**: Literal string patterns from all active rules are compiled into a unified Aho-Corasick automaton, evaluating in $O(N)$ time with respect to input size.
* **Zero Allocations in Inner Loops**: Parsers operate directly on byte slices without heap reallocation.

---

## Documentation

Full documentation is available in the [`docs/`](docs/index.md) directory:

* [Quick Start Guide](docs/getting_started.md)
* [CLI Reference](docs/cli_reference.md)
* [Rule Writing Guide](docs/rule_writing_guide.md)
* [Advanced Capabilities & Scoping](docs/advanced_capabilities.md)
* [Threat Scoring & MITRE ATT&CK](docs/threat_scoring.md)
* [Enterprise Integrations (SARIF & STIX)](docs/enterprise_integrations.md)
* [Engine Architecture](docs/architecture.md)

---

## License

Licensed under the Apache License, Version 2.0 (the "License").
You may obtain a copy of the License at [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0).
