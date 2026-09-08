# Raya

Raya is a static analysis and binary pattern-matching engine written in Rust. It combines multi-pattern byte search, regular expressions, deep Portable Executable (PE32/PE32+) and Executable and Linkable Format (ELF32/ELF64) header parsing, instruction disassembly (`iced-x86`), and Shannon entropy calculation.

Every match produces a structured evidence trace specifying exact byte offsets, imported APIs, section flags, and entropy metrics.

---

## Technical Architecture

```
                      +------------------------+
                      |        Raya CLI        |
                      | scan | check | test ...|
                      +-----------+------------+
                                  |
           +----------------------+----------------------+
           |                                             |
           v                                             v
+----------------------+                      +----------------------+
|     Rule Parser      |                      |     Target File      |
| Lexer & Pratt Parser |                      |  Format Det. / Hash  |
+----------+-----------+                      +----------+-----------+
           |                                             |
           v                                             v
+----------------------+                      +----------------------+
|    Compiled Rules    |                      | Binary Context (AST) |
| Strings / Conditions |                      |  PE / ELF / Entropy  |
+----------+-----------+                      +----------+-----------+
           |                                             |
           +----------------------+----------------------+
                                  |
                                  v
                      +------------------------+
                      |    Scanning Engine     |
                      |  Aho-Corasick / Regex  |
                      |   Evaluator & Trace    |
                      +-----------+------------+
                                  |
                                  v
                      +------------------------+
                      |    Detection Report    |
                      | Terminal (Ev.) / JSON  |
                      +------------------------+
```

### Design Principles

* **Bounds Safety:** Format parsers (PE, ELF) implement strict bounds checking without relying on unvalidated pointer arithmetic. Malformed or truncated files produce structured error states instead of panicking.
* **Format Detection via Magic Bytes:** File types are identified through header inspection (`MZ` + `PE\0\0` for PE, `\x7fELF` for ELF) regardless of filesystem extension.
* **Automata-Based Matching:** Literal ASCII and wide (UTF-16LE) patterns are searched using an Aho-Corasick automaton in linear time. Wildcard byte sequences and regular expressions are evaluated using byte-oriented regex engines.
* **Thread Concurrency:** Directory recursion evaluates targets in parallel using work-stealing threads (`rayon`).

---

## Building and Installation

### Dependencies

* Rust 1.75+ toolchain

### Build

```bash
cargo build --release
```

The optimized binary is emitted to `target/release/raya`.

### Install Locally

```bash
cargo install --path .
```

---

## Command-Line Interface

### 1. Scanning Files and Directories

```bash
# Scan a single executable
raya scan /path/to/binary.exe --rules rules/

# Recursively scan a directory
raya scan /path/to/samples/ --rules rules/ --recursive

# Emit machine-readable JSON
raya scan /path/to/binary.exe --rules rules/ --json

# Pipeline-friendly output (<path>: <rule>)
raya scan /path/to/samples/ --rules rules/ --quiet

# Filter rules by tag
raya scan /path/to/samples/ --rules rules/ --tag ransomware
```

**Exit Codes:**
* `0`: No matches found (clean)
* `1`: One or more rules matched (detection)
* `2`: Execution error (unreadable file, invalid rules)

### 2. Validating Rules

Verifies syntax, regex validity, and structural integrity:

```bash
raya check rules/
raya check rules/ --verbose
```

### 3. Rule Test Suites

Runs positive and negative test cases from a test manifest:

```bash
raya test tests/fixtures/test_spec.json
```

### 4. Benchmarking

Measures throughput (MB/s), latency per file, and rule compilation time:

```bash
raya bench tests/fixtures/ --rules rules/ --iterations 5
```

---

## Rule Language Specification

Rules consist of `meta`, `strings`, and `condition` sections:

```raya
rule ransomware_wannacry : windows ransomware {
    meta:
        author = "Raya Research Team"
        description = "Detects WannaCry artifacts and execution commands"
        severity = "critical"
        technique = "T1486"

    strings:
        $tasksche = "tasksche.exe" ascii wide nocase
        $icacls   = "icacls . /grant Everyone:F" ascii wide nocase
        $attrib   = "attrib +h ." ascii wide nocase
        $stub     = { 48 89 5C 24 ?? 48 89 ?? ?? 48 83 EC 20 }
        $b64      = /[A-Za-z0-9+\/]{80,}={0,2}/

    condition:
        ($tasksche and ($icacls or $attrib))
        or $stub
        or (pe.is_pe and pe.import("kernel32.dll", "VirtualAllocEx"))
}
```

### String Definition Modifiers

* `ascii`: Matches 8-bit ASCII string.
* `wide`: Matches 16-bit UTF-16LE string.
* `nocase`: Case-insensitive matching.
* Byte patterns: `{ 48 8B ?? ?4 24 }` supports full wildcards (`??`) and nibble wildcards (`4?`, `?4`).
* Regular expressions: `/[A-Za-z0-9]{32}/i`.

### Condition Expressions

* Boolean operators: `and`, `or`, `not`, parentheses `( ... )`.
* Pattern references:
  * `$id`: Pattern matched at least once.
  * `#id`: Number of times pattern matched (e.g. `#id >= 3`).
  * `@id`: Offset in bytes of first match (e.g. `@id < 1024`).
* Quantifiers: `2 of ($a, $b, $c)`, `all of them`, `any of them`, `none of them`.
* Portable Executable (`pe.*`):
  * `pe.is_pe`: Target is a valid PE.
  * `pe.is_pe32_plus`: Target is 64-bit PE32+.
  * `pe.is_dll`: DLL characteristic flag set.
  * `pe.number_of_sections`: Count of sections.
  * `pe.has_rwx`: Section with read, write, and execute flags present.
  * `pe.import(dll, function)`: API import resolution.
  * `pe.export(function)`: Exported symbol resolution.
  * `pe.section(name).entropy`: Section Shannon entropy.
  * `pe.section(name).executable`: Executable section flag.
  * `pe.section(name).writable`: Writable section flag.
  * `pe.has_instruction(mnemonic)`: Disassembles code section to find mnemonic (e.g. `"syscall"`).
  * `pe.has_instruction_sequence("mov", "xor", "call")`: Disassembles code to detect instruction sequence.
* Executable and Linkable Format (`elf.*`):
  * `elf.is_elf`: Target is a valid ELF.
  * `elf.is_64`: 64-bit ELF binary.
  * `elf.is_executable`: ET_EXEC file type.
  * `elf.section(name).executable`: Section execution permission.
* Global attributes: `filesize`, `entropy`.

---

## Empirical Testing and Validation

### 1. Production System Binaries (924 Files in `/usr/bin`)

Scanned 924 native operating system binaries (224.5 MB):
* **Throughput:** 43.01 MB/s
* **Latency:** 5.64 ms per file
* **False-Positive Rate:** 0.0% (0 false positives across all 924 binaries)

### 2. Live Malware Testing (WannaCry)

Tested against the canonical WannaCry ransomware binary (`SHA-256: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa`):

```text
Target: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe
Size:   3514368 bytes
Type:   PE32
SHA256: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
Entropy: 8.00 / 8.0

MATCHES (1 rule(s) triggered):

[CRITICAL] ransomware_wannacry (windows, ransomware)
  Description: Detects WannaCry ransomware artifacts, command execution strings, and drop mechanisms
  ATT&CK:      T1486
  Evidence:
    ✓ Pattern $tasksche (1 hit(s) at [0xf4d8])
    ✓ Pattern $icacls (1 hit(s) at [0xf4fc])
  Verdict Reason: Condition satisfied with 2 evidence indicator(s)
```

### 3. Industry-Standard Verification (EICAR)

Tested against the official EICAR anti-malware test pattern:
* Verified match at offset `0x0` using rule `eicar_standard_test_file`.

---

## Automated Test Suite

```bash
cargo test --all-targets
```

32 unit, integration, CLI, and regression tests passing. Zero compiler or clippy warnings under `-D warnings`.

---

## License

Licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.
