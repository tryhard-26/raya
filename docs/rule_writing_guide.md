# Raya Rule Authoring Guide

Raya uses a domain-specific language (DSL) inspired by YARA, while offering enhanced capabilities for binary structure analysis, instruction disassembly, cryptographic constant identification, runtime introspection, and evidence tracing.

---

## 1. Rule Structure

A standard Raya rule consists of three blocks:
1. `meta`: Key-value attributes for categorization, authorship, severity, and MITRE ATT&CK mapping.
2. `strings`: Text, hex, or regex patterns to locate within the target binary.
3. `condition`: Boolean expression utilizing Pratt parsing to evaluate string matches, binary metadata, and disassembly heuristics.

```raya
rule sample_detection_rule : tag1 tag2 {
    meta:
        author = "Analyst Name"
        description = "Detects suspicious execution patterns"
        severity = "high"
        technique = "T1055.002"
        reference = "https://attack.mitre.org/techniques/T1055/002/"

    strings:
        $text_pattern = "CreateRemoteThread" ascii wide
        $hex_pattern  = { 6A 40 68 00 10 00 00 FF D2 }
        $regex_pattern = /powershell(\.exe)?\s+(-enc|-e)\s+[A-Za-z0-9+\/=]+/ nocase

    condition:
        ($text_pattern and $hex_pattern) or $regex_pattern
}
```

---

## 2. Meta Section Conventions

The following meta keys are recognized by Raya's reporting and threat scoring engine:

| Key | Type | Description |
| :--- | :--- | :--- |
| `author` | String | Rule author or threat intelligence group. |
| `description`| String | Human-readable explanation of what the rule detects. |
| `severity` | String | `info`, `low`, `medium`, `high`, `critical`. |
| `technique` | String | MITRE ATT&CK technique identifier (e.g. `T1486`, `T1055.002`). |
| `reference` | String | External URL for documentation or threat report. |

---

## 3. String Patterns

### Text Strings
Text strings support modifiers:
* `ascii`: Matches 1-byte ASCII characters (default).
* `wide`: Matches 2-byte UTF-16LE characters (`"cmd"` -> `c\0m\0d\0`).
* `nocase`: Case-insensitive matching.
* `fullword`: Matches on word boundaries (delimiters like whitespace, punctuation, null bytes).
* `xor`: Generates XOR-encoded variations across keys 0x01–0xFF.

```raya
strings:
    $cmd = "cmd.exe" ascii wide nocase fullword
```

### Hex Byte Sequences
Raya supports full hex pattern expressions:
* Exact bytes: `4D 5A 90 00`
* Wildcard nibbles: `4?`, `?8`, `??`
* Byte jumps: `[4-8]`, `[-16]`, `[8-]`, `[4]`
* Alternations: `( 11 22 | 33 44 | 55 66 )`

```raya
strings:
    $shellcode_stub = { E8 00 00 00 00 58 ( 83 E8 05 | 83 C0 0A ) [2-4] FF ?? }
```

### Regular Expressions
Enclosed in forward slashes `/.../` with optional `nocase` flag:

```raya
strings:
    $b64_eval = /(IEX|Invoke-Expression)\s*\(.*\[System\.Text\.Encoding\]/ nocase
```

---

## 4. Logical Conditions

Raya supports full boolean logic:
* Operators: `and`, `or`, `not`
* Comparisons: `==`, `!=`, `<`, `<=`, `>`, `>=`
* Arithmetic: `+`, `-`, `*`, `/`
* Quantifiers:
  * `any of them`
  * `all of them`
  * `none of them`
  * `2 of ($str1, $str2, $str3)`
  * `3 of ($prefix_*)`
* String counts and offsets:
  * `#a > 3` (string `$a` matched more than 3 times)
  * `@a < 1024` (first match offset of `$a` is within the first 1KB)

---

## 5. Built-In Binary Modules

### PE Module (`pe`)

| Function / Property | Description |
| :--- | :--- |
| `pe.is_pe` | True if the file is a valid PE32 or PE32+ executable. |
| `pe.is_dll` | True if the binary has the DLL characteristic flag set. |
| `pe.number_of_sections` | Total number of PE sections. |
| `pe.number_of_imports` | Total number of imported API functions. |
| `pe.has_rwx` | True if any section has Read, Write, and Execute permissions. |
| `pe.has_tls` | True if the binary defines a Thread Local Storage (TLS) directory. |
| `pe.tls_callbacks` | Array of registered TLS callback function addresses. |
| `pe.imphash` | Calculated import hash string. |
| `pe.exphash` | Calculated export hash string. |
| `pe.import("dll", "func")` | True if the PE imports the specified API. |
| `pe.export("func")` | True if the PE exports the specified symbol. |
| `pe.has_section(".name")` | True if the section exists in the section table. |
| `pe.section_entropy(".text")`| Shannon entropy of the named section (0.0–8.0). |
| `pe.api_call_arg("API", val)`| True if the API is called with the specified argument constant. |
| `pe.in_basic_block(seq...)`| True if instruction mnemonics occur within the same basic block. |
| `pe.in_function(seq...)` | True if instruction mnemonics occur within the same function. |
| `pe.has_stack_string` | True if any stack strings were extracted from executable sections. |
| `pe.stack_string("str")` | True if a specific string was deobfuscated from stack frame writes. |
| `pe.stack_strings_count` | Number of deobfuscated stack strings found. |
| `pe.has_rich_header` | True if the binary contains a Microsoft PE Rich header. |
| `pe.rich_checksum_mismatch` | True if the Rich header checksum does NOT match the XOR key (forgery). |
| `pe.is_rich_checksum_valid` | True if the Rich header checksum successfully validates against the XOR key. |
| `pe.rich_comp_id(id)` | True if the Rich header contains the specified compiler component ID. |
| `pe.rich_product_id(id)` | True if the Rich header contains the specified product/build ID. |

### .NET / CLR Module (`dotnet`)

| Function / Property | Description |
| :--- | :--- |
| `dotnet.is_dotnet` | True if the binary contains a valid CLI runtime header (Data Directory 14). |
| `dotnet.user_string("str")` | True if `#US` user strings stream contains the specified string. |
| `dotnet.has_type("name")` | True if `#Strings` stream defines the specified Type name. |
| `dotnet.has_method("name")` | True if `#Strings` stream defines the specified Method name. |
| `dotnet.assembly_name` | Assembly name extracted from metadata. |
| `dotnet.clr_version` | CLR runtime version string (e.g. `v4.0.30319`). |

### Cryptographic Constants Module (`crypto`)

| Function / Property | Description |
| :--- | :--- |
| `crypto.has("algorithm")` | True if constants for algorithm (`AES`, `ChaCha20`, `MD5`, `SHA-256`, `CRC32`, `SM4`) are found. |
| `crypto.constants_count` | Total count of detected cryptographic primitives and S-boxes. |
| `has_crypto` | Global boolean flag; true if any cryptographic primitive constant was found. |

### Go Module (`go`)

| Function / Property | Description |
| :--- | :--- |
| `go.is_go` | True if binary contains Go runtime `.gopclntab` structure. |
| `go.has_function("name")` | True if `.gopclntab` contains the specified function symbol. |
| `go.has_package("name")` | True if any symbol belongs to the specified Go package. |
| `go.version` | Detected Go compiler version string (e.g. `go1.21.0`). |

### Rust Module (`rust`)

| Function / Property | Description |
| :--- | :--- |
| `rust.is_rust` | True if Rust compiler markers or panic handlers are detected. |
| `rust.has_crate("name")` | True if the binary statically links the specified crate (e.g. `reqwest`, `tokio`). |
| `rust.rustc_commit` | Git commit hash of the compiling rustc toolchain. |

### Disassembly Module (`disasm`)

| Function | Description |
| :--- | :--- |
| `disasm.in_basic_block(seq...)` | Checks if instructions co-occur within a single basic block. |
| `disasm.in_function(seq...)` | Checks if instructions occur within a single function boundary. |
| `disasm.has_instruction("syscall")` | Checks if the instruction mnemonic is present in code. |
| `disasm.has_instruction_sequence(seq...)` | Checks for consecutive opcode sequence. |

### ELF Module (`elf`)

| Function / Property | Description |
| :--- | :--- |
| `elf.is_elf` | True if the file is a valid ELF executable. |
| `elf.is_64` | True if ELF is 64-bit (`elf.is_32` for 32-bit). |
| `elf.entry_point` | Virtual address of the entry point. |
| `elf.number_of_sections` | Total section header count. |
| `elf.has_section(".name")` | True if section exists. |
| `elf.has_nx` | True if the stack segment has no execute permission. |
| `elf.import("symbol")` | True if dynamic symbol is imported. |

### Mach-O Module (`macho`)

| Function / Property | Description |
| :--- | :--- |
| `macho.is_macho` | True if file is a Mach-O binary. |
| `macho.is_fat` | True if binary is a Universal / FAT multi-architecture binary. |
| `macho.cpu_type` | CPU architecture type (e.g. x86_64, ARM64). |
| `macho.number_of_commands` | Number of load commands. |
| `macho.number_of_segments` | Number of segments. |
| `macho.section(seg, sec).entropy` | Entropy of the specified Mach-O section. |

### Entropy Module (`entropy`)

| Function | Description |
| :--- | :--- |
| `entropy` | Global Shannon entropy of the file (0.0 to 8.0). |
| `entropy.max_window(size)` | Maximum Shannon entropy across sliding windows. |
| `entropy.max_window_exceeds(size, threshold)` | True if any sliding window exceeds threshold. |
