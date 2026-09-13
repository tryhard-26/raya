# Advanced Binary Capabilities & Scoping

Raya introduces static binary inspection capabilities designed to bridge the gap between traditional file-level pattern matchers and deep reverse engineering frameworks.

---

## 1. The Scoping Problem

Traditional pattern matching tools evaluate string and byte rules at the whole-file level:

```text
[ File Start ]
  ...
  Instruction: "push 0x40" (in benign function foo())
  ...
  [ 50,000 bytes later ]
  ...
  Instruction: "call edx" (in unrelated UI handler bar())
  ...
[ File End ]
```

A naive rule checking for `push 0x40` AND `call` matches both instructions even though they are in completely separate functions and execute at different times. This produces false positives during automated triage.

---

## 2. Basic-Block & Function Scoping

Raya disassembles executable sections using the high-performance `iced-x86` instruction decoder and partitions the instruction stream into straight-line **basic blocks** and **scoped functions**:

* **Basic Block**: A sequence of instructions with a single entry point and single exit point, terminated by control flow instructions (`jmp`, `jz`, `jnz`, `ret`, `call`, `syscall`).
* **Function**: A sequence of basic blocks bounded by function prologues/entries and function returns (`ret`).

### Rule Syntax: Basic-Block Scoping

```raya
rule scoped_injection_stub {
    condition:
        // Matches ONLY if "push" and "call" occur within the SAME basic block
        pe.in_basic_block("push", "call")
}
```

If a jump or branch occurs between the instructions, Raya's basic-block evaluator will reject the match:

```text
MATCH:
    push 0x40
    call edx

REJECTED (Separated across jump boundary):
    xor eax, eax
    jmp +10
    ... (Target)
    call edx
```

---

## 3. Static API Call Argument Tracking

Security analysts frequently need to know not just whether an API is imported, but how it is called.

For example, calling `VirtualAlloc` with `PAGE_READWRITE` (`0x04`) is common in benign software, while calling it with `PAGE_EXECUTE_READWRITE` (`0x40`) is a primary indicator of process injection, shellcode staging, or unpacking.

### Rule Syntax: API Call Argument Matching

```raya
rule detect_rwx_allocation {
    meta:
        description = "Detects VirtualAlloc prepared with PAGE_EXECUTE_READWRITE"
        severity = "critical"
        technique = "T1055.002"

    condition:
        pe.is_pe and (
            pe.api_call_arg("VirtualAlloc", 0x40)
            or pe.api_call_arg("VirtualProtect", 0x40)
            or pe.api_call_arg("VirtualAllocEx", 0x40)
        )
}
```

### Supported API Arguments & Constants

Raya maps standard security-sensitive Windows API constants:

| Target API Family | Constant Value | Constant Name | Parameter Name |
| :--- | :--- | :--- | :--- |
| `VirtualAlloc`, `VirtualProtect` | `0x40` (64) | `PAGE_EXECUTE_READWRITE` | `flProtect` |
| `VirtualAlloc`, `VirtualProtect` | `0x20` (32) | `PAGE_EXECUTE_READ` | `flProtect` |
| `VirtualAlloc`, `VirtualProtect` | `0x10` (16) | `PAGE_EXECUTE` | `flProtect` |
| `VirtualAlloc` | `0x1000` (4096) | `MEM_COMMIT` | `flAllocationType` |
| `VirtualAlloc` | `0x2000` (8192) | `MEM_RESERVE` | `flAllocationType` |
| `VirtualFree` | `0x8000` (32768) | `MEM_RELEASE` | `dwFreeType` |
| `OpenProcess`, `DuplicateHandle` | `0x001F0FFF` | `PROCESS_ALL_ACCESS` | `dwDesiredAccess` |
| `OpenProcess` | `0x0020` (32) | `PROCESS_VM_WRITE` | `dwDesiredAccess` |
| `OpenProcess` | `0x0010` (16) | `PROCESS_VM_READ` | `dwDesiredAccess` |
| `CreateProcessW`, `CreateProcessA` | `0x04` (4) | `CREATE_SUSPENDED` | `dwCreationFlags` |

### Forensic Evidence Output

When an API call argument matches, Raya records the exact Virtual Address (VA) and constant name in the evidence trace:

```text
[CRITICAL] advanced_memory_tampering (windows, injection, evasion)
  ATT&CK:      T1055.002
  Evidence:
    API Call Argument: VirtualAlloc!flProtect = 0x40 (PAGE_EXECUTE_READWRITE) at VA 0x140003785
  Verdict Reason: Condition satisfied with 1 evidence indicator(s)
```

---

## 4. Automated Stack String Deobfuscation

Malware authors frequently evade static string detection by assembling strings at runtime onto the stack frame using immediate memory instructions:

```asm
mov byte ptr [rbp - 0x20], 0x63 ; 'c'
mov byte ptr [rbp - 0x1F], 0x6D ; 'm'
mov byte ptr [rbp - 0x1E], 0x64 ; 'd'
mov byte ptr [rbp - 0x1D], 0x2E ; '.'
mov byte ptr [rbp - 0x1C], 0x65 ; 'e'
mov byte ptr [rbp - 0x1B], 0x78 ; 'x'
mov byte ptr [rbp - 0x1A], 0x65 ; 'e'
```

### Raya Stack String Engine

Raya's instruction disassembly engine tracks:
* Destination base registers (`ebp`, `rbp`, `esp`, `rsp`)
* Memory displacement offsets with signed arithmetic for 32-bit and 64-bit frames
* Byte, word, dword, and qword immediate writes
* Sequential contiguous memory layout reconstruction

It automatically extracts both **ASCII** and **UTF-16LE** stack strings without requiring emulation or dynamic sandbox execution.

### Rule Syntax: Stack Strings

```raya
rule detect_stack_string_c2 {
    meta:
        description = "Detects hidden stack-constructed command line"
        severity = "high"

    condition:
        pe.is_pe and (
            pe.has_stack_string
            and pe.stack_string("cmd.exe")
        )
}
```

---

## 5. Cryptographic Constant & S-Box Detection

Raya embeds an optimized multi-pattern scanner for identifying cryptographic primitives, substitution boxes (S-boxes), and initialization vectors compiled into binaries:

* **AES**: Rijndael forward S-box (`0x63, 0x7C, 0x77...`) and inverse S-box (`0x52, 0x09, 0x6A...`)
* **ChaCha20 / Salsa20**: Constant sigma string (`"expand 32-byte k"`)
* **MD5**: Initialization vector constants in little-endian and big-endian representations
* **SHA-256**: Initial hash value constants ($H_0$ through $H_7$)
* **CRC32**: IEEE 802.3 polynomial table lookup constants
* **SM4**: Chinese national standard block cipher S-box

### Rule Syntax: Crypto Constants

```raya
rule detect_embedded_aes_crypto {
    meta:
        description = "Identifies embedded AES encryption tables indicative of ransomware"
        severity = "medium"

    condition:
        crypto.has("AES") or crypto.has("ChaCha20")
}
```

---

## 6. Microsoft PE Rich Header Integrity & Forensics

The Microsoft PE Rich header contains metadata documenting the exact compiler and linker toolchain versions used to generate the executable.

Threat actors attempting to masquerade as legitimate Microsoft binaries frequently tamper with or hand-craft the Rich header. Raya verifies the mathematical integrity of the Rich header checksum:

$$\text{Checksum} = e\_lfanew + \sum \text{rotl}(DOS[i], i \pmod{32}) + \sum \text{rotl}(ProdID \mid CompID, Count \pmod{32})$$

If the computed checksum does not equal the XOR key stored at the `"Rich"` marker, Raya flags a **Rich Header Checksum Mismatch** (suspected forgery).

### Rule Syntax: Rich Header Anomaly

```raya
rule detect_rich_header_forgery {
    meta:
        description = "Detects PE files with forged or corrupted Rich headers"
        severity = "high"
        technique = "T1027"

    condition:
        pe.is_pe and pe.has_rich_header and pe.rich_checksum_mismatch
}
```

---

## 7. Modern Runtime Introspection

Adversaries increasingly develop implants using modern managed and compiled languages (.NET, Go, Rust). Raya provides dedicated introspection modules for each runtime.

### .NET / CLR Introspection (`dotnet.*`)

Parses the CLI Header (Data Directory index 14), the BSJB metadata root, and metadata streams:

* `dotnet.is_dotnet`: Returns `true` if binary contains a valid CLR header.
* `dotnet.user_string(s)`: Searches the `#US` user strings stream for exact or substring matches (e.g. C2 URLs, embedded scripts).
* `dotnet.has_type(name)`: Checks if a specific TypeDef or TypeRef name is defined in `#Strings`.
* `dotnet.has_method(name)`: Checks if a specific MethodDef name is defined.
* `dotnet.assembly_name`: Extracts the assembly name.
* `dotnet.clr_version`: Extracts the runtime version (e.g. `v4.0.30319`).

```raya
rule detect_dotnet_infostealer {
    condition:
        dotnet.is_dotnet and (
            dotnet.user_string("discord.com/api/webhooks")
            or dotnet.has_type("StealerConfig")
        )
}
```

### Go Introspection (`go.*`)

Parses the Go `.gopclntab` (PC-Line table) symbol structure across Go 1.2 through Go 1.20+:

* `go.is_go`: Returns `true` if `.gopclntab` magic header is detected.
* `go.version`: Returns the Go compiler version string (e.g. `go1.21.0`).
* `go.has_function(name)`: Checks for a function symbol in the pclntab table.
* `go.has_package(name)`: Checks if any symbol belongs to the specified package namespace.

```raya
rule detect_golang_implant {
    condition:
        go.is_go and (
            go.has_package("main")
            and go.has_function("executeShellcode")
        )
}
```

### Rust Introspection (`rust.*`)

Detects compiled Rust binaries, extracts the rustc toolchain commit, and demangles statically linked crates:

* `rust.is_rust`: Evaluates to `true` if Rust runtime indicators or panic handlers are present.
* `rust.rustc_commit`: Returns the 40-character Git commit hash of the compiling rustc toolchain.
* `rust.has_crate(name)`: Checks if the binary statically links a specific crate (e.g. `reqwest`, `winapi`).

```raya
rule detect_rust_ransomware {
    condition:
        rust.is_rust and rust.has_crate("aes_gcm")
}
```

---

## 8. Control Flow Graph (CFG) & Cyclomatic Complexity (`cfg.*`)

Raya 2.0 constructs a basic-block directed control flow graph from disassembled instructions, discovering execution paths and control flow anomalies:

* `cfg.has_loop`: Evaluates to `true` if one or more natural back-edge loops are detected.
* `cfg.loop_count`: Returns the number of natural loops discovered via dominator tree analysis.
* `cfg.cyclomatic_complexity`: Calculates McCabe's Cyclomatic Complexity:
  $$M = E - V + 2P$$
* `cfg.is_flattened`: Flags Control Flow Flattening (CFF) obfuscation (e.g. OLLVM dispatcher / switch state machine).
* `cfg.blocks_count`: Total number of basic blocks in the CFG.
* `cfg.edges_count`: Total number of directed edges in the CFG.

```raya
rule detect_obfuscated_cff {
    meta:
        description = "Detects control flow flattening and extreme complexity"
        severity = "high"
    condition:
        cfg.is_flattened or cfg.cyclomatic_complexity > 500
}
```

---

## 9. Direct & Indirect Syscall Evasion Hunter (`syscall.*`)

Modern malware evades userland EDR API hooks by invoking native Windows kernel transitions directly (`syscall`, `sysenter`, `int 0x2e`) or jumping to indirect syscall trampolines:

* `pe.has_direct_syscall` / `disasm.has_direct_syscall`: Flags direct syscall instructions present in code sections.
* `pe.has_indirect_syscall` / `disasm.has_indirect_syscall`: Flags indirect syscall trampolines (`mov r10, rcx; mov eax, SSN; jmp qword ptr [ntdll_trampoline]`).

Raya's disassembler decodes the SSN (System Service Number) and resolves it to its associated Windows Native API (e.g. `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`).

```raya
rule detect_edr_syscall_evasion {
    meta:
        description = "Detects direct and indirect syscall execution stubs"
        severity = "critical"
        technique = "T1562.001"
    condition:
        pe.is_pe and (pe.has_direct_syscall or pe.has_indirect_syscall)
}
```

---

## 10. Micro-Emulation & Automated API Hash Resolver (`api_hash.*`)

Adversaries dynamically resolve API addresses using hashing algorithms to avoid populating the PE Import Address Table (IAT):

* `pe.has_api_hash`: Evaluates to `true` if any known API hash is detected in instruction immediate values or raw memory.
* `pe.api_hash("algorithm", "ApiName")`: Evaluates to `true` if a specific algorithm hash matches the requested API (supports `ROR13`, `DJB2`, `DJB2a`).

Raya includes a built-in precomputed hash table covering the top 60 Windows native and userland APIs frequently abused by threat actors.

```raya
rule detect_api_hashing_loader {
    meta:
        description = "Identifies ROR13 API hashing for virtual memory allocation"
        severity = "critical"
        technique = "T1027.007"
    condition:
        pe.is_pe and (
            pe.api_hash("ror13", "NtAllocateVirtualMemory")
            or pe.api_hash("djb2", "VirtualAlloc")
        )
}
```

---

## 11. Authenticode PKCS#7 Forensics & Signature Overlay Auditing

Raya inspects PE digital signatures via the `IMAGE_DIRECTORY_ENTRY_SECURITY` descriptor:

* `pe.has_signature_overlay`: Detects malicious overlays or data appended after the cryptographic signature boundaries.
* `pe.overlay_size`: Returns the size in bytes of the detected overlay.
* `pe.is_self_signed`: Identifies certificates where Subject Common Name equals Issuer Common Name, flagging unverified self-signed binaries.

```raya
rule detect_signature_overlay_tampering {
    meta:
        description = "Detects PE files with suspicious signature overlay appendages"
        severity = "high"
        technique = "T1553.002"
    condition:
        pe.is_pe and pe.has_signature_overlay and pe.overlay_size > 1024
}
```

---

## 12. Multi-Platform Security Hardening (Mach-O & ELF)

### Mach-O Entitlements (`macho.*`)
* `macho.has_entitlement(name)`: Checks for the existence of an entitlement in embedded XML plists.
* `macho.has_dangerous_entitlement`: Evaluates to `true` if high-risk entitlements are detected (`get-task-allow`, `disable-library-validation`, `allow-unsigned-executable-memory`, `allow-dyld-environment-variables`).

### ELF Compiler Mitigations (`elf.*`)
* `elf.has_nx`: Non-executable stack protection (`PT_GNU_STACK` permissions).
* `elf.has_canary`: Stack smashing protector (`__stack_chk_fail` symbol).
* `elf.relro`: Relocation Read-Only hardening level (`"None"`, `"Partial"`, `"Full"`).
* `elf.is_pie`: Position Independent Executable status.

```raya
rule detect_vulnerable_elf_binary {
    condition:
        elf.is_elf and not elf.has_nx and elf.relro == "None"
}
```
