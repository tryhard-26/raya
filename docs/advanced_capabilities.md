# Advanced Binary Capabilities & Scoping

Raya introduces static binary inspection capabilities designed to bridge the gap between traditional file-level pattern matchers and deep reverse engineering frameworks.

---

## 1. The Scoping Problem

Traditional pattern matching tools evaluate string and byte rules at the **whole-file level**:

```
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

A naive rule checking for `push 0x40` AND `call` matches both instructions even though they are in completely separate functions and execute at different times. This produces **false positives** during automated triage.

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
✓ MATCH:
    push 0x40
    call edx

✗ REJECTED (Separated across jump boundary):
    xor eax, eax
    jmp +10
    ... (Target)
    call edx
```

---

## 3. Static API Call Argument Tracking

Security analysts frequently need to know not just *whether* an API is imported, but *how* it is called.

For example, calling `VirtualAlloc` with `PAGE_READWRITE` (0x04) is common in benign software, while calling it with `PAGE_EXECUTE_READWRITE` (0x40) is a primary indicator of process injection, shellcode staging, or unpacking.

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
    ✓ API Call Argument: VirtualAlloc!flProtect = 0x40 (PAGE_EXECUTE_READWRITE) at VA 0x140003785
  Verdict Reason: Condition satisfied with 1 evidence indicator(s)
```
