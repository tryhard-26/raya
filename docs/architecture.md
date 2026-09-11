# Engine Architecture & Internals

Raya is designed from the ground up for high-throughput automated malware triage, memory safety, and deterministic explainability.

---

## 1. High-Level Architectural Flow

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
                      │ Terminal / JSON / ...  │
                      │  SARIF 2.1 / STIX 2.1  │
                      └────────────────────────┘
```

---

## 2. Core Subsystems

### A. Binary Format Parsers (`src/binary/`)
* **Zero-Panic Bounds Checking**: All slice offsets and table pointers validate against file buffer bounds before reading. Truncated or adversarial headers safely return `None` rather than aborting.
* **Format Independent Detection**: Authorized via file header magic bytes (`MZ` + `PE\0\0`, `\x7fELF`, `\xca\xfe\xba\xbe`, `\xcf\xfa\xed\xfe`).
* **PE Deep Inspection**: Parses COFF headers, Optional Headers (PE32/PE32+), Section Tables, Import Address Tables (IAT), Export Tables, Security Directories, Rich Headers, and TLS Directories.
* **Disassembly & Scoping (`iced-x86`)**: Linear disassembly, basic-block partitioning, and function boundary extraction.

### B. In-Memory Archive & Encrypted Drop Engine (`src/archive.rs`)
* Detects standard `.zip` files (PK header `0x04034b50`).
* Inspects nested files without dropping payloads to disk.
* Automatically tests common malware archive passwords (`infected`, `malware`, `password`, `clean`, `1234`) or custom `--password`.
* Zip-bomb safety: Decompression is bounded by a 128MB ceiling.

### C. Pattern Matching & Automata (`src/engine/matcher.rs`)
* Literal text and wide strings are compiled into a unified Aho-Corasick automaton for single-pass multi-pattern matching.
* Hex strings with nibble wildcards and jumps utilize byte-oriented regular expression automata.
* String locations and counts are recorded with exact byte offsets.

### D. Expression Evaluator & Pratt Parser (`src/engine/evaluator.rs`, `src/parser/`)
* Pratt top-down operator precedence parser resolves complex expressions with correct precedence without recursion limits.
* Evaluator records every satisfied condition into a non-empty `MatchedEvidence` graph.

### E. Concurrency & Parallelism (`rayon`)
* Multi-threaded directory traversal uses work-stealing parallelism (`rayon::par_iter()`), scanning tens of thousands of binaries with near-linear scaling across CPU cores.
