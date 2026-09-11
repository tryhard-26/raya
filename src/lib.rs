//! # Raya: High-Performance Malware Detection & Binary Triage Engine
//!
//! Raya is a fast, memory-safe malware detection and binary pattern-matching engine
//! written in pure Rust. It is engineered for security operations center (SOC) triage,
//! incident response pipelines, automated sandbox preprocessing, and forensic analysis.
//!
//! ## Architecture Overview
//!
//! Raya integrates pattern compilation, binary introspection, and disassembly into a
//! unified evaluation pipeline:
//!
//! ```text
//!  ┌──────────────────────────┐
//!  │   Raya Rules (.raya)     │
//!  └─────────────┬────────────┘
//!                │
//!                ▼
//!       [ Rule Compiler ] ──────► Aho-Corasick Automata + Regex + AST
//!                │
//!                ▼
//!       [ Scanning Engine ] ◄───► Binary Analysis (PE / ELF / Mach-O / Raw)
//!                │               - Basic-Block Scoped Disassembly
//!                │               - Static API Argument Tracking
//!                ▼
//!     [ ScanContext & Eval ] ───► Zero-Empty-Evidence Matching
//!                │
//!                ▼
//!       [ Output Formats ] ─────► Terminal (Colored) / JSON / SARIF / STIX 2.1
//! ```
//!
//! ## Key Capabilities
//!
//! - **High-Throughput Matching**: Combines multi-string Aho-Corasick matching, PCRE-compatible
//!   regular expressions, and optimized hex wildcards with linear byte scans.
//! - **Deep Binary Introspection**: Native zero-copy parsers for **PE32/PE32+**, **ELF32/ELF64**,
//!   and **Mach-O** (Fat and Thin binaries), exposing imports, exports, section entropy, and RWX flags.
//! - **Basic-Block Scoping & Argument Tracking**: Disassembles x86/x64 instruction streams with
//!   [`iced-x86`](https://docs.rs/iced-x86), tracking static API call arguments (e.g.
//!   `PAGE_EXECUTE_READWRITE` protection flags on allocation primitives) within basic blocks.
//! - **In-Memory Archive Inspection**: Extracts and recursively scans password-protected and
//!   AES-encrypted ZIP/archive drops entirely in memory without writing decrypted payloads to disk.
//! - **Zero-Empty-Evidence Guarantee**: Every detection records concrete evidence (exact file
//!   offsets, matching byte sequences, disassembly addresses, or offending section headers).
//! - **Enterprise Reporting**: Native serialization to **OASIS SARIF v2.1.0** (GitHub Advanced
//!   Security compatible) and **OASIS STIX 2.1** indicator bundles.
//!
//! ## Quick Start
//!
//! ```rust
//! use raya::prelude::*;
//!
//! // 1. Define a detection rule using the Raya DSL
//! let rule_source = r#"
//!     rule suspicious_dropper : windows execution {
//!         meta:
//!             description = "Detects interactive command execution"
//!             severity = "high"
//!         strings:
//!             $cmd = "cmd.exe /c powershell" ascii nocase
//!         condition:
//!             $cmd
//!     }
//! "#;
//!
//! // 2. Parse rules into an Abstract Syntax Tree (AST)
//! let rules = parse_rules_from_str(rule_source).expect("Valid rule syntax");
//!
//! // 3. Compile rules into an optimized scanning engine
//! let engine = Engine::compile_rules(rules).expect("Engine compilation succeeds");
//!
//! // 4. Scan in-memory bytes
//! let sample_payload = b"Executing dropper: cmd.exe /c powershell -ExecutionPolicy Bypass";
//! let result = engine.scan_bytes(sample_payload, "sample.bin");
//!
//! // 5. Inspect matches and evidence
//! assert_eq!(result.matches.len(), 1);
//! assert_eq!(result.matches[0].rule, "suspicious_dropper");
//! assert_eq!(result.matches[0].severity, Severity::High);
//! ```
//!
//! ## Submodules
//!
//! | Module | Purpose |
//! |---|---|
//! | [`engine`] | Core compilation, multi-pattern search, execution context, and rule evaluation. |
//! | [`ast`] | Abstract Syntax Tree definitions for rules, patterns, expressions, and metadata. |
//! | [`parser`] | High-speed lexer and recursive descent parser for Raya and YARA rules. |
//! | [`binary`] | Executable format parsing (PE, ELF, Mach-O), disassembly, and argument tracking. |
//! | [`archive`] | In-memory decompression and AES/ZipCrypto decryption for triage drops. |
//! | [`report`] | Match evidence structures, terminal formatters, SARIF, and STIX 2.1 generators. |
//! | [`entropy`] | Shannon entropy calculation and sliding-window packing detection. |
//! | [`hash`] | Cryptographic (MD5, SHA1, SHA256) and fuzzy (SSDEEP) hashing. |
//! | [`test_runner`] | Automated test suite verification ensuring zero false positives/negatives. |

pub mod archive;
pub mod ast;
pub mod binary;
pub mod cli;
pub mod engine;
pub mod entropy;
pub mod hash;
pub mod parser;
pub mod report;
pub mod test_runner;

/// Convenient re-exports of common Raya types and functions.
///
/// ```rust
/// use raya::prelude::*;
/// ```
pub mod prelude {
    pub use crate::ast::{Rule, Severity};
    pub use crate::engine::{Engine, MatchedEvidence, ScanContext};
    pub use crate::parser::{parse_rules_from_file, parse_rules_from_str};
    pub use crate::report::{RuleMatch, ScanResult};
}

// Curated top-level re-exports for the most commonly used types:
pub use ast::{Rule, Severity};
pub use engine::{CompiledRule, Engine, MatchedEvidence, ScanContext};
pub use parser::{parse_rules_from_file, parse_rules_from_str};
pub use report::{RuleMatch, ScanResult};
