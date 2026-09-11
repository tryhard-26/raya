//! # Scan Evaluation Context & Evidence Model
//!
//! This module defines the evaluation state ([`ScanContext`]) and the structured evidence
//! items ([`MatchedEvidence`]) recorded when rules evaluate to true.

use crate::binary::BinaryAnalysis;
use crate::engine::matcher::StringMatch;
use crate::hash::FileHashes;
use std::collections::HashMap;
use std::path::Path;

/// Specific, concrete evidence indicators captured during rule evaluation.
///
/// In production triage and security operations, alerts must contain verifiable technical
/// facts. Each variant of [`MatchedEvidence`] captures exact file offsets, byte hits,
/// imported symbols, or disassembled instruction arguments.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum MatchedEvidence {
    /// String or hex pattern match with exact byte offsets.
    StringMatch {
        /// The string identifier (e.g. `$cmd`).
        id: String,
        /// Number of times the pattern matched in the sample.
        count: usize,
        /// Concrete byte offsets where the pattern was located.
        offsets: Vec<usize>,
    },
    /// An imported dynamic function from a DLL or shared object.
    PeImport {
        /// Name of the dynamic library (e.g. `kernel32.dll`).
        dll: String,
        /// Name of the imported API function (e.g. `VirtualAlloc`).
        function: String,
    },
    /// An exported function symbol from a library or binary.
    PeExport {
        /// Name of the exported function.
        function: String,
    },
    /// High Shannon entropy detected within a specific binary section.
    PeSectionEntropy {
        /// Name of the section (e.g. `.text` or `.rsrc`).
        section: String,
        /// Calculated Shannon entropy (0.0 - 8.0).
        entropy: f64,
        /// Configured threshold that was exceeded.
        threshold: f64,
    },
    /// A section flag characteristic (e.g. `executable`, `writable`).
    PeSectionFlag {
        /// Target section name.
        section: String,
        /// Name of the matched characteristic or flag.
        flag: String,
    },
    /// A quantifier condition (e.g. `2 of ($a, $b, $c)`).
    Quantifier {
        /// Number of matches required by the condition.
        required: usize,
        /// Number of matches observed.
        matched: usize,
        /// Identifiers of satisfied pattern indicators.
        indicators: Vec<String>,
    },
    /// Whole-file Shannon entropy anomaly.
    FileEntropy {
        /// Observed whole-file entropy.
        entropy: f64,
        /// Configured threshold.
        threshold: f64,
    },
    /// PE characteristic anomaly (e.g., RWX permissions, anomalous entry point).
    PeCharacteristic {
        /// Name of the characteristic.
        name: String,
        /// Detailed technical description.
        detail: String,
    },
    /// Matched Import Hash (imphash).
    Imphash {
        /// The MD5 imphash string.
        imphash: String,
    },
    /// Thread Local Storage (TLS) callbacks (often used for anti-debugging or pre-main execution).
    TlsCallback {
        /// Number of registered callbacks.
        count: usize,
        /// Virtual addresses of callback functions.
        addresses: Vec<u64>,
    },
    /// Matched Export Hash (exphash).
    Exphash {
        /// The MD5 exphash string.
        exphash: String,
    },
    /// Static tracking of arguments passed to an API call within a basic block.
    ApiCallArgument {
        /// The target Windows API function (e.g. `VirtualAlloc`).
        api: String,
        /// Name of the tracked parameter (e.g. `flProtect`).
        argument_name: String,
        /// Concrete numerical argument value (e.g. `0x40`).
        value: u64,
        /// Known constant alias (e.g. `PAGE_EXECUTE_READWRITE`).
        constant_name: String,
        /// Virtual address of the call instruction.
        address: u64,
    },
    /// Matched instruction sequence localized to a single basic block.
    BasicBlockMatch {
        /// Sequence of instruction mnemonics.
        mnemonics: Vec<String>,
        /// Virtual address of the basic block entry.
        address: u64,
    },
    /// Matched instruction sequence within a decompiled function scope.
    FunctionMatch {
        /// Sequence of instruction mnemonics.
        mnemonics: Vec<String>,
        /// Virtual address of the function entry point.
        address: u64,
    },
    /// Custom analyst or rule notification string.
    Custom(String),
}

impl MatchedEvidence {
    pub fn display_text(&self) -> String {
        match self {
            MatchedEvidence::StringMatch { id, count, offsets } => {
                let offset_preview: Vec<String> = offsets
                    .iter()
                    .take(4)
                    .map(|o| format!("0x{:x}", o))
                    .collect();
                let more = if offsets.len() > 4 {
                    format!(" (+{} more)", offsets.len() - 4)
                } else {
                    String::new()
                };
                format!(
                    "Pattern {} ({} hit(s) at [{}]{})",
                    id,
                    count,
                    offset_preview.join(", "),
                    more
                )
            }
            MatchedEvidence::PeImport { dll, function } => {
                format!("Imported API: {}!{}", dll, function)
            }
            MatchedEvidence::PeExport { function } => {
                format!("Exported Symbol: {}", function)
            }
            MatchedEvidence::PeSectionEntropy {
                section,
                entropy,
                threshold,
            } => {
                format!(
                    "Section '{}' entropy: {:.2} (threshold: {:.2})",
                    section, entropy, threshold
                )
            }
            MatchedEvidence::PeSectionFlag { section, flag } => {
                format!("Section '{}' flag: {}", section, flag)
            }
            MatchedEvidence::Quantifier {
                required,
                matched,
                indicators,
            } => {
                format!(
                    "Quantifier: {}/{} indicators satisfied ({})",
                    matched,
                    required,
                    indicators.join(", ")
                )
            }
            MatchedEvidence::FileEntropy { entropy, threshold } => {
                format!(
                    "High file entropy: {:.2} (threshold > {:.2})",
                    entropy, threshold
                )
            }
            MatchedEvidence::PeCharacteristic { name, detail } => {
                format!("PE characteristic {}: {}", name, detail)
            }
            MatchedEvidence::Imphash { imphash } => {
                format!("Import Hash (imphash): {}", imphash)
            }
            MatchedEvidence::TlsCallback { count, addresses } => {
                let addrs_str = addresses
                    .iter()
                    .take(4)
                    .map(|a| format!("0x{:x}", a))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "TLS Callbacks: {} callback(s) registered [{}]",
                    count, addrs_str
                )
            }
            MatchedEvidence::Exphash { exphash } => {
                format!("Export Hash (exphash): {}", exphash)
            }
            MatchedEvidence::ApiCallArgument {
                api,
                argument_name,
                value,
                constant_name,
                address,
            } => {
                format!(
                    "API call '{}' passed {} = 0x{:x} ({}) at VA 0x{:x}",
                    api, argument_name, value, constant_name, address
                )
            }
            MatchedEvidence::BasicBlockMatch { mnemonics, address } => {
                format!(
                    "Basic block at VA 0x{:x} matches scoped sequence: [{}]",
                    address,
                    mnemonics.join(" -> ")
                )
            }
            MatchedEvidence::FunctionMatch { mnemonics, address } => {
                format!(
                    "Function at VA 0x{:x} matches scoped sequence: [{}]",
                    address,
                    mnemonics.join(" -> ")
                )
            }
            MatchedEvidence::Custom(msg) => msg.clone(),
        }
    }
}

/// The runtime evaluation context supplied to rule condition evaluators.
///
/// Holds the binary data slice, filesystem path (if scanning from disk), pre-calculated
/// hashes, whole-file and section entropy, binary format metadata (PE, ELF, Mach-O),
/// pattern matches, and recorded [`MatchedEvidence`] instances.
pub struct ScanContext<'a> {
    /// Raw byte buffer of the target sample.
    pub data: &'a [u8],
    /// Filesystem path of the target, if scanned from disk.
    pub path: Option<&'a Path>,
    /// Size of the sample in bytes.
    pub file_size: usize,
    /// Cryptographic and fuzzy hashes (MD5, SHA1, SHA256, SSDEEP, imphash).
    pub hashes: FileHashes,
    /// Whole-file Shannon entropy (0.0 to 8.0).
    pub entropy: f64,
    /// Detailed executable format analysis (PE, ELF, Mach-O).
    pub binary: BinaryAnalysis,
    /// String matches indexed by pattern identifier (e.g. `$a`).
    pub string_matches: HashMap<String, Vec<StringMatch>>,
    /// Verifiable technical evidence accumulated during rule evaluation.
    pub evidence: Vec<MatchedEvidence>,
}

impl<'a> ScanContext<'a> {
    /// Constructs a new [`ScanContext`] initialized with extracted features and patterns.
    pub fn new(
        data: &'a [u8],
        path: Option<&'a Path>,
        hashes: FileHashes,
        entropy: f64,
        binary: BinaryAnalysis,
        string_matches: HashMap<String, Vec<StringMatch>>,
    ) -> Self {
        Self {
            data,
            path,
            file_size: data.len(),
            hashes,
            entropy,
            binary,
            string_matches,
            evidence: Vec::new(),
        }
    }

    /// Appends a new item of concrete technical evidence, deduplicating identical records.
    pub fn record_evidence(&mut self, evidence: MatchedEvidence) {
        if !self.evidence.contains(&evidence) {
            self.evidence.push(evidence);
        }
    }
}
