use crate::binary::BinaryAnalysis;
use crate::engine::matcher::StringMatch;
use crate::hash::FileHashes;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum MatchedEvidence {
    StringMatch {
        id: String,
        count: usize,
        offsets: Vec<usize>,
    },
    PeImport {
        dll: String,
        function: String,
    },
    PeExport {
        function: String,
    },
    PeSectionEntropy {
        section: String,
        entropy: f64,
        threshold: f64,
    },
    PeSectionFlag {
        section: String,
        flag: String,
    },
    Quantifier {
        required: usize,
        matched: usize,
        indicators: Vec<String>,
    },
    FileEntropy {
        entropy: f64,
        threshold: f64,
    },
    PeCharacteristic {
        name: String,
        detail: String,
    },
    Imphash {
        imphash: String,
    },
    TlsCallback {
        count: usize,
        addresses: Vec<u64>,
    },
    Exphash {
        exphash: String,
    },
    ApiCallArgument {
        api: String,
        argument_name: String,
        value: u64,
        constant_name: String,
        address: u64,
    },
    BasicBlockMatch {
        mnemonics: Vec<String>,
        address: u64,
    },
    FunctionMatch {
        mnemonics: Vec<String>,
        address: u64,
    },
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

pub struct ScanContext<'a> {
    pub data: &'a [u8],
    pub path: Option<&'a Path>,
    pub file_size: usize,
    pub hashes: FileHashes,
    pub entropy: f64,
    pub binary: BinaryAnalysis,
    pub string_matches: HashMap<String, Vec<StringMatch>>,
    pub evidence: Vec<MatchedEvidence>,
}

impl<'a> ScanContext<'a> {
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

    pub fn record_evidence(&mut self, evidence: MatchedEvidence) {
        if !self.evidence.contains(&evidence) {
            self.evidence.push(evidence);
        }
    }
}
