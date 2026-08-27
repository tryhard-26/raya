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
    Custom(String),
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
