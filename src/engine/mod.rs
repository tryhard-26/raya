//! # Scanning Engine & Evaluation Pipeline
//!
//! This module contains [`Engine`], the central execution engine responsible for:
//! - Compiling abstract rules into high-performance search automata.
//! - Running single-pass global multi-string searches using [Aho-Corasick](aho_corasick).
//! - Executing isolated regex and hex wildcard pattern scans.
//! - Performing executable format introspection ([PE](crate::binary::pe), [ELF](crate::binary::elf), [Mach-O](crate::binary::macho)).
//! - Evaluating boolean condition trees and recording concrete [`MatchedEvidence`].
//! - Calculating threat scores (0–100) and mapping matches to MITRE ATT&CK tactics.

pub mod context;
pub mod evaluator;
pub mod matcher;

pub use context::{MatchedEvidence, ScanContext};
pub use evaluator::Evaluator;
pub use matcher::{CompiledRulePatterns, MatchError, StringMatch};

use crate::ast::Rule;
use crate::binary::BinaryAnalysis;
use crate::entropy::shannon_entropy;
use crate::hash::compute_hashes;
use crate::report::{RuleMatch, ScanResult};
use std::fs;
use std::path::Path;
use std::time::Instant;

use aho_corasick::AhoCorasick;
use std::collections::HashMap;

/// A single compiled rule containing its AST definition and pre-compiled search patterns.
pub struct CompiledRule {
    /// The parsed Abstract Syntax Tree (AST) definition of the rule.
    pub rule: Rule,
    /// Pre-compiled regex and hex pattern matchers for this rule.
    pub patterns: CompiledRulePatterns,
}

/// The core scanning engine that executes compiled rules against byte streams and files.
///
/// An [`Engine`] is created by compiling one or more parsed [`Rule`] definitions via
/// [`Engine::compile_rules`]. The engine constructs a global, single-pass Aho-Corasick
/// automaton from all simple ASCII string patterns across all rules, ensuring O(N) linear
/// time complexity regardless of rule count.
///
/// # Example
///
/// ```rust
/// use raya::prelude::*;
///
/// let rules = parse_rules_from_str(r#"
///     rule sample_detection {
///         strings:
///             $a = "malicious_payload"
///         condition:
///             $a
///     }
/// "#).unwrap();
///
/// let engine = Engine::compile_rules(rules).unwrap();
/// let result = engine.scan_bytes(b"Contains malicious_payload here", "sample.bin");
/// assert_eq!(result.matches.len(), 1);
/// ```
pub struct Engine {
    /// All compiled rules loaded into the engine.
    pub rules: Vec<CompiledRule>,
    /// Global Aho-Corasick automaton across all simple literal patterns.
    pub global_ac: Option<AhoCorasick>,
    /// Mapping of global pattern IDs back to (rule_index, string_identifier).
    pub global_pattern_targets: Vec<(usize, String)>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    /// Creates an empty scanning engine with no rules loaded.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            global_ac: None,
            global_pattern_targets: Vec::new(),
        }
    }

    /// Compiles a vector of parsed [`Rule`]s into an optimized scanning engine.
    ///
    /// This method partitions literal strings suitable for global Aho-Corasick acceleration,
    /// compiles regular expressions and hex byte patterns, and optimizes rule conditions.
    ///
    /// # Errors
    ///
    /// Returns [`MatchError`] if any regular expression or hex pattern fails to compile.
    pub fn compile_rules(rules: Vec<Rule>) -> Result<Self, MatchError> {
        let mut global_patterns: Vec<Vec<u8>> = Vec::new();
        let mut global_pattern_targets: Vec<(usize, String)> = Vec::new();
        let mut compiled = Vec::with_capacity(rules.len());

        for (rule_idx, rule) in rules.into_iter().enumerate() {
            for def in &rule.strings {
                if let crate::ast::StringPattern::Literal {
                    ref bytes,
                    ascii,
                    wide,
                    nocase,
                    fullword,
                    xor,
                    base64,
                    base64wide,
                } = def.pattern
                {
                    if ascii
                        && !wide
                        && !nocase
                        && !fullword
                        && xor.is_none()
                        && !base64
                        && !base64wide
                    {
                        global_patterns.push(bytes.clone());
                        global_pattern_targets.push((rule_idx, def.id.clone()));
                    }
                }
            }

            let patterns = CompiledRulePatterns::compile(&rule.strings)?;
            compiled.push(CompiledRule { rule, patterns });
        }

        let global_ac = if !global_patterns.is_empty() {
            Some(AhoCorasick::new(&global_patterns)?)
        } else {
            None
        };

        Ok(Self {
            rules: compiled,
            global_ac,
            global_pattern_targets,
        })
    }

    /// Scans an in-memory byte slice against all compiled rules.
    ///
    /// The scan performs the following automated analysis pipeline:
    /// 1. Computes cryptographic hashes (MD5, SHA1, SHA256).
    /// 2. Computes whole-file Shannon entropy (0.0 to 8.0).
    /// 3. Introspects executable headers ([PE](crate::binary::pe), [ELF](crate::binary::elf), [Mach-O](crate::binary::macho)).
    /// 4. Executes global Aho-Corasick matching across all rules in a single pass.
    /// 5. Evaluates rule conditions and populates [`MatchedEvidence`].
    /// 6. Computes comprehensive threat score (0–100) and MITRE ATT&CK mapping.
    pub fn scan_bytes(&self, data: &[u8], target_name: &str) -> ScanResult {
        let start = Instant::now();
        let mut hashes = compute_hashes(data);
        let entropy = shannon_entropy(data);
        let binary = BinaryAnalysis::analyze(data);
        let file_type = binary.format.to_string();

        if let Some(ref pe) = binary.pe {
            hashes.imphash = pe.imphash.clone();
            hashes.exphash = pe.exphash.clone();
        }

        let mut rule_matches = Vec::new();

        // 1. Unified single-pass global Aho-Corasick across ALL rules
        let mut global_matches_per_rule: Vec<HashMap<String, Vec<StringMatch>>> =
            vec![HashMap::new(); self.rules.len()];

        if let Some(ac) = &self.global_ac {
            for mat in ac.find_iter(data) {
                let (rule_idx, string_id) = &self.global_pattern_targets[mat.pattern()];
                let offset = mat.start();
                let length = mat.end() - mat.start();
                let snippet_end = (offset + length.min(64)).min(data.len());
                let snippet = data[offset..snippet_end].to_vec();

                global_matches_per_rule[*rule_idx]
                    .entry(string_id.clone())
                    .or_default()
                    .push(StringMatch {
                        id: string_id.clone(),
                        offset,
                        length,
                        snippet,
                    });
            }
        }

        // 2. Evaluate each rule
        for (rule_idx, compiled_rule) in self.rules.iter().enumerate() {
            let mut string_matches = global_matches_per_rule[rule_idx].clone();

            // Run regex and hex patterns specific to this rule
            let regex_matches = compiled_rule.patterns.scan_regex_only(data);
            for (k, v) in regex_matches {
                string_matches.entry(k).or_default().extend(v);
            }

            let mut context = ScanContext::new(
                data,
                None,
                hashes.clone(),
                entropy,
                binary.clone(),
                string_matches,
            );

            let matched = {
                let mut evaluator = Evaluator::new(&mut context, &compiled_rule.rule);
                evaluator.evaluate()
            };

            if matched {
                // Guarantee automated triage pipelines and analysts never receive a detection alert with empty evidence
                if context.evidence.is_empty() {
                    context.record_evidence(MatchedEvidence::Custom(format!(
                        "rule:{} (condition evaluated to true)",
                        compiled_rule.rule.name
                    )));
                }

                let matched_indicators: Vec<String> = context
                    .evidence
                    .iter()
                    .map(|e| match e {
                        MatchedEvidence::StringMatch { id, .. } => id.clone(),
                        MatchedEvidence::PeImport { dll, function } => {
                            format!("{}!{}", dll, function)
                        }
                        MatchedEvidence::PeExport { function } => function.clone(),
                        MatchedEvidence::PeSectionEntropy { section, .. } => {
                            format!("{}.entropy", section)
                        }
                        MatchedEvidence::PeSectionFlag { section, flag } => {
                            format!("{}.{}", section, flag)
                        }
                        MatchedEvidence::PeCharacteristic { name, .. } => name.clone(),
                        MatchedEvidence::Imphash { imphash } => {
                            format!("imphash:{}", imphash)
                        }
                        MatchedEvidence::TlsCallback { count, .. } => {
                            format!("tls_callbacks:{}", count)
                        }
                        MatchedEvidence::Exphash { exphash } => {
                            format!("exphash:{}", exphash)
                        }
                        MatchedEvidence::ApiCallArgument {
                            api,
                            argument_name,
                            value,
                            ..
                        } => format!("{}!{}:0x{:x}", api, argument_name, value),
                        MatchedEvidence::BasicBlockMatch { address, .. } => {
                            format!("bb:0x{:x}", address)
                        }
                        MatchedEvidence::FunctionMatch { address, .. } => {
                            format!("fn:0x{:x}", address)
                        }
                        MatchedEvidence::FileEntropy { entropy, threshold } => {
                            format!("entropy:{:.2}>{}", entropy, threshold)
                        }
                        MatchedEvidence::Quantifier {
                            matched,
                            required,
                            indicators,
                        } => format!(
                            "quantifier:{}/{} ({})",
                            matched,
                            required,
                            indicators.join(",")
                        ),
                        MatchedEvidence::StackString { value, offset, .. } => {
                            format!("stack_str:\"{}\"@0x{:x}", value, offset)
                        }
                        MatchedEvidence::CryptoConstant {
                            algorithm, offset, ..
                        } => {
                            format!("crypto:{}:0x{:x}", algorithm, offset)
                        }
                        MatchedEvidence::DotNetIndicator { indicator } => {
                            format!("dotnet:{}", indicator)
                        }
                        MatchedEvidence::GoIndicator { indicator } => {
                            format!("go:{}", indicator)
                        }
                        MatchedEvidence::RustIndicator { indicator } => {
                            format!("rust:{}", indicator)
                        }
                        MatchedEvidence::RichAnomaly { detail } => {
                            format!("rich_anomaly:{}", detail)
                        }
                        MatchedEvidence::Custom(msg) => msg.clone(),
                    })
                    .collect();

                let reason = format!(
                    "Condition satisfied with {} evidence indicator(s)",
                    context.evidence.len()
                );

                rule_matches.push(RuleMatch {
                    rule: compiled_rule.rule.name.clone(),
                    severity: compiled_rule.rule.severity(),
                    tags: compiled_rule.rule.tags.clone(),
                    description: compiled_rule.rule.description().map(String::from),
                    author: compiled_rule.rule.author().map(String::from),
                    mitre_technique: compiled_rule.rule.mitre_technique().map(String::from),
                    matched_indicators,
                    evidence: context.evidence,
                    reason,
                });
            }
        }

        let duration = start.elapsed();
        let scan_duration_ms = duration.as_secs_f64() * 1000.0;

        let (threat_score, threat_level, attack_tactics) =
            ScanResult::compute_threat_metrics(&rule_matches, entropy, &binary);

        ScanResult {
            target: target_name.to_string(),
            file_size: data.len(),
            file_type,
            hashes,
            entropy,
            matches: rule_matches,
            scan_duration_ms,
            threat_score,
            threat_level,
            attack_tactics,
        }
    }

    /// Scans a file on disk against all compiled rules.
    ///
    /// For performance and memory efficiency, files $\ge 16\text{ KB}$ are mapped
    /// into memory using [`memmap2::Mmap`], eliminating buffer duplication and kernel-to-user
    /// copying overhead. Files $< 16\text{ KB}$ are read directly into a stack/heap buffer.
    ///
    /// # Errors
    ///
    /// Returns an [`std::io::Error`] if the file cannot be found or read.
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<ScanResult, std::io::Error> {
        let p = path.as_ref();
        let target_name = p.display().to_string();
        let file = fs::File::open(p)?;
        let meta = file.metadata()?;
        let file_len = meta.len();

        if file_len == 0 {
            return Ok(self.scan_bytes(&[], &target_name));
        }

        // Use memory-mapped I/O (memmap2) for files >= 16 KB to eliminate buffer copying
        if file_len >= 16 * 1024 {
            let mmap = unsafe { memmap2::Mmap::map(&file)? };
            Ok(self.scan_bytes(&mmap, &target_name))
        } else {
            let data = fs::read(p)?;
            Ok(self.scan_bytes(&data, &target_name))
        }
    }

    /// Serializes and saves the engine's compiled rule definitions to a binary file.
    ///
    /// Pre-compiling rules with this method allows near-instantaneous startup in CLI tools,
    /// daemon services, and serverless scanning functions by bypassing lexing and parsing.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or filesystem writing fails.
    pub fn save_compiled_rules<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rules: Vec<Rule> = self.rules.iter().map(|cr| cr.rule.clone()).collect();
        let encoded = bincode::serialize(&rules)?;
        fs::write(path, encoded)?;
        Ok(())
    }

    /// Deserializes and loads pre-compiled rules from a binary file.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the file or deserializing fails.
    pub fn load_compiled_rules<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = fs::read(path)?;
        let rules: Vec<Rule> = bincode::deserialize(&bytes)?;
        let engine = Self::compile_rules(rules)?;
        Ok(engine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_rules_from_str;

    #[test]
    fn test_engine_end_to_end() {
        let rule_source = r#"
            rule detect_secret {
                meta:
                    severity = "high"
                    description = "Detects secret token"
                strings:
                    $token = "SECRET_API_KEY_12345"
                condition:
                    $token and filesize > 10
            }
        "#;

        let rules = parse_rules_from_str(rule_source).unwrap();
        let engine = Engine::compile_rules(rules).unwrap();

        let payload = b"Header... SECRET_API_KEY_12345 ... Footer";
        let result = engine.scan_bytes(payload, "test_file.bin");

        assert!(result.has_matches());
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].rule, "detect_secret");
    }

    #[test]
    fn test_save_load_compiled_rules() {
        let rule_source = r#"
            rule cache_test {
                meta:
                    severity = "critical"
                strings:
                    $sig = "MALWARE_SIGNATURE_99"
                condition:
                    $sig
            }
        "#;

        let rules = parse_rules_from_str(rule_source).unwrap();
        let engine = Engine::compile_rules(rules).unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let cache_path = temp_dir.path().join("rules.rc");

        engine
            .save_compiled_rules(&cache_path)
            .expect("Failed to save rules");
        assert!(cache_path.exists());

        let loaded_engine = Engine::load_compiled_rules(&cache_path).expect("Failed to load rules");
        let payload = b"Injecting MALWARE_SIGNATURE_99 inside memory";
        let res = loaded_engine.scan_bytes(payload, "sample.bin");
        assert!(res.has_matches());
        assert_eq!(res.matches[0].rule, "cache_test");
    }

    #[test]
    fn test_crypto_engine_evaluation() {
        let rule_source = r#"
            rule detect_aes {
                meta:
                    severity = "medium"
                condition:
                    crypto.has_aes and crypto.has_any
            }
        "#;

        let rules = parse_rules_from_str(rule_source).unwrap();
        let engine = Engine::compile_rules(rules).unwrap();

        // Sample with AES S-box prefix
        let mut payload = vec![0u8; 128];
        const AES_SBOX: [u8; 16] = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ];
        payload[20..36].copy_from_slice(&AES_SBOX);

        let res = engine.scan_bytes(&payload, "crypto_sample.bin");
        assert!(res.has_matches());
        assert_eq!(res.matches[0].rule, "detect_aes");
    }

    #[test]
    fn test_go_and_rust_engine_evaluation() {
        let rule_source = r#"
            rule detect_go_sample {
                condition:
                    go.is_go and go.has_package("main")
            }
            rule detect_rust_sample {
                condition:
                    rust.is_rust and rust.has_crate("tokio")
            }
        "#;

        let rules = parse_rules_from_str(rule_source).unwrap();
        let engine = Engine::compile_rules(rules).unwrap();

        let mut go_payload = vec![0u8; 256];
        go_payload[0..6].copy_from_slice(&[0xf0, 0xff, 0xff, 0xff, 0x00, 0x00]);
        go_payload[50..58].copy_from_slice(b"go1.21.0");
        go_payload[100..109].copy_from_slice(b"main.init");

        let go_res = engine.scan_bytes(&go_payload, "go_app.bin");
        assert!(go_res.has_matches());
        assert_eq!(go_res.matches[0].rule, "detect_go_sample");

        let mut rust_payload = vec![0u8; 256];
        rust_payload[10..31].copy_from_slice(b"Option::unwrap()` on ");
        rust_payload[50..57].copy_from_slice(b"tokio::");

        let rust_res = engine.scan_bytes(&rust_payload, "rust_app.bin");
        assert!(rust_res.has_matches());
        assert_eq!(rust_res.matches[0].rule, "detect_rust_sample");
    }
}
