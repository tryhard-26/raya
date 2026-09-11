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

pub struct CompiledRule {
    pub rule: Rule,
    pub patterns: CompiledRulePatterns,
}

pub struct Engine {
    pub rules: Vec<CompiledRule>,
    pub global_ac: Option<AhoCorasick>,
    pub global_pattern_targets: Vec<(usize, String)>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            global_ac: None,
            global_pattern_targets: Vec::new(),
        }
    }

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
                    .filter_map(|e| match e {
                        MatchedEvidence::StringMatch { id, .. } => Some(id.clone()),
                        MatchedEvidence::PeImport { dll, function } => {
                            Some(format!("{}!{}", dll, function))
                        }
                        MatchedEvidence::PeExport { function } => Some(function.clone()),
                        MatchedEvidence::PeSectionEntropy { section, .. } => {
                            Some(format!("{}.entropy", section))
                        }
                        MatchedEvidence::PeSectionFlag { section, flag } => {
                            Some(format!("{}.{}", section, flag))
                        }
                        MatchedEvidence::PeCharacteristic { name, .. } => Some(name.clone()),
                        MatchedEvidence::Imphash { imphash } => {
                            Some(format!("imphash:{}", imphash))
                        }
                        MatchedEvidence::TlsCallback { count, .. } => {
                            Some(format!("tls_callbacks:{}", count))
                        }
                        MatchedEvidence::Exphash { exphash } => {
                            Some(format!("exphash:{}", exphash))
                        }
                        MatchedEvidence::ApiCallArgument {
                            api,
                            argument_name,
                            value,
                            ..
                        } => Some(format!("{}!{}:0x{:x}", api, argument_name, value)),
                        MatchedEvidence::BasicBlockMatch { address, .. } => {
                            Some(format!("bb:0x{:x}", address))
                        }
                        MatchedEvidence::FunctionMatch { address, .. } => {
                            Some(format!("fn:0x{:x}", address))
                        }
                        MatchedEvidence::FileEntropy { entropy, threshold } => {
                            Some(format!("entropy:{:.2}>{}", entropy, threshold))
                        }
                        MatchedEvidence::Quantifier {
                            matched,
                            required,
                            indicators,
                        } => Some(format!(
                            "quantifier:{}/{} ({})",
                            matched,
                            required,
                            indicators.join(",")
                        )),
                        MatchedEvidence::Custom(msg) => Some(msg.clone()),
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

    pub fn save_compiled_rules<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rules: Vec<Rule> = self.rules.iter().map(|cr| cr.rule.clone()).collect();
        let encoded = bincode::serialize(&rules)?;
        fs::write(path, encoded)?;
        Ok(())
    }

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
}
