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

pub struct CompiledRule {
    pub rule: Rule,
    pub patterns: CompiledRulePatterns,
}

pub struct Engine {
    pub rules: Vec<CompiledRule>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn compile_rules(rules: Vec<Rule>) -> Result<Self, MatchError> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            let patterns = CompiledRulePatterns::compile(&rule.strings)?;
            compiled.push(CompiledRule { rule, patterns });
        }
        Ok(Self { rules: compiled })
    }

    pub fn scan_bytes(&self, data: &[u8], target_name: &str) -> ScanResult {
        let start = Instant::now();
        let hashes = compute_hashes(data);
        let entropy = shannon_entropy(data);
        let binary = BinaryAnalysis::analyze(data);
        let file_type = binary.format.to_string();

        let mut rule_matches = Vec::new();

        for compiled_rule in &self.rules {
            let string_matches = compiled_rule.patterns.scan(data);

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
                        _ => None,
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

        ScanResult {
            target: target_name.to_string(),
            file_size: data.len(),
            file_type,
            hashes,
            entropy,
            matches: rule_matches,
            scan_duration_ms,
        }
    }

    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<ScanResult, std::io::Error> {
        let p = path.as_ref();
        let data = fs::read(p)?;
        let target_name = p.display().to_string();
        Ok(self.scan_bytes(&data, &target_name))
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
}
