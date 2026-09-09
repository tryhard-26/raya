use crate::ast::Severity;
use crate::engine::context::MatchedEvidence;
use crate::hash::FileHashes;
use colored::Colorize;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule: String,
    pub severity: Severity,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_technique: Option<String>,
    pub matched_indicators: Vec<String>,
    pub evidence: Vec<MatchedEvidence>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub file_size: usize,
    pub file_type: String,
    pub hashes: FileHashes,
    pub entropy: f64,
    pub matches: Vec<RuleMatch>,
    pub scan_duration_ms: f64,
}

impl ScanResult {
    pub fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }

    pub fn to_json(&self, pretty: bool) -> Result<String, serde_json::Error> {
        if pretty {
            serde_json::to_string_pretty(self)
        } else {
            serde_json::to_string(self)
        }
    }

    pub fn render_terminal(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!("Target: {}\n", self.target.bold()));
        out.push_str(&format!("Size:   {} bytes\n", self.file_size));
        out.push_str(&format!("Type:   {}\n", self.file_type.cyan()));
        out.push_str(&format!("SHA256: {}\n", self.hashes.sha256));
        out.push_str(&format!("Entropy: {:.2} / 8.0\n", self.entropy));

        if self.matches.is_empty() {
            out.push_str(&format!(
                "\n{}\n",
                "✓ No rules matched (clean)".green().bold()
            ));
            return out;
        }

        out.push_str(&format!(
            "\n{}\n",
            format!("MATCHES ({} rule(s) triggered):", self.matches.len())
                .red()
                .bold()
        ));

        for m in &self.matches {
            let sev_tag = match m.severity {
                Severity::Critical => "[CRITICAL]".on_red().white().bold(),
                Severity::High => "[HIGH]".red().bold(),
                Severity::Medium => "[MEDIUM]".yellow().bold(),
                Severity::Low => "[LOW]".blue().bold(),
                Severity::Info => "[INFO]".cyan().bold(),
            };

            let tags_str = if !m.tags.is_empty() {
                format!(" ({})", m.tags.join(", "))
            } else {
                String::new()
            };

            out.push_str(&format!(
                "\n{} {}{}\n",
                sev_tag,
                m.rule.bold(),
                tags_str.dimmed()
            ));

            if let Some(desc) = &m.description {
                out.push_str(&format!("  Description: {}\n", desc));
            }
            if let Some(tech) = &m.mitre_technique {
                out.push_str(&format!("  ATT&CK:      {}\n", tech.magenta()));
            }

            out.push_str("  Evidence:\n");
            for ev in &m.evidence {
                match ev {
                    MatchedEvidence::StringMatch { id, count, offsets } => {
                        let offset_preview: Vec<String> = offsets
                            .iter()
                            .take(3)
                            .map(|o| format!("0x{:x}", o))
                            .collect();
                        let more = if offsets.len() > 3 {
                            format!(" +{} more", offsets.len() - 3)
                        } else {
                            String::new()
                        };
                        out.push_str(&format!(
                            "    ✓ Pattern {} ({} hit(s) at [{}]{})\n",
                            id.green(),
                            count,
                            offset_preview.join(", "),
                            more
                        ));
                    }
                    MatchedEvidence::PeImport { dll, function } => {
                        out.push_str(&format!(
                            "    ✓ Imported API: {}!{}\n",
                            dll.cyan(),
                            function.yellow().bold()
                        ));
                    }
                    MatchedEvidence::PeExport { function } => {
                        out.push_str(&format!("    ✓ Exported Symbol: {}\n", function.yellow()));
                    }
                    MatchedEvidence::PeSectionEntropy {
                        section, entropy, ..
                    } => {
                        out.push_str(&format!(
                            "    ✓ Section '{}' entropy: {:.2}\n",
                            section.cyan(),
                            entropy
                        ));
                    }
                    MatchedEvidence::PeSectionFlag { section, flag } => {
                        out.push_str(&format!(
                            "    ✓ Section '{}' flag: {}\n",
                            section.cyan(),
                            flag.red()
                        ));
                    }
                    MatchedEvidence::Quantifier {
                        required,
                        matched,
                        indicators,
                    } => {
                        out.push_str(&format!(
                            "    ✓ Quantifier: {}/{} indicators satisfied ({})\n",
                            matched,
                            required,
                            indicators.join(", ")
                        ));
                    }
                    MatchedEvidence::FileEntropy { entropy, threshold } => {
                        out.push_str(&format!(
                            "    ✓ High file entropy: {:.2} (threshold > {:.2})\n",
                            entropy, threshold
                        ));
                    }
                    MatchedEvidence::Custom(msg) => {
                        out.push_str(&format!("    ✓ {}\n", msg));
                    }
                }
            }

            if !m.reason.is_empty() {
                out.push_str(&format!("  Verdict Reason: {}\n", m.reason.dimmed()));
            }
        }

        out
    }
}

pub fn to_sarif(results: &[ScanResult]) -> Result<String, serde_json::Error> {
    use serde_json::json;

    let mut rules_map = std::collections::BTreeMap::new();
    let mut sarif_results = Vec::new();

    for res in results {
        for m in &res.matches {
            let level = match m.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            };

            rules_map.entry(m.rule.clone()).or_insert_with(|| {
                json!({
                    "id": m.rule,
                    "name": m.rule,
                    "shortDescription": {
                        "text": m.description.clone().unwrap_or_else(|| m.rule.clone())
                    },
                    "defaultConfiguration": {
                        "level": level
                    },
                    "properties": {
                        "tags": m.tags,
                        "mitreTechnique": m.mitre_technique
                    }
                })
            });

            sarif_results.push(json!({
                "ruleId": m.rule,
                "level": level,
                "message": {
                    "text": format!("{}: {}", m.rule, m.description.as_deref().unwrap_or(&m.reason))
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": res.target
                            }
                        }
                    }
                ]
            }));
        }
    }

    let sarif_rules: Vec<_> = rules_map.into_values().collect();

    let output = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Raya",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/tryhard-26/raya",
                        "rules": sarif_rules
                    }
                },
                "results": sarif_results
            }
        ]
    });

    serde_json::to_string_pretty(&output)
}

pub fn to_stix(results: &[ScanResult]) -> Result<String, serde_json::Error> {
    use serde_json::json;

    let mut objects = Vec::new();

    for (idx, res) in results.iter().enumerate() {
        if !res.has_matches() {
            continue;
        }

        let file_sco_id = format!("file--{}", res.hashes.sha256);
        let mut hashes_obj = serde_json::Map::new();
        hashes_obj.insert("SHA-256".to_string(), json!(res.hashes.sha256));
        hashes_obj.insert("SHA-1".to_string(), json!(res.hashes.sha1));
        hashes_obj.insert("MD5".to_string(), json!(res.hashes.md5));
        if let Some(ref ssdeep) = res.hashes.ssdeep {
            hashes_obj.insert("SSDEEP".to_string(), json!(ssdeep));
        }

        objects.push(json!({
            "type": "file",
            "spec_version": "2.1",
            "id": file_sco_id,
            "name": res.target,
            "size": res.file_size,
            "hashes": hashes_obj
        }));

        for m in &res.matches {
            let indicator_id = format!("indicator--raya-{}-{}", idx, m.rule);
            objects.push(json!({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "name": m.rule,
                "description": m.description,
                "indicator_types": ["malicious-activity"],
                "pattern": format!("[file:hashes.'SHA-256' = '{}']", res.hashes.sha256),
                "pattern_type": "stix"
            }));
        }
    }

    let bundle = json!({
        "type": "bundle",
        "id": format!("bundle--raya-scan-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()),
        "objects": objects
    });

    serde_json::to_string_pretty(&bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_and_stix_generation() {
        let result = ScanResult {
            target: "sample.exe".to_string(),
            file_size: 1024,
            file_type: "PE32".to_string(),
            hashes: FileHashes {
                sha256: "abc123".to_string(),
                sha1: "def456".to_string(),
                md5: "789ghi".to_string(),
                ssdeep: Some("3:xyz:abc".to_string()),
            },
            entropy: 7.2,
            matches: vec![RuleMatch {
                rule: "ransomware_detected".to_string(),
                severity: Severity::Critical,
                tags: vec!["ransomware".to_string()],
                description: Some("Detects ransomware payload".to_string()),
                author: Some("Analyst".to_string()),
                mitre_technique: Some("T1486".to_string()),
                matched_indicators: vec!["$s1".to_string()],
                evidence: Vec::new(),
                reason: "Matched".to_string(),
            }],
            scan_duration_ms: 1.5,
        };

        let sarif = to_sarif(std::slice::from_ref(&result)).expect("Should serialize SARIF");
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(sarif.contains("ransomware_detected"));

        let stix = to_stix(&[result]).expect("Should serialize STIX");
        assert!(stix.contains("\"type\": \"bundle\""));
        assert!(stix.contains("\"type\": \"indicator\""));
    }
}
