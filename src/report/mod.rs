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
            out.push_str(&format!("\n{}\n", "✓ No rules matched (clean)".green().bold()));
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

            out.push_str(&format!("\n{} {}{}\n", sev_tag, m.rule.bold(), tags_str.dimmed()));

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
                    MatchedEvidence::PeSectionEntropy { section, entropy, .. } => {
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
                    MatchedEvidence::Quantifier { required, matched, indicators } => {
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
