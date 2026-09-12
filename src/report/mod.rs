//! # Reporting, Evidence Formatting & Threat Scoring
//!
//! This module provides structured reporting models, terminal formatting, and enterprise
//! integrations for scan verdicts.
//!
//! - [`ScanResult`]: Top-level scan report containing hashes, entropy, file format, and rule matches.
//! - [`RuleMatch`]: Information on an individual matched rule, including MITRE ATT&CK techniques and concrete evidence.
//! - [`to_sarif`]: Serializer for **OASIS SARIF v2.1.0**, directly ingestible by GitHub Code Scanning and security dashboards.
//! - [`to_stix`]: Serializer for **OASIS STIX 2.1**, converting detections into structured threat intelligence bundles.

use crate::ast::Severity;
use crate::binary::BinaryAnalysis;
use crate::engine::context::MatchedEvidence;
use crate::hash::FileHashes;
use colored::Colorize;
use serde::{Deserialize, Serialize};

/// Detailed report of a single detection rule match.
///
/// Contains rule metadata, threat severity, MITRE ATT&CK mapping, and an array
/// of concrete [`MatchedEvidence`] entries documenting exact technical findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Name of the matched rule.
    pub rule: String,
    /// Assessed severity level.
    pub severity: Severity,
    /// Tags assigned to the rule (e.g. `["windows", "malware", "injection"]`).
    pub tags: Vec<String>,
    /// Optional human-readable rule description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Author or organization that created the rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Associated MITRE ATT&CK technique ID (e.g. `T1055.002`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_technique: Option<String>,
    /// Compact list of satisfied indicator names (e.g. `["$inject", "imphash:abc"]`).
    pub matched_indicators: Vec<String>,
    /// Full technical evidence details (offsets, bytes, disassembly, API arguments).
    pub evidence: Vec<MatchedEvidence>,
    /// Explanation of why the rule condition was satisfied.
    pub reason: String,
}

/// The complete forensic verdict produced by scanning a target file or buffer.
///
/// Contains whole-file cryptographic and fuzzy hashes, entropy calculations,
/// executable format introspection, a normalized threat score (0–100), and all
/// triggered [`RuleMatch`]es.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Identifier or filepath of the scanned target.
    pub target: String,
    /// Size of the target in bytes.
    pub file_size: usize,
    /// Detected format (e.g. `"PE32+"`, `"ELF64"`, `"Mach-O"`, `"RAW"`).
    pub file_type: String,
    /// Cryptographic (MD5, SHA1, SHA256) and fuzzy (SSDEEP, imphash, exphash) hashes.
    pub hashes: FileHashes,
    /// Whole-file Shannon entropy (0.0 to 8.0).
    pub entropy: f64,
    /// List of all triggered rule detections.
    pub matches: Vec<RuleMatch>,
    /// Duration of the scan in milliseconds.
    pub scan_duration_ms: f64,
    /// Computed composite threat score from 0 (benign) to 100 (critical threat).
    #[serde(default)]
    pub threat_score: u8,
    /// Qualitative classification (`"CLEAN"`, `"SUSPICIOUS"`, `"MALICIOUS"`, `"CRITICAL"`).
    #[serde(default)]
    pub threat_level: String,
    /// Discovered MITRE ATT&CK tactics (e.g. `["Execution", "Defense Evasion"]`).
    #[serde(default)]
    pub attack_tactics: Vec<String>,
}

impl ScanResult {
    pub fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }

    pub fn compute_threat_metrics(
        matches: &[RuleMatch],
        entropy: f64,
        binary: &BinaryAnalysis,
    ) -> (u8, String, Vec<String>) {
        if matches.is_empty() {
            return (0, "CLEAN".to_string(), Vec::new());
        }

        let mut score: u32 = 0;
        let mut tactics = std::collections::BTreeSet::new();

        for m in matches {
            match m.severity {
                Severity::Critical => score += 70,
                Severity::High => score += 40,
                Severity::Medium => score += 20,
                Severity::Low => score += 10,
                Severity::Info => score += 3,
            }

            if let Some(ref tech) = m.mitre_technique {
                let tactic = match tech.split('.').next().unwrap_or(tech) {
                    "T1055" => "Privilege Escalation / Injection",
                    "T1059" => "Execution",
                    "T1071" => "Command and Control (C2)",
                    "T1486" => "Impact (Ransomware)",
                    "T1547" => "Persistence",
                    "T1027" => "Defense Evasion (Obfuscation)",
                    "T1036" => "Defense Evasion (Masquerading)",
                    "T1082" => "Discovery",
                    "T1003" => "Credential Access",
                    "T1566" => "Initial Access",
                    _ => "Malicious Activity",
                };
                tactics.insert(tactic.to_string());
            }

            for ev in &m.evidence {
                if let MatchedEvidence::ApiCallArgument { .. } = ev {
                    score += 15;
                }
            }
        }

        if entropy > 7.8 {
            score += 15;
        } else if entropy > 7.2 {
            score += 10;
        }

        if let Some(ref pe) = binary.pe {
            if pe.has_rwx_section() {
                score += 20;
            }
            if pe.has_tls && !pe.tls_callbacks.is_empty() {
                score += 10;
            }
            if pe.number_of_sections > 10 {
                score += 10;
            }
        }

        let final_score = score.min(100) as u8;
        let level = match final_score {
            0 => "CLEAN",
            1..=29 => "LOW RISK",
            30..=59 => "SUSPICIOUS",
            60..=79 => "HIGH RISK",
            _ => "MALICIOUS",
        }
        .to_string();

        (final_score, level, tactics.into_iter().collect())
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

        out.push_str(&format!("Target:       {}\n", self.target.bold()));
        out.push_str(&format!("Size:         {} bytes\n", self.file_size));
        out.push_str(&format!("Type:         {}\n", self.file_type.cyan()));
        out.push_str(&format!("SHA256:       {}\n", self.hashes.sha256));
        if let Some(ref imp) = self.hashes.imphash {
            out.push_str(&format!("IMPHASH:      {}\n", imp.magenta()));
        }
        if let Some(ref exp) = self.hashes.exphash {
            out.push_str(&format!("EXPHASH:      {}\n", exp.magenta()));
        }
        out.push_str(&format!("Entropy:      {:.2} / 8.0\n", self.entropy));

        if self.matches.is_empty() {
            out.push_str(&format!(
                "Threat Level: {}\n",
                "[CLEAN] (Score: 0/100)".green().bold()
            ));
            out.push_str(&format!(
                "\n{}\n",
                "✓ No rules matched (clean)".green().bold()
            ));
            return out;
        }

        let threat_display = match self.threat_level.as_str() {
            "MALICIOUS" => format!("[{}] (Score: {}/100)", self.threat_level, self.threat_score)
                .on_red()
                .white()
                .bold(),
            "HIGH RISK" => format!("[{}] (Score: {}/100)", self.threat_level, self.threat_score)
                .red()
                .bold(),
            "SUSPICIOUS" => format!("[{}] (Score: {}/100)", self.threat_level, self.threat_score)
                .yellow()
                .bold(),
            "LOW RISK" => format!("[{}] (Score: {}/100)", self.threat_level, self.threat_score)
                .blue()
                .bold(),
            _ => format!("[{}] (Score: {}/100)", self.threat_level, self.threat_score)
                .green()
                .bold(),
        };
        out.push_str(&format!("Threat Level: {}\n", threat_display));

        if !self.attack_tactics.is_empty() {
            out.push_str(&format!(
                "ATT&CK Chain: {}\n",
                self.attack_tactics.join(" -> ").magenta().bold()
            ));
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
                    MatchedEvidence::PeCharacteristic { name, detail } => {
                        out.push_str(&format!(
                            "    ✓ PE characteristic: {} ({})\n",
                            name.cyan().bold(),
                            detail.yellow()
                        ));
                    }
                    MatchedEvidence::Imphash { imphash } => {
                        out.push_str(&format!(
                            "    ✓ Import Hash (imphash): {}\n",
                            imphash.magenta().bold()
                        ));
                    }
                    MatchedEvidence::Exphash { exphash } => {
                        out.push_str(&format!(
                            "    ✓ Export Hash (exphash): {}\n",
                            exphash.magenta().bold()
                        ));
                    }
                    MatchedEvidence::TlsCallback { count, addresses } => {
                        let addrs_str = if addresses.is_empty() {
                            String::new()
                        } else {
                            format!(
                                " [{}]",
                                addresses
                                    .iter()
                                    .take(3)
                                    .map(|a| format!("0x{:x}", a))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        };
                        out.push_str(&format!(
                            "    ✓ TLS Callbacks: {} callback(s) registered{}\n",
                            count.to_string().red().bold(),
                            addrs_str.dimmed()
                        ));
                    }
                    MatchedEvidence::ApiCallArgument {
                        api,
                        argument_name,
                        value,
                        constant_name,
                        address,
                    } => {
                        out.push_str(&format!(
                            "    ✓ API Call Argument: {}!{} = 0x{:x} ({}) at VA 0x{:x}\n",
                            api.cyan().bold(),
                            argument_name.yellow(),
                            value,
                            constant_name.red().bold(),
                            address
                        ));
                    }
                    MatchedEvidence::BasicBlockMatch { mnemonics, address } => {
                        out.push_str(&format!(
                            "    ✓ Scoped Basic Block at VA 0x{:x}: [{}]\n",
                            address,
                            mnemonics.join(" -> ").yellow()
                        ));
                    }
                    MatchedEvidence::FunctionMatch { mnemonics, address } => {
                        out.push_str(&format!(
                            "    ✓ Scoped Function at VA 0x{:x}: [{}]\n",
                            address,
                            mnemonics.join(" -> ").yellow()
                        ));
                    }
                    MatchedEvidence::StackString {
                        value,
                        offset,
                        is_wide,
                    } => {
                        out.push_str(&format!(
                            "    ✓ Deobfuscated Stack String: \"{}\" at VA 0x{:x}{}\n",
                            value.green().bold(),
                            offset,
                            if *is_wide { " (UTF-16LE)" } else { "" }
                        ));
                    }
                    MatchedEvidence::CryptoConstant {
                        algorithm,
                        description,
                        offset,
                    } => {
                        out.push_str(&format!(
                            "    ✓ Cryptographic Constant [{}]: {} at offset 0x{:x}\n",
                            algorithm.magenta().bold(),
                            description,
                            offset
                        ));
                    }
                    MatchedEvidence::DotNetIndicator { indicator } => {
                        out.push_str(&format!("    ✓ .NET CLR Indicator: {}\n", indicator.cyan()));
                    }
                    MatchedEvidence::GoIndicator { indicator } => {
                        out.push_str(&format!("    ✓ Golang Indicator: {}\n", indicator.cyan()));
                    }
                    MatchedEvidence::RustIndicator { indicator } => {
                        out.push_str(&format!("    ✓ Rust Indicator: {}\n", indicator.cyan()));
                    }
                    MatchedEvidence::RichAnomaly { detail } => {
                        out.push_str(&format!(
                            "    ✓ Rich Header Anomaly: {}\n",
                            detail.red().bold()
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

/// Converts a slice of [`ScanResult`] items into an **OASIS SARIF v2.1.0** JSON report.
///
/// SARIF (Static Analysis Results Interchange Format) is the industry standard for
/// uploading static analysis findings to **GitHub Advanced Security / Code Scanning**,
/// GitLab SAST, and enterprise IDEs.
///
/// Each rule is converted into a SARIF `rule` object with MITRE ATT&CK taxonomy tags,
/// and each detection produces a SARIF `result` with physical file locations and byte offsets.
///
/// # Errors
///
/// Returns [`serde_json::Error`] if serialization fails.
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

            let evidence_bullets: Vec<String> = m
                .evidence
                .iter()
                .map(|e| format!("- {}", e.display_text()))
                .collect();

            let evidence_section = if !evidence_bullets.is_empty() {
                format!(
                    "\n\n### Evidence Indicators\n{}",
                    evidence_bullets.join("\n")
                )
            } else {
                String::new()
            };

            let mitre_line = if let Some(ref tech) = m.mitre_technique {
                format!(
                    "\n**MITRE ATT&CK:** [{0}](https://attack.mitre.org/techniques/{1}/)",
                    tech,
                    tech.replace('.', "/")
                )
            } else {
                String::new()
            };

            let markdown_text = format!(
                "**Rule:** `{}` ({:?})\n**Target:** `{}` (SHA-256: `{}`){}\n\n{}\n\n**Verdict Reason:** {}{}",
                m.rule,
                m.severity,
                res.target,
                res.hashes.sha256,
                mitre_line,
                m.description.as_deref().unwrap_or("No description provided."),
                m.reason,
                evidence_section
            );

            let mut related_locations = Vec::new();
            for ev in &m.evidence {
                if let MatchedEvidence::StringMatch { id, offsets, .. } = ev {
                    for (i, &offset) in offsets.iter().take(5).enumerate() {
                        related_locations.push(json!({
                            "id": related_locations.len() + 1,
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": res.target
                                },
                                "region": {
                                    "byteOffset": offset
                                }
                            },
                            "message": {
                                "text": format!("String pattern '{}' (occurrence #{})", id, i + 1)
                            }
                        }));
                    }
                }
            }

            let mut res_obj = json!({
                "ruleId": m.rule,
                "level": level,
                "message": {
                    "text": format!("{}: {}", m.rule, m.description.as_deref().unwrap_or(&m.reason)),
                    "markdown": markdown_text
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": res.target
                            }
                        }
                    }
                ],
                "properties": {
                    "tags": m.tags,
                    "mitreTechnique": m.mitre_technique,
                    "author": m.author,
                    "matchedIndicators": m.matched_indicators,
                    "evidence": m.evidence,
                    "sha256": res.hashes.sha256,
                    "imphash": res.hashes.imphash,
                    "fileSize": res.file_size,
                    "fileType": res.file_type,
                    "entropy": res.entropy,
                    "threatScore": res.threat_score,
                    "threatLevel": res.threat_level,
                    "attackTactics": res.attack_tactics
                }
            });

            if !related_locations.is_empty() {
                res_obj["relatedLocations"] = json!(related_locations);
            }

            sarif_results.push(res_obj);
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

/// Converts a slice of [`ScanResult`] items into an **OASIS STIX 2.1** JSON bundle.
///
/// STIX (Structured Threat Information Expression) 2.1 is the global standard for
/// cyber threat intelligence (CTI) sharing and SOAR platform ingestion (e.g. OpenCTI,
/// MISP, Splunk ES, Sentinel).
///
/// Produces a STIX `bundle` containing:
/// - A `file` Cyber Observable Object (SCO) capturing hashes (SHA-256, SHA-1, MD5, SSDEEP, imphash).
/// - An `indicator` Domain Object (SDO) for each detected rule with MITRE ATT&CK technique references.
/// - A `relationship` SDO (`"based-on"`) connecting the indicator to the target file observable.
///
/// # Errors
///
/// Returns [`serde_json::Error`] if serialization fails.
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
        if let Some(ref imp) = res.hashes.imphash {
            hashes_obj.insert("IMPHASH".to_string(), json!(imp));
        }
        if let Some(ref exp) = res.hashes.exphash {
            hashes_obj.insert("EXPHASH".to_string(), json!(exp));
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
            let confidence = match m.severity {
                Severity::Critical => 95,
                Severity::High => 85,
                Severity::Medium => 70,
                Severity::Low => 50,
                Severity::Info => 30,
            };

            let mut external_refs = Vec::new();
            if let Some(ref tech) = m.mitre_technique {
                external_refs.push(json!({
                    "source_name": "mitre-attack",
                    "external_id": tech,
                    "url": format!("https://attack.mitre.org/techniques/{}/", tech.replace('.', "/"))
                }));
            }

            let mut desc = m.description.clone().unwrap_or_else(|| m.rule.clone());
            if !m.evidence.is_empty() {
                desc.push_str("\n\nEvidence Indicators:\n");
                for ev in &m.evidence {
                    desc.push_str(&format!("- {}\n", ev.display_text()));
                }
            }
            desc.push_str(&format!("\nVerdict: {}", m.reason));

            let mut indicator_obj = json!({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "name": m.rule,
                "description": desc,
                "indicator_types": ["malicious-activity"],
                "pattern": format!("[file:hashes.'SHA-256' = '{}']", res.hashes.sha256),
                "pattern_type": "stix",
                "confidence": confidence,
                "labels": m.tags,
                "x_raya_severity": format!("{:?}", m.severity).to_lowercase(),
                "x_raya_threat_score": res.threat_score,
                "x_raya_threat_level": res.threat_level,
                "x_raya_attack_tactics": res.attack_tactics,
                "x_raya_matched_indicators": m.matched_indicators
            });

            if !external_refs.is_empty() {
                indicator_obj["external_references"] = json!(external_refs);
            }

            objects.push(indicator_obj);

            // SDO Relationship: indicator indicates the observed file
            let rel_id = format!("relationship--raya-{}-{}", idx, m.rule);
            objects.push(json!({
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": file_sco_id,
                "description": format!("Rule {} indicates potential malware in {}", m.rule, res.target)
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
                imphash: Some("68f013d7437aa653a8a98a05807afeb1".to_string()),
                exphash: None,
            },
            entropy: 7.2,
            matches: vec![RuleMatch {
                rule: "ransomware_detected".to_string(),
                severity: Severity::Critical,
                tags: vec!["ransomware".to_string()],
                description: Some("Detects ransomware payload".to_string()),
                author: Some("Analyst".to_string()),
                mitre_technique: Some("T1486".to_string()),
                matched_indicators: vec!["has_rwx".to_string(), "imphash:68f013d7437aa653a8a98a05807afeb1".to_string()],
                evidence: vec![
                    MatchedEvidence::PeCharacteristic {
                        name: "has_rwx".to_string(),
                        detail: "RWX section '.text' at VA 0x00001000 (VirtualSize: 1024 bytes, RawSize: 1024 bytes, Flags: 0xE0000060)".to_string(),
                    },
                    MatchedEvidence::Imphash {
                        imphash: "68f013d7437aa653a8a98a05807afeb1".to_string(),
                    },
                ],
                reason: "Condition satisfied with 2 evidence indicator(s)".to_string(),
            }],
            scan_duration_ms: 1.5,
            threat_score: 95,
            threat_level: "MALICIOUS".to_string(),
            attack_tactics: vec!["Impact".to_string()],
        };

        let sarif = to_sarif(std::slice::from_ref(&result)).expect("Should serialize SARIF");
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(sarif.contains("ransomware_detected"));
        assert!(sarif.contains("Evidence Indicators"));
        assert!(sarif.contains("properties"));
        assert!(sarif.contains("has_rwx"));
        assert!(sarif.contains("68f013d7437aa653a8a98a05807afeb1"));

        let stix = to_stix(&[result]).expect("Should serialize STIX");
        assert!(stix.contains("\"type\": \"bundle\""));
        assert!(stix.contains("\"type\": \"indicator\""));
        assert!(stix.contains("\"type\": \"relationship\""));
        assert!(stix.contains("\"relationship_type\": \"indicates\""));
        assert!(stix.contains("\"confidence\": 95"));
        assert!(stix.contains("mitre-attack"));
        assert!(stix.contains("Evidence Indicators:"));
    }
}
