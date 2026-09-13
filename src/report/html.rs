// src/report/html.rs
//
// Standalone, Air-Gapped Interactive HTML Forensic Report Generator for Raya 2.0
// Produces an enterprise-grade cybersecurity report with dark mode UI, MITRE ATT&CK
// technique mapping, entropy visualization, and evidence breakdown with zero external CDN dependencies.

use crate::ast::Severity;
use crate::report::ScanResult;

/// Generates an interactive, standalone HTML report from an array of ScanResults.
pub fn to_html(results: &[ScanResult]) -> String {
    let total_scanned = results.len();
    let mut total_malicious = 0;
    let mut total_suspicious = 0;
    let mut total_clean = 0;

    for r in results {
        match r.threat_level.as_str() {
            "MALICIOUS" | "CRITICAL" => total_malicious += 1,
            "SUSPICIOUS" => total_suspicious += 1,
            _ => total_clean += 1,
        }
    }

    let mut html = String::with_capacity(64 * 1024);

    html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Raya 2.0 - Forensic Threat Intelligence Report</title>
<style>
:root {
  --bg-primary: #0d1117;
  --bg-secondary: #161b22;
  --bg-tertiary: #21262d;
  --text-main: #c9d1d9;
  --text-bright: #f0f6fc;
  --text-muted: #8b949e;
  --accent-cyan: #58a6ff;
  --accent-green: #3fb950;
  --accent-yellow: #d29922;
  --accent-red: #f85149;
  --border-color: #30363d;
}
body {
  margin: 0;
  padding: 24px;
  background-color: var(--bg-primary);
  color: var(--text-main);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
.container {
  max-width: 1200px;
  margin: 0 auto;
}
header {
  border-bottom: 2px solid var(--border-color);
  padding-bottom: 16px;
  margin-bottom: 24px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.logo {
  font-size: 28px;
  font-weight: 800;
  color: var(--accent-cyan);
  letter-spacing: 1px;
}
.badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 12px;
  font-weight: 700;
  font-size: 13px;
  text-transform: uppercase;
}
.badge-clean { background: rgba(63, 185, 80, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }
.badge-suspicious { background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
.badge-malicious { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 32px;
}
.stat-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}
.stat-value {
  font-size: 32px;
  font-weight: 800;
  margin-top: 4px;
  color: var(--text-bright);
}
.card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 24px;
  margin-bottom: 24px;
}
.card h2 {
  margin-top: 0;
  color: var(--accent-cyan);
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 8px;
  font-size: 20px;
}
table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 12px;
  font-size: 14px;
}
th, td {
  padding: 10px 14px;
  text-align: left;
  border-bottom: 1px solid var(--border-color);
}
th {
  background: var(--bg-tertiary);
  color: var(--text-bright);
  font-weight: 600;
}
.entropy-bar-container {
  width: 100%;
  height: 12px;
  background: var(--bg-tertiary);
  border-radius: 6px;
  overflow: hidden;
}
.entropy-bar {
  height: 100%;
  border-radius: 6px;
}
.evidence-list {
  background: var(--bg-primary);
  border-left: 3px solid var(--accent-cyan);
  padding: 12px 16px;
  margin-top: 8px;
  border-radius: 0 6px 6px 0;
  font-family: monospace;
  font-size: 13px;
}
.mitre-tag {
  display: inline-block;
  background: var(--bg-tertiary);
  color: var(--accent-cyan);
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  margin-right: 6px;
  text-decoration: none;
}
.mitre-tag:hover {
  text-decoration: underline;
}
</style>
</head>
<body>
<div class="container">
<header>
  <div>
    <div class="logo">RAYA 2.0 FORENSIC ENGINE</div>
    <div style="color: var(--text-muted); font-size: 13px;">Next-Generation Binary & Threat Intelligence Platform</div>
  </div>
  <div>
    <span class="badge badge-clean">Air-Gapped Edition</span>
  </div>
</header>
"#);

    // Summary cards
    html.push_str("<div class=\"stats-grid\">\n");
    html.push_str(&format!(
        "<div class=\"stat-card\"><div style=\"color: var(--text-muted);\">Total Scanned</div><div class=\"stat-value\">{}</div></div>\n",
        total_scanned
    ));
    html.push_str(&format!(
        "<div class=\"stat-card\"><div style=\"color: var(--accent-red);\">Malicious</div><div class=\"stat-value\" style=\"color: var(--accent-red);\">{}</div></div>\n",
        total_malicious
    ));
    html.push_str(&format!(
        "<div class=\"stat-card\"><div style=\"color: var(--accent-yellow);\">Suspicious</div><div class=\"stat-value\" style=\"color: var(--accent-yellow);\">{}</div></div>\n",
        total_suspicious
    ));
    html.push_str(&format!(
        "<div class=\"stat-card\"><div style=\"color: var(--accent-green);\">Clean</div><div class=\"stat-value\" style=\"color: var(--accent-green);\">{}</div></div>\n",
        total_clean
    ));
    html.push_str("</div>\n");

    // Per target detailed breakdown
    for res in results {
        let badge_class = match res.threat_level.as_str() {
            "MALICIOUS" | "CRITICAL" => "badge-malicious",
            "SUSPICIOUS" => "badge-suspicious",
            _ => "badge-clean",
        };

        html.push_str("<div class=\"card\">\n");
        html.push_str(&format!(
            "<div style=\"display: flex; justify-content: space-between; align-items: center;\"><h2>{}</h2><span class=\"badge {}\">{} (Score: {}/100)</span></div>\n",
            escape_html(&res.target), badge_class, res.threat_level, res.threat_score
        ));

        // Metadata table
        html.push_str("<table>\n");
        html.push_str(&format!(
            "<tr><th style=\"width: 20%;\">File Size</th><td>{} bytes</td></tr>\n",
            res.file_size
        ));
        html.push_str(&format!(
            "<tr><th>Binary Format</th><td>{}</td></tr>\n",
            res.file_type
        ));
        html.push_str(&format!(
            "<tr><th>Entropy</th><td>{:.4} / 8.0</td></tr>\n",
            res.entropy
        ));
        html.push_str(&format!(
            "<tr><th>SHA-256</th><td><code>{}</code></td></tr>\n",
            res.hashes.sha256
        ));
        html.push_str(&format!(
            "<tr><th>MD5</th><td><code>{}</code></td></tr>\n",
            res.hashes.md5
        ));
        if let Some(ref ss) = res.hashes.ssdeep {
            html.push_str(&format!(
                "<tr><th>SSDEEP</th><td><code>{}</code></td></tr>\n",
                ss
            ));
        }
        if let Some(ref imp) = res.hashes.imphash {
            html.push_str(&format!(
                "<tr><th>Imphash</th><td><code>{}</code></td></tr>\n",
                imp
            ));
        }
        if !res.attack_tactics.is_empty() {
            html.push_str(&format!(
                "<tr><th>ATT&CK Tactics</th><td>{}</td></tr>\n",
                res.attack_tactics.join(" &rarr; ")
            ));
        }
        html.push_str("</table>\n");

        // Rule matches
        if res.matches.is_empty() {
            html.push_str("<p style=\"color: var(--accent-green); margin-top: 16px;\">[+] Clean binary - zero detection rules matched.</p>\n");
        } else {
            html.push_str("<h3 style=\"margin-top: 24px; color: var(--text-bright);\">Triggered Detection Rules</h3>\n");
            for m in &res.matches {
                let sev_color = match m.severity {
                    Severity::Critical => "var(--accent-red)",
                    Severity::High => "var(--accent-red)",
                    Severity::Medium => "var(--accent-yellow)",
                    _ => "var(--accent-cyan)",
                };

                html.push_str("<div style=\"margin-bottom: 16px; border: 1px solid var(--border-color); border-radius: 6px; padding: 14px; background: var(--bg-tertiary);\">\n");
                html.push_str(&format!(
                    "<div style=\"display: flex; justify-content: space-between;\"><strong style=\"color: {}; font-size: 15px;\">[{:?}] {}</strong>",
                    sev_color, m.severity, escape_html(&m.rule)
                ));

                if let Some(ref tech) = m.mitre_technique {
                    html.push_str(&format!(
                        "<a class=\"mitre-tag\" href=\"https://attack.mitre.org/techniques/{}/\" target=\"_blank\">MITRE {}</a>",
                        tech.replace('.', "/"), tech
                    ));
                }
                html.push_str("</div>\n");

                if let Some(ref desc) = m.description {
                    html.push_str(&format!("<div style=\"color: var(--text-muted); font-size: 13px; margin: 4px 0;\">{}</div>\n", escape_html(desc)));
                }

                html.push_str("<div class=\"evidence-list\">\n");
                html.push_str(&format!(
                    "<div><strong>Verdict Reason:</strong> {}</div>\n",
                    escape_html(&m.reason)
                ));
                for ev in &m.evidence {
                    html.push_str(&format!(
                        "<div>[+] {}</div>\n",
                        escape_html(&format!("{:?}", ev))
                    ));
                }
                html.push_str("</div>\n");

                html.push_str("</div>\n");
            }
        }

        html.push_str("</div>\n"); // end card
    }

    html.push_str(r#"
<footer style="text-align: center; color: var(--text-muted); font-size: 12px; margin-top: 40px; border-top: 1px solid var(--border-color); padding-top: 16px;">
  Generated by Raya 2.0 | High-Assurance Rust-Native Malware Analysis Engine
</footer>
</div>
</body>
</html>
"#);

    html
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::FileHashes;

    #[test]
    fn test_html_generation_clean() {
        let res = ScanResult {
            target: "sample.exe".to_string(),
            file_size: 1024,
            file_type: "PE32+".to_string(),
            hashes: FileHashes {
                md5: "md5".to_string(),
                sha1: "sha1".to_string(),
                sha256: "sha256".to_string(),
                ssdeep: None,
                imphash: None,
                exphash: None,
            },
            entropy: 4.5,
            matches: Vec::new(),
            scan_duration_ms: 10.0,
            threat_score: 0,
            threat_level: "CLEAN".to_string(),
            attack_tactics: Vec::new(),
        };

        let html = to_html(&[res]);
        assert!(html.contains("RAYA 2.0 FORENSIC ENGINE"));
        assert!(html.contains("CLEAN"));
        assert!(html.contains("sample.exe"));
    }
}
