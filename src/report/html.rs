// src/report/html.rs
//
// Standalone, Air-Gapped Interactive HTML Forensic Report Generator for Raya 2.0
// Styled according to Apple museum gallery-grade design standards:
// - Photography-first presentation framing the binary artifact
// - Edge-to-edge alternating light (#f5f5f7 / #ffffff) and dark (#272729 / #2a2a2c) canvases
// - SF Pro Display headlines with negative letter-spacing and 17px body copy
// - Single Action Blue (#0066cc) interactive accent with zero decorative gradients
// - Single soft surface drop-shadow (rgba(0, 0, 0, 0.22) 3px 5px 30px 0) on the artifact pedestal
// - Zero external CDN dependencies, fully air-gapped with zero Unicode emojis

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

    let primary_target = results
        .first()
        .map(|r| r.target.as_str())
        .unwrap_or("Binary Artifact");

    let primary_verdict = results
        .first()
        .map(|r| r.threat_level.as_str())
        .unwrap_or("CLEAN");

    let primary_score = results.first().map(|r| r.threat_score).unwrap_or(0);

    let mut html = String::with_capacity(128 * 1024);

    html.push_str(r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Raya 2.0 - Forensic Threat Intelligence Report</title>
<style>
:root {
  --primary: #0066cc;
  --primary-focus: #0071e3;
  --primary-on-dark: #2997ff;
  --ink: #1d1d1f;
  --body: #1d1d1f;
  --body-on-dark: #ffffff;
  --body-muted: #cccccc;
  --ink-muted-80: #333333;
  --ink-muted-48: #7a7a7a;
  --divider-soft: #f0f0f0;
  --hairline: #e0e0e0;
  --canvas: #ffffff;
  --canvas-parchment: #f5f5f7;
  --surface-pearl: #fafafc;
  --surface-tile-1: #272729;
  --surface-tile-2: #2a2a2c;
  --surface-tile-3: #252527;
  --surface-black: #000000;
  --surface-chip: rgba(210, 210, 215, 0.64);
  --status-critical: #d70015;
  --status-high: #ff6482;
  --status-medium: #c97f00;
  --status-clean: #248a3d;
}

*, *::before, *::after {
  box-sizing: border-box;
}

body {
  margin: 0;
  padding: 0;
  background-color: var(--canvas-parchment);
  color: var(--ink);
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 17px;
  line-height: 1.47;
  letter-spacing: -0.374px;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

/* Global Nav */
.global-nav {
  position: sticky;
  top: 0;
  z-index: 1000;
  background-color: var(--surface-black);
  height: 44px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 32px;
  font-family: "SF Pro Text", system-ui, -apple-system, sans-serif;
  font-size: 12px;
  font-weight: 400;
  letter-spacing: -0.12px;
  color: var(--body-on-dark);
}
.global-nav-brand {
  font-weight: 600;
  letter-spacing: -0.05px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.global-nav-links {
  display: flex;
  align-items: center;
  gap: 24px;
}
.global-nav a {
  color: var(--body-muted);
  text-decoration: none;
  transition: color 0.15s ease;
}
.global-nav a:hover {
  color: var(--body-on-dark);
}

/* Frosted Sub-Nav */
.sub-nav-frosted {
  position: sticky;
  top: 44px;
  z-index: 990;
  background-color: rgba(245, 245, 247, 0.82);
  backdrop-filter: saturate(180%) blur(20px);
  -webkit-backdrop-filter: saturate(180%) blur(20px);
  border-bottom: 1px solid rgba(0, 0, 0, 0.08);
  height: 52px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 32px;
}
.sub-nav-title {
  font-family: "SF Pro Display", system-ui, -apple-system, sans-serif;
  font-size: 21px;
  font-weight: 600;
  line-height: 1.19;
  letter-spacing: 0.231px;
  color: var(--ink);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 60%;
}
.sub-nav-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

/* Buttons */
.btn-primary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background-color: var(--primary);
  color: #ffffff;
  font-family: "SF Pro Text", system-ui, -apple-system, sans-serif;
  font-size: 14px;
  font-weight: 400;
  line-height: 1.0;
  padding: 8px 18px;
  border-radius: 9999px;
  text-decoration: none;
  border: none;
  cursor: pointer;
  transition: transform 0.15s cubic-bezier(0.25, 1, 0.5, 1), background-color 0.15s ease;
}
.btn-primary:active {
  transform: scale(0.95);
  background-color: var(--primary-focus);
}
.btn-secondary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background-color: var(--canvas);
  color: var(--primary);
  font-family: "SF Pro Text", system-ui, -apple-system, sans-serif;
  font-size: 14px;
  font-weight: 400;
  line-height: 1.0;
  padding: 8px 18px;
  border-radius: 9999px;
  text-decoration: none;
  border: 1px solid var(--primary);
  cursor: pointer;
  transition: transform 0.15s cubic-bezier(0.25, 1, 0.5, 1);
}
.btn-secondary:active {
  transform: scale(0.95);
}

/* Badges */
.badge-pill {
  display: inline-flex;
  align-items: center;
  padding: 4px 12px;
  border-radius: 9999px;
  font-family: "SF Pro Text", system-ui, -apple-system, sans-serif;
  font-size: 12px;
  font-weight: 600;
  line-height: 1.29;
  letter-spacing: -0.224px;
  text-transform: uppercase;
}
.badge-critical {
  background-color: #fde8e8;
  color: var(--status-critical);
  border: 1px solid rgba(215, 0, 21, 0.2);
}
.badge-high {
  background-color: #fef0f0;
  color: var(--status-critical);
  border: 1px solid rgba(215, 0, 21, 0.2);
}
.badge-medium {
  background-color: #fff8e6;
  color: var(--status-medium);
  border: 1px solid rgba(201, 127, 0, 0.2);
}
.badge-clean {
  background-color: #eaf6ec;
  color: var(--status-clean);
  border: 1px solid rgba(36, 138, 61, 0.2);
}

/* Product Tile Layouts */
.section-parchment {
  background-color: var(--canvas-parchment);
  padding: 80px 24px 60px;
}
.section-canvas {
  background-color: var(--canvas);
  padding: 80px 24px;
}
.section-dark {
  background-color: var(--surface-tile-1);
  color: var(--body-on-dark);
  padding: 80px 24px;
}

.content-container {
  max-width: 1200px;
  margin: 0 auto;
}

/* Museum Gallery Hero */
.hero-stack {
  text-align: center;
  max-width: 860px;
  margin: 0 auto 56px;
}
.hero-eyebrow {
  font-family: "SF Pro Text", system-ui, -apple-system, sans-serif;
  font-size: 14px;
  font-weight: 600;
  line-height: 1.29;
  letter-spacing: 0.8px;
  text-transform: uppercase;
  color: var(--primary);
  margin-bottom: 12px;
}
.hero-headline {
  font-family: "SF Pro Display", system-ui, -apple-system, sans-serif;
  font-size: 56px;
  font-weight: 600;
  line-height: 1.07;
  letter-spacing: -0.28px;
  color: var(--ink);
  margin: 0 0 16px;
}
.hero-lead {
  font-family: "SF Pro Display", system-ui, -apple-system, sans-serif;
  font-size: 24px;
  font-weight: 400;
  line-height: 1.3;
  letter-spacing: 0.196px;
  color: var(--ink-muted-48);
  margin: 0;
}

/* The Artifact Pedestal (Signature Drop-Shadow) */
.artifact-pedestal {
  background-color: var(--canvas);
  border-radius: 18px;
  box-shadow: 3px 5px 30px rgba(0, 0, 0, 0.16);
  padding: 40px;
  border: 1px solid var(--hairline);
  margin-bottom: 40px;
}
.pedestal-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  border-bottom: 1px solid var(--divider-soft);
  padding-bottom: 24px;
  margin-bottom: 32px;
}
.pedestal-title {
  font-family: "SF Pro Display", system-ui, -apple-system, sans-serif;
  font-size: 34px;
  font-weight: 600;
  line-height: 1.2;
  letter-spacing: -0.374px;
  color: var(--ink);
  margin: 0 0 8px;
  word-break: break-all;
}
.pedestal-subtitle {
  font-size: 14px;
  color: var(--ink-muted-48);
}
.score-pill-box {
  text-align: right;
}
.score-big {
  font-family: "SF Pro Display", system-ui, -apple-system, sans-serif;
  font-size: 52px;
  font-weight: 600;
  line-height: 1.0;
  letter-spacing: -0.5px;
}

/* Metric Grid */
.metric-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 20px;
  margin-bottom: 32px;
}
.metric-card {
  background-color: var(--surface-pearl);
  border: 1px solid var(--hairline);
  border-radius: 18px;
  padding: 24px;
}
.metric-label {
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.4px;
  text-transform: uppercase;
  color: var(--ink-muted-48);
  margin-bottom: 8px;
}
.metric-value {
  font-family: "SF Pro Display", system-ui, -apple-system, sans-serif;
  font-size: 28px;
  font-weight: 600;
  letter-spacing: -0.2px;
  color: var(--ink);
}
.metric-sub {
  font-size: 12px;
  color: var(--ink-muted-80);
  margin-top: 4px;
}

/* Entropy Bar Component */
.entropy-container {
  margin-top: 12px;
}
.entropy-track {
  width: 100%;
  height: 8px;
  background-color: var(--hairline);
  border-radius: 9999px;
  overflow: hidden;
}
.entropy-fill {
  height: 100%;
  border-radius: 9999px;
  transition: width 0.3s ease;
}

/* Hash Table */
.hash-stack {
  background-color: var(--surface-pearl);
  border: 1px solid var(--hairline);
  border-radius: 18px;
  padding: 20px 24px;
}
.hash-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 10px 0;
  border-bottom: 1px solid var(--divider-soft);
  font-size: 14px;
}
.hash-row:last-child {
  border-bottom: none;
}
.hash-name {
  font-weight: 600;
  color: var(--ink-muted-80);
  width: 120px;
}
.hash-value {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 13px;
  color: var(--ink);
  background: var(--canvas);
  border: 1px solid var(--hairline);
  border-radius: 8px;
  padding: 6px 12px;
  word-break: break-all;
  flex: 1;
  margin: 0 12px;
}
.btn-copy {
  background-color: var(--canvas);
  border: 1px solid var(--hairline);
  border-radius: 8px;
  padding: 6px 12px;
  font-size: 12px;
  cursor: pointer;
  color: var(--primary);
  font-weight: 500;
  transition: transform 0.15s ease, background-color 0.15s ease;
}
.btn-copy:active {
  transform: scale(0.95);
  background-color: var(--canvas-parchment);
}

/* Section Headlines */
.section-headline {
  font-family: "SF Pro Display", system-ui, -apple-system, sans-serif;
  font-size: 40px;
  font-weight: 600;
  line-height: 1.1;
  letter-spacing: 0;
  margin: 0 0 12px;
}
.section-tagline {
  font-family: "SF Pro Display", system-ui, -apple-system, sans-serif;
  font-size: 21px;
  font-weight: 400;
  line-height: 1.4;
  color: var(--ink-muted-48);
  margin: 0 0 40px;
}
.section-dark .section-tagline {
  color: var(--body-muted);
}

/* Dark Section Cards */
.dark-finding-card {
  background-color: var(--surface-tile-2);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 18px;
  padding: 32px;
  margin-bottom: 24px;
}
.dark-card-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 16px;
}
.finding-rule-name {
  font-family: "SF Pro Display", system-ui, -apple-system, sans-serif;
  font-size: 24px;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px;
}
.finding-desc {
  font-size: 15px;
  color: var(--body-muted);
  line-height: 1.5;
  margin: 0 0 16px;
}
.finding-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 20px;
}
.tag-chip {
  background-color: rgba(255, 255, 255, 0.08);
  border-radius: 9999px;
  padding: 4px 12px;
  font-size: 12px;
  color: #ffffff;
}
.mitre-chip {
  background-color: rgba(41, 151, 255, 0.15);
  border: 1px solid rgba(41, 151, 255, 0.3);
  border-radius: 9999px;
  padding: 4px 12px;
  font-size: 12px;
  font-weight: 600;
  color: var(--primary-on-dark);
}

/* Evidence Terminal Container */
.evidence-terminal {
  background-color: var(--surface-black);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 11px;
  padding: 16px 20px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 13px;
  line-height: 1.6;
  color: #e5e5ea;
  overflow-x: auto;
}
.evidence-item {
  margin-bottom: 6px;
  display: flex;
  align-items: baseline;
  gap: 8px;
}
.evidence-prefix {
  color: var(--primary-on-dark);
  font-weight: 600;
}

/* Footer */
.gallery-footer {
  background-color: var(--canvas-parchment);
  border-top: 1px solid var(--hairline);
  padding: 64px 32px;
  font-size: 12px;
  color: var(--ink-muted-80);
}
.footer-content {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 24px;
}
.legal-copy {
  color: var(--ink-muted-48);
  margin-top: 16px;
}

@media (max-width: 768px) {
  .hero-headline {
    font-size: 38px;
  }
  .pedestal-header {
    flex-direction: column;
    gap: 16px;
  }
  .score-pill-box {
    text-align: left;
  }
  .global-nav {
    padding: 0 16px;
  }
  .sub-nav-frosted {
    padding: 0 16px;
  }
}
</style>
</head>
<body>

<!-- Global Navigation -->
<nav class="global-nav">
  <div class="global-nav-brand">
    <span>RAYA 2.0 FORENSIC ENGINE</span>
  </div>
  <div class="global-nav-links">
    <a href="#overview">Overview</a>
    <a href="#findings">Threat Matches</a>
    <a href="#metadata">Artifact Hashes</a>
    <span style="color: var(--primary-on-dark);">Air-Gapped Standalone</span>
  </div>
</nav>

<!-- Frosted Sub-Navigation -->
<div class="sub-nav-frosted">
  <div class="sub-nav-title">"###);

    html.push_str(&escape_html(primary_target));
    html.push_str(
        r###"</div>
  <div class="sub-nav-actions">"###,
    );

    let badge_cls = match primary_verdict {
        "MALICIOUS" | "CRITICAL" => "badge-critical",
        "SUSPICIOUS" => "badge-medium",
        _ => "badge-clean",
    };

    html.push_str(&format!(
        r###"<span class="badge-pill {}">{} ({} / 100)</span>
    <button class="btn-primary" onclick="window.print()">Print / Export PDF</button>
  </div>
</div>
"###,
        badge_cls, primary_verdict, primary_score
    ));

    // Section 1: Hero Exhibition
    html.push_str(r###"<section class="section-parchment" id="overview">
  <div class="content-container">
    <div class="hero-stack">
      <div class="hero-eyebrow">Forensic Threat Intelligence</div>
      <h1 class="hero-headline">Static Binary Analysis.</h1>
      <p class="hero-lead">High-fidelity triage, control-flow graph mapping, and deep rule evaluation for security operations.</p>
    </div>
"###);

    // Summary Metric Cards (Store Utility Cards)
    html.push_str(
        r###"<div class="metric-grid">
      <div class="metric-card">
        <div class="metric-label">Objects Inspected</div>
        <div class="metric-value">"###,
    );
    html.push_str(&total_scanned.to_string());
    html.push_str(
        r###"</div>
        <div class="metric-sub">Full multi-pass coverage</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Malicious Hits</div>
        <div class="metric-value" style="color: var(--status-critical);">"###,
    );
    html.push_str(&total_malicious.to_string());
    html.push_str(
        r###"</div>
        <div class="metric-sub">Confirmed critical signatures</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Suspicious Detections</div>
        <div class="metric-value" style="color: var(--status-medium);">"###,
    );
    html.push_str(&total_suspicious.to_string());
    html.push_str(
        r###"</div>
        <div class="metric-sub">Heuristic and behavioral alerts</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Clean Files</div>
        <div class="metric-value" style="color: var(--status-clean);">"###,
    );
    html.push_str(&total_clean.to_string());
    html.push_str(
        r###"</div>
        <div class="metric-sub">Zero anomalies identified</div>
      </div>
    </div>
"###,
    );

    // Per-Artifact Exhibition Pedestals
    for res in results {
        let (item_badge_cls, item_score_color) = match res.threat_level.as_str() {
            "MALICIOUS" | "CRITICAL" => ("badge-critical", "var(--status-critical)"),
            "SUSPICIOUS" => ("badge-medium", "var(--status-medium)"),
            _ => ("badge-clean", "var(--status-clean)"),
        };

        let entropy_pct = ((res.entropy / 8.0) * 100.0).clamp(0.0, 100.0);
        let entropy_color = if res.entropy > 7.2 {
            "var(--status-critical)"
        } else if res.entropy > 6.0 {
            "var(--status-medium)"
        } else {
            "var(--primary)"
        };

        html.push_str(
            r###"    <div class="artifact-pedestal">
      <div class="pedestal-header">
        <div>
          <h2 class="pedestal-title">"###,
        );
        html.push_str(&escape_html(&res.target));
        html.push_str(
            r###"</h2>
          <div class="pedestal-subtitle">Format: "###,
        );
        html.push_str(&escape_html(&res.file_type));
        html.push_str(&format!(
            r###" | Size: {} bytes ({:.2} MB) | Duration: {:.2} ms</div>
        </div>
        <div class="score-pill-box">
          <span class="badge-pill {}">{}</span>
          <div class="score-big" style="color: {}; margin-top: 8px;">{}/100</div>
        </div>
      </div>
"###,
            res.file_size,
            res.file_size as f64 / (1024.0 * 1024.0),
            res.scan_duration_ms,
            item_badge_cls,
            res.threat_level,
            item_score_color,
            res.threat_score
        ));

        // Sub-metrics inside pedestal
        html.push_str(
            r###"      <div class="metric-grid" style="grid-template-columns: repeat(3, 1fr);">
        <div class="metric-card">
          <div class="metric-label">Shannon Entropy</div>
          <div class="metric-value">"###,
        );
        html.push_str(&format!(
            "{:.4} <span style=\"font-size: 16px; color: var(--ink-muted-48);\">/ 8.0</span>",
            res.entropy
        ));
        html.push_str(&format!(
            r###"</div>
          <div class="entropy-container">
            <div class="entropy-track">
              <div class="entropy-fill" style="width: {:.1}%; background-color: {};"></div>
            </div>
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Matching Rules</div>
          <div class="metric-value">{}</div>
          <div class="metric-sub">Triggered threat patterns</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">MITRE Tactics</div>
          <div class="metric-value">{}</div>
          <div class="metric-sub">ATT&CK techniques mapped</div>
        </div>
      </div>
"###,
            entropy_pct,
            entropy_color,
            res.matches.len(),
            res.attack_tactics.len()
        ));

        // Hash Table
        html.push_str(
            r###"      <div class="hash-stack" id="metadata">
        <div class="hash-row">
          <div class="hash-name">SHA-256</div>
          <div class="hash-value">"###,
        );
        html.push_str(&escape_html(&res.hashes.sha256));
        html.push_str(&format!(
            r###"</div>
          <button class="btn-copy" onclick="navigator.clipboard.writeText('{}'); this.innerText='Copied'">Copy</button>
        </div>
        <div class="hash-row">
          <div class="hash-name">MD5</div>
          <div class="hash-value">{}</div>
          <button class="btn-copy" onclick="navigator.clipboard.writeText('{}'); this.innerText='Copied'">Copy</button>
        </div>
"###,
            res.hashes.sha256, res.hashes.md5, res.hashes.md5
        ));

        if let Some(ref ssdeep) = res.hashes.ssdeep {
            html.push_str(&format!(
                r###"        <div class="hash-row">
          <div class="hash-name">SSDEEP</div>
          <div class="hash-value">{}</div>
          <button class="btn-copy" onclick="navigator.clipboard.writeText('{}'); this.innerText='Copied'">Copy</button>
        </div>
"###,
                escape_html(ssdeep),
                ssdeep
            ));
        }

        if let Some(ref imphash) = res.hashes.imphash {
            html.push_str(&format!(
                r###"        <div class="hash-row">
          <div class="hash-name">Imphash</div>
          <div class="hash-value">{}</div>
          <button class="btn-copy" onclick="navigator.clipboard.writeText('{}'); this.innerText='Copied'">Copy</button>
        </div>
"###,
                escape_html(imphash),
                imphash
            ));
        }

        html.push_str("      </div>\n    </div>\n");
    }

    html.push_str("  </div>\n</section>\n");

    // Section 2: Dark Canvas for Deep Forensic Rule Findings
    html.push_str(r###"<section class="section-dark" id="findings">
  <div class="content-container">
    <h2 class="section-headline">Forensic Evidence & Rule Detections.</h2>
    <p class="section-tagline">Granular match telemetry, instruction-level offsets, and MITRE ATT&CK tactical classifications.</p>
"###);

    for res in results {
        if res.matches.is_empty() {
            html.push_str(r###"    <div class="dark-finding-card" style="text-align: center; padding: 48px;">
      <h3 style="color: var(--primary-on-dark); font-size: 24px; margin-bottom: 8px;">No Malicious Rules Triggered</h3>
      <p style="color: var(--body-muted);">The target passed all static signature, heuristic, and entropy checks cleanly.</p>
    </div>
"###);
            continue;
        }

        for m in &res.matches {
            let sev_badge = match m.severity {
                Severity::Critical => "badge-critical",
                Severity::High => "badge-high",
                Severity::Medium => "badge-medium",
                _ => "badge-clean",
            };

            html.push_str(
                r###"    <div class="dark-finding-card">
      <div class="dark-card-head">
        <div>
          <h3 class="finding-rule-name">"###,
            );
            html.push_str(&escape_html(&m.rule));
            html.push_str(
                r###"</h3>
          <div class="finding-desc">"###,
            );
            if let Some(ref desc) = m.description {
                html.push_str(&escape_html(desc));
            } else {
                html.push_str(&escape_html(&m.reason));
            }
            html.push_str(
                r###"</div>
        </div>
        <span class="badge-pill "###,
            );
            html.push_str(sev_badge);
            html.push_str(&format!(
                r###"">{:?}</span>
      </div>
      <div class="finding-tags">
"###,
                m.severity
            ));

            for tag in &m.tags {
                html.push_str(&format!(
                    r###"        <span class="tag-chip">#{}</span>
"###,
                    escape_html(tag)
                ));
            }

            if let Some(ref tech) = m.mitre_technique {
                html.push_str(&format!(
                    r###"        <span class="mitre-chip">MITRE ATT&CK: {}</span>
"###,
                    escape_html(tech)
                ));
            }

            html.push_str("      </div>\n");

            // Evidence Terminal
            html.push_str(
                r###"      <div class="evidence-terminal">
"###,
            );

            if m.evidence.is_empty() {
                html.push_str(&format!(
                    r###"        <div class="evidence-item">
          <span class="evidence-prefix">[-]</span>
          <span>{}</span>
        </div>
"###,
                    escape_html(&m.reason)
                ));
            } else {
                for ev in &m.evidence {
                    html.push_str(&format!(
                        r###"        <div class="evidence-item">
          <span class="evidence-prefix">[+]</span>
          <span>{:?}</span>
        </div>
"###,
                        ev
                    ));
                }
            }

            html.push_str("      </div>\n    </div>\n");
        }
    }

    html.push_str("  </div>\n</section>\n");

    // Section 3: Museum Footer
    html.push_str(r###"<footer class="gallery-footer">
  <div class="footer-content">
    <div>
      <div style="font-weight: 600; color: var(--ink); margin-bottom: 4px;">Raya 2.0 Binary Analysis Platform</div>
      <div>Engineered in Rust for zero-trust forensic triage and high-speed threat hunting.</div>
      <div class="legal-copy">Air-Gapped Standalone Forensic Report. Generated locally with zero network calls.</div>
    </div>
    <div style="text-align: right;">
      <div>Report Specifications: Version 2.0 (Alpha)</div>
      <div style="color: var(--ink-muted-48); margin-top: 4px;">Primary Interactive Color: Action Blue (#0066cc)</div>
    </div>
  </div>
</footer>

</body>
</html>
"###);

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
