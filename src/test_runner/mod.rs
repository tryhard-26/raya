use crate::engine::Engine;
use crate::parser::parse_rules_from_file;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub rule: String,
    #[serde(default)]
    pub positive: Vec<PathBuf>,
    #[serde(default)]
    pub negative: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuiteSpec {
    pub name: String,
    pub rules_path: PathBuf,
    pub cases: Vec<TestCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResultDetail {
    pub rule: String,
    pub sample: String,
    pub expected_match: bool,
    pub actual_match: bool,
    pub passed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSummary {
    pub suite_name: String,
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub details: Vec<TestResultDetail>,
}

impl TestSummary {
    pub fn detection_coverage(&self) -> f64 {
        let total_pos = self.details.iter().filter(|d| d.expected_match).count();
        if total_pos == 0 {
            return 100.0;
        }
        let true_pos = self
            .details
            .iter()
            .filter(|d| d.expected_match && d.actual_match)
            .count();
        (true_pos as f64 / total_pos as f64) * 100.0
    }

    pub fn false_positive_rate(&self) -> f64 {
        let total_neg = self.details.iter().filter(|d| !d.expected_match).count();
        if total_neg == 0 {
            return 0.0;
        }
        let fp = self.false_positives;
        (fp as f64 / total_neg as f64) * 100.0
    }

    pub fn render_terminal(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "\n=== Rule Test Suite: {} ===\n\n",
            self.suite_name.bold()
        ));

        for d in &self.details {
            let status = if d.passed {
                "PASS".green().bold()
            } else {
                "FAIL".red().bold()
            };

            let expected_str = if d.expected_match {
                "must match".cyan()
            } else {
                "must NOT match".magenta()
            };

            out.push_str(&format!(
                "  [{}] rule '{}' against '{}' ({})\n",
                status, d.rule, d.sample, expected_str
            ));

            if let Some(err) = &d.error {
                out.push_str(&format!("         Error: {}\n", err.red()));
            }
        }

        out.push_str(&format!("\nTotal tests:     {}\n", self.total_tests));
        out.push_str(&format!("Passed:          {}\n", self.passed.to_string().green()));
        out.push_str(&format!(
            "Failed:          {}\n",
            if self.failed > 0 {
                self.failed.to_string().red().bold()
            } else {
                "0".normal()
            }
        ));
        out.push_str(&format!("False Positives: {}\n", self.false_positives));
        out.push_str(&format!("False Negatives: {}\n", self.false_negatives));
        out.push_str(&format!(
            "Coverage:        {:.1}%\n",
            self.detection_coverage()
        ));
        out.push_str(&format!(
            "FP Rate:         {:.1}%\n",
            self.false_positive_rate()
        ));

        out
    }
}

pub fn run_test_suite<P: AsRef<Path>>(spec_path: P) -> Result<TestSummary, String> {
    let spec_path = spec_path.as_ref();
    let spec_dir = spec_path.parent().unwrap_or_else(|| Path::new("."));

    let content = fs::read_to_string(spec_path)
        .map_err(|e| format!("Cannot read test spec '{}': {}", spec_path.display(), e))?;

    let spec: TestSuiteSpec = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid test spec JSON in '{}': {}", spec_path.display(), e))?;

    // Resolve rules path relative to spec
    let rules_path = if spec.rules_path.is_absolute() {
        spec.rules_path.clone()
    } else {
        spec_dir.join(&spec.rules_path)
    };

    // Load rules
    let mut all_rules = Vec::new();
    if rules_path.is_file() {
        let rules = parse_rules_from_file(&rules_path)
            .map_err(|e| format!("Rule parsing error in '{}': {}", rules_path.display(), e))?;
        all_rules.extend(rules);
    } else if rules_path.is_dir() {
        for entry in WalkDir::new(&rules_path).into_iter().filter_map(|e| e.ok()) {
            if entry.path().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "raya" || ext == "yar" || ext == "yara" {
                        if let Ok(rules) = parse_rules_from_file(entry.path()) {
                            all_rules.extend(rules);
                        }
                    }
                }
            }
        }
    } else {
        return Err(format!("Rules path '{}' does not exist", rules_path.display()));
    }

    let engine = Engine::compile_rules(all_rules)
        .map_err(|e| format!("Engine compilation error: {}", e))?;

    let mut details = Vec::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut false_positives = 0;
    let mut false_negatives = 0;

    for case in &spec.cases {
        // Positive tests
        for sample_rel in &case.positive {
            let sample_path = if sample_rel.is_absolute() {
                sample_rel.clone()
            } else {
                spec_dir.join(sample_rel)
            };

            let res = engine.scan_file(&sample_path);
            match res {
                Ok(scan_result) => {
                    let matched = scan_result.matches.iter().any(|m| m.rule == case.rule);
                    let is_pass = matched;
                    if is_pass {
                        passed += 1;
                    } else {
                        failed += 1;
                        false_negatives += 1;
                    }
                    details.push(TestResultDetail {
                        rule: case.rule.clone(),
                        sample: sample_path.display().to_string(),
                        expected_match: true,
                        actual_match: matched,
                        passed: is_pass,
                        error: if !matched {
                            Some("Expected rule to match, but got no match".to_string())
                        } else {
                            None
                        },
                    });
                }
                Err(e) => {
                    failed += 1;
                    false_negatives += 1;
                    details.push(TestResultDetail {
                        rule: case.rule.clone(),
                        sample: sample_path.display().to_string(),
                        expected_match: true,
                        actual_match: false,
                        passed: false,
                        error: Some(format!("Failed to read sample: {}", e)),
                    });
                }
            }
        }

        // Negative tests
        for sample_rel in &case.negative {
            let sample_path = if sample_rel.is_absolute() {
                sample_rel.clone()
            } else {
                spec_dir.join(sample_rel)
            };

            let res = engine.scan_file(&sample_path);
            match res {
                Ok(scan_result) => {
                    let matched = scan_result.matches.iter().any(|m| m.rule == case.rule);
                    let is_pass = !matched;
                    if is_pass {
                        passed += 1;
                    } else {
                        failed += 1;
                        false_positives += 1;
                    }
                    details.push(TestResultDetail {
                        rule: case.rule.clone(),
                        sample: sample_path.display().to_string(),
                        expected_match: false,
                        actual_match: matched,
                        passed: is_pass,
                        error: if matched {
                            Some(format!("False positive! Rule '{}' matched clean sample", case.rule))
                        } else {
                            None
                        },
                    });
                }
                Err(e) => {
                    failed += 1;
                    details.push(TestResultDetail {
                        rule: case.rule.clone(),
                        sample: sample_path.display().to_string(),
                        expected_match: false,
                        actual_match: false,
                        passed: false,
                        error: Some(format!("Failed to read sample: {}", e)),
                    });
                }
            }
        }
    }

    Ok(TestSummary {
        suite_name: spec.name,
        total_tests: details.len(),
        passed,
        failed,
        false_positives,
        false_negatives,
        details,
    })
}
