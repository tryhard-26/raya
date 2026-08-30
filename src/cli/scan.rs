use crate::ast::Severity;
use crate::engine::Engine;
use crate::parser::parse_rules_from_file;
use crate::report::ScanResult;
use colored::Colorize;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

pub struct ScanArgs {
    pub target: PathBuf,
    pub rules: Option<PathBuf>,
    pub recursive: bool,
    pub json: bool,
    pub quiet: bool,
    pub tag: Option<String>,
    pub threads: Option<usize>,
}

pub fn run_scan(args: ScanArgs) -> i32 {
    let rules_dir = args
        .rules
        .clone()
        .unwrap_or_else(|| PathBuf::from("rules"));

    let mut rule_files = Vec::new();
    if rules_dir.is_file() {
        rule_files.push(rules_dir.clone());
    } else if rules_dir.is_dir() {
        for entry in WalkDir::new(&rules_dir).into_iter().filter_map(|e| e.ok()) {
            if entry.path().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "raya" || ext == "yar" || ext == "yara" {
                        rule_files.push(entry.path().to_path_buf());
                    }
                }
            }
        }
    } else {
        eprintln!(
            "{} Rules path '{}' does not exist.",
            "ERROR:".red().bold(),
            rules_dir.display()
        );
        return 2;
    }

    if rule_files.is_empty() {
        eprintln!(
            "{} No rule files (.raya, .yar, .yara) found in '{}'.",
            "ERROR:".red().bold(),
            rules_dir.display()
        );
        return 2;
    }

    // Parse all rules
    let mut parsed_rules = Vec::new();
    for rf in &rule_files {
        match parse_rules_from_file(rf) {
            Ok(rules) => parsed_rules.extend(rules),
            Err(e) => {
                eprintln!(
                    "{} Failed to parse '{}': {}",
                    "ERROR:".red().bold(),
                    rf.display(),
                    e
                );
                return 2;
            }
        }
    }

    // Filter by tag if requested
    if let Some(ref target_tag) = args.tag {
        parsed_rules.retain(|r| r.tags.iter().any(|t| t.eq_ignore_ascii_case(target_tag)));
        if parsed_rules.is_empty() {
            eprintln!(
                "{} No rules matched tag '{}'.",
                "WARNING:".yellow().bold(),
                target_tag
            );
            return 0;
        }
    }

    let engine = match Engine::compile_rules(parsed_rules) {
        Ok(eng) => eng,
        Err(e) => {
            eprintln!("{} Failed to compile rules: {}", "ERROR:".red().bold(), e);
            return 2;
        }
    };

    if let Some(t) = args.threads {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(t)
            .build_global();
    }

    if args.target.is_file() {
        scan_single_file(&engine, &args.target, args.json, args.quiet)
    } else if args.target.is_dir() {
        scan_directory(&engine, &args.target, args.recursive, args.json, args.quiet)
    } else {
        eprintln!(
            "{} Target '{}' does not exist.",
            "ERROR:".red().bold(),
            args.target.display()
        );
        2
    }
}

fn scan_single_file(engine: &Engine, path: &Path, json: bool, quiet: bool) -> i32 {
    let result = match engine.scan_file(path) {
        Ok(res) => res,
        Err(e) => {
            eprintln!(
                "{} Failed to scan file '{}': {}",
                "ERROR:".red().bold(),
                path.display(),
                e
            );
            return 2;
        }
    };

    if json {
        match result.to_json(true) {
            Ok(j) => println!("{}", j),
            Err(e) => {
                eprintln!("{} Failed to serialize JSON: {}", "ERROR:".red().bold(), e);
                return 2;
            }
        }
    } else if quiet {
        if result.has_matches() {
            for m in &result.matches {
                println!("{}: {}", result.target, m.rule);
            }
        }
    } else {
        print!("{}", result.render_terminal());
    }

    if result.has_matches() {
        1
    } else {
        0
    }
}

fn scan_directory(
    engine: &Engine,
    dir: &Path,
    recursive: bool,
    json: bool,
    quiet: bool,
) -> i32 {
    let start_time = Instant::now();
    let walker = if recursive {
        WalkDir::new(dir)
    } else {
        WalkDir::new(dir).max_depth(1)
    };

    let target_files: Vec<PathBuf> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();

    let total_files = target_files.len();

    // Parallel scan using Rayon
    let scan_results: Vec<Result<ScanResult, (PathBuf, std::io::Error)>> = target_files
        .par_iter()
        .map(|path| match engine.scan_file(path) {
            Ok(res) => Ok(res),
            Err(e) => Err((path.clone(), e)),
        })
        .collect();

    let elapsed = start_time.elapsed();

    let mut matched_results = Vec::new();
    let mut errors = Vec::new();
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;
    let mut info_count = 0;

    for r in scan_results {
        match r {
            Ok(res) => {
                if res.has_matches() {
                    for m in &res.matches {
                        match m.severity {
                            Severity::Critical => critical_count += 1,
                            Severity::High => high_count += 1,
                            Severity::Medium => medium_count += 1,
                            Severity::Low => low_count += 1,
                            Severity::Info => info_count += 1,
                        }
                    }
                    matched_results.push(res);
                }
            }
            Err((path, err)) => {
                errors.push((path, err));
            }
        }
    }

    if json {
        let json_val = serde_json::json!({
            "directory": dir.display().to_string(),
            "total_files": total_files,
            "matched_files": matched_results.len(),
            "errors": errors.len(),
            "scan_time_ms": elapsed.as_secs_f64() * 1000.0,
            "severities": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "info": info_count,
            },
            "matches": matched_results,
        });
        println!("{}", serde_json::to_string_pretty(&json_val).unwrap_or_default());
    } else if quiet {
        for res in &matched_results {
            for m in &res.matches {
                println!("{}: {}", res.target, m.rule);
            }
        }
    } else {
        println!("\n=== Scan Summary for '{}' ===", dir.display().to_string().bold());
        println!("Files scanned:  {}", total_files);
        println!(
            "Matches:        {} file(s)",
            if !matched_results.is_empty() {
                matched_results.len().to_string().red().bold()
            } else {
                "0".green()
            }
        );
        if critical_count > 0 {
            println!("  Critical:     {}", critical_count.to_string().on_red().white().bold());
        }
        if high_count > 0 {
            println!("  High:         {}", high_count.to_string().red().bold());
        }
        if medium_count > 0 {
            println!("  Medium:       {}", medium_count.to_string().yellow().bold());
        }
        if low_count > 0 {
            println!("  Low:          {}", low_count.to_string().blue());
        }
        if info_count > 0 {
            println!("  Info:         {}", info_count.to_string().cyan());
        }
        if !errors.is_empty() {
            println!("Errors:         {}", errors.len().to_string().red());
        }
        println!("Scan time:      {:.2?}", elapsed);

        if !matched_results.is_empty() {
            println!("\n=== Detections ===");
            for res in &matched_results {
                println!("\n{}", res.render_terminal());
            }
        }
    }

    if !matched_results.is_empty() {
        1
    } else {
        0
    }
}
