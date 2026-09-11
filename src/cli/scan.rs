use crate::ast::Severity;
use crate::cli::compile::load_or_compile_rules;
use crate::cli::process::scan_process_memory;
use crate::engine::Engine;
use crate::report::{to_sarif, to_stix, ScanResult};
use colored::Colorize;
use rayon::prelude::*;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

pub struct ScanArgs {
    pub target: Option<PathBuf>,
    pub rules: Option<PathBuf>,
    pub recursive: bool,
    pub json: bool,
    pub quiet: bool,
    pub tag: Option<String>,
    pub threads: Option<usize>,
    pub pid: Option<u32>,
    pub format: Option<String>,
    pub password: Option<String>,
}

pub fn run_scan(args: ScanArgs) -> i32 {
    let rules_dir = args.rules.clone().unwrap_or_else(|| PathBuf::from("rules"));

    let engine = match load_or_compile_rules(&rules_dir) {
        Ok(mut eng) => {
            if let Some(ref target_tag) = args.tag {
                eng.rules.retain(|r| {
                    r.rule
                        .tags
                        .iter()
                        .any(|t| t.eq_ignore_ascii_case(target_tag))
                });
                if eng.rules.is_empty() {
                    eprintln!(
                        "{} No rules matched tag '{}'.",
                        "WARNING:".yellow().bold(),
                        target_tag
                    );
                    return 0;
                }
            }
            eng
        }
        Err(e) => {
            eprintln!("{} {}", "ERROR:".red().bold(), e);
            return 2;
        }
    };

    if let Some(t) = args.threads {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(t)
            .build_global();
    }

    // Process memory scan if PID provided
    if let Some(pid) = args.pid {
        return scan_process_memory(&engine, pid, args.json, args.quiet, args.format.as_deref());
    }

    // Check target: stdin vs file vs directory
    let target = match args.target {
        Some(ref t) if t == Path::new("-") => {
            return scan_stdin(&engine, args.json, args.quiet, args.format.as_deref());
        }
        Some(t) => t,
        None => {
            return scan_stdin(&engine, args.json, args.quiet, args.format.as_deref());
        }
    };

    if target.is_file() {
        scan_single_file(
            &engine,
            &target,
            args.json,
            args.quiet,
            args.format.as_deref(),
            args.password.as_deref(),
        )
    } else if target.is_dir() {
        scan_directory(
            &engine,
            &target,
            args.recursive,
            args.json,
            args.quiet,
            args.format.as_deref(),
            args.password.as_deref(),
        )
    } else {
        eprintln!(
            "{} Target '{}' does not exist.",
            "ERROR:".red().bold(),
            target.display()
        );
        2
    }
}

fn scan_stdin(engine: &Engine, json: bool, quiet: bool, format: Option<&str>) -> i32 {
    let mut buffer = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut buffer) {
        eprintln!("{} Failed to read stdin: {}", "ERROR:".red().bold(), e);
        return 2;
    }
    let result = engine.scan_bytes(&buffer, "stdin");
    render_single_result(&result, json, quiet, format)
}

fn scan_single_file(
    engine: &Engine,
    path: &Path,
    json: bool,
    quiet: bool,
    format: Option<&str>,
    password: Option<&str>,
) -> i32 {
    let data = match std::fs::read(path) {
        Ok(d) => d,
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

    if crate::archive::is_zip(&data) {
        if let Ok(entries) = crate::archive::extract_zip_bytes(&data, password) {
            if !entries.is_empty() {
                let nested_results: Vec<ScanResult> = entries
                    .into_iter()
                    .map(|entry| {
                        let label = format!("{} -> {}", path.display(), entry.name);
                        engine.scan_bytes(&entry.data, &label)
                    })
                    .collect();

                return render_multi_results(&nested_results, json, quiet, format);
            }
        }
    }

    let result = engine.scan_bytes(&data, &path.display().to_string());
    render_single_result(&result, json, quiet, format)
}

fn render_multi_results(
    results: &[ScanResult],
    json: bool,
    quiet: bool,
    format: Option<&str>,
) -> i32 {
    if results.len() == 1 {
        return render_single_result(&results[0], json, quiet, format);
    }

    let fmt = format.unwrap_or(if json { "json" } else { "text" });

    match fmt {
        "sarif" => match to_sarif(results) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("{} Failed to serialize SARIF: {}", "ERROR:".red().bold(), e);
                return 2;
            }
        },
        "stix" => match to_stix(results) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("{} Failed to serialize STIX: {}", "ERROR:".red().bold(), e);
                return 2;
            }
        },
        "json" => match serde_json::to_string_pretty(results) {
            Ok(j) => println!("{}", j),
            Err(e) => {
                eprintln!("{} Failed to serialize JSON: {}", "ERROR:".red().bold(), e);
                return 2;
            }
        },
        _ => {
            if quiet {
                for res in results {
                    if res.has_matches() {
                        for m in &res.matches {
                            println!("{}: {}", res.target, m.rule);
                        }
                    }
                }
            } else {
                for res in results {
                    print!("{}", res.render_terminal());
                }
            }
        }
    }

    if results.iter().any(|r| r.has_matches()) {
        1
    } else {
        0
    }
}

fn render_single_result(result: &ScanResult, json: bool, quiet: bool, format: Option<&str>) -> i32 {
    let fmt = format.unwrap_or(if json { "json" } else { "text" });

    match fmt {
        "pdf" => {
            let json_str = match result.to_json(true) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("{} Failed to serialize JSON: {}", "ERROR:".red().bold(), e);
                    return 2;
                }
            };
            let out_file = format!(
                "raya_report_{}.pdf",
                &result.hashes.sha256[..12.min(result.hashes.sha256.len())]
            );
            let py_paths = ["/tmp/raya_venv/bin/python3", "python3"];
            let mut generated = false;
            for py in &py_paths {
                if let Ok(mut child) = std::process::Command::new(py)
                    .arg("scripts/generate_pdf_report.py")
                    .arg("--output")
                    .arg(&out_file)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::inherit())
                    .spawn()
                {
                    if let Some(mut stdin) = child.stdin.take() {
                        use std::io::Write;
                        let _ = stdin.write_all(json_str.as_bytes());
                    }
                    if let Ok(status) = child.wait() {
                        if status.success() {
                            generated = true;
                            break;
                        }
                    }
                }
            }
            if !generated {
                eprintln!(
                    "{} Failed to generate PDF report using scripts/generate_pdf_report.py",
                    "ERROR:".red().bold()
                );
                return 2;
            }
        }
        "sarif" => match to_sarif(std::slice::from_ref(result)) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("{} Failed to serialize SARIF: {}", "ERROR:".red().bold(), e);
                return 2;
            }
        },
        "stix" => match to_stix(std::slice::from_ref(result)) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("{} Failed to serialize STIX: {}", "ERROR:".red().bold(), e);
                return 2;
            }
        },
        "json" => match result.to_json(true) {
            Ok(j) => println!("{}", j),
            Err(e) => {
                eprintln!("{} Failed to serialize JSON: {}", "ERROR:".red().bold(), e);
                return 2;
            }
        },
        _ => {
            if quiet {
                if result.has_matches() {
                    for m in &result.matches {
                        println!("{}: {}", result.target, m.rule);
                    }
                }
            } else {
                print!("{}", result.render_terminal());
            }
        }
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
    format: Option<&str>,
    password: Option<&str>,
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

    // Parallel scan using Rayon with transparent archive inspection
    let scan_results: Vec<Result<ScanResult, (PathBuf, std::io::Error)>> = target_files
        .par_iter()
        .flat_map(|path| match std::fs::read(path) {
            Ok(data) => {
                if crate::archive::is_zip(&data) {
                    if let Ok(entries) = crate::archive::extract_zip_bytes(&data, password) {
                        if !entries.is_empty() {
                            return entries
                                .into_iter()
                                .map(|entry| {
                                    let label = format!("{} -> {}", path.display(), entry.name);
                                    Ok(engine.scan_bytes(&entry.data, &label))
                                })
                                .collect::<Vec<_>>();
                        }
                    }
                }
                vec![Ok(engine.scan_bytes(&data, &path.display().to_string()))]
            }
            Err(e) => vec![Err((path.clone(), e))],
        })
        .collect();

    let total_files = scan_results.len();
    let elapsed = start_time.elapsed();

    let mut matched_results = Vec::new();
    let mut all_results = Vec::new();
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
                    matched_results.push(res.clone());
                }
                all_results.push(res);
            }
            Err((path, err)) => {
                errors.push((path, err));
            }
        }
    }

    let fmt = format.unwrap_or(if json { "json" } else { "text" });

    match fmt {
        "sarif" => match to_sarif(&matched_results) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("{} Failed to serialize SARIF: {}", "ERROR:".red().bold(), e);
                return 2;
            }
        },
        "stix" => match to_stix(&matched_results) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("{} Failed to serialize STIX: {}", "ERROR:".red().bold(), e);
                return 2;
            }
        },
        "json" => match serde_json::to_string_pretty(&matched_results) {
            Ok(j) => println!("{}", j),
            Err(e) => {
                eprintln!("{} Failed to serialize JSON: {}", "ERROR:".red().bold(), e);
                return 2;
            }
        },
        _ => {
            if quiet {
                for res in &matched_results {
                    for m in &res.matches {
                        println!("{}: {}", res.target, m.rule);
                    }
                }
            } else {
                for res in &matched_results {
                    print!("{}", res.render_terminal());
                }

                println!("\n{}", "=== Scan Summary ===".bold());
                println!("Files scanned:  {}", total_files);
                println!(
                    "Matches:        {}",
                    if matched_results.is_empty() {
                        "0 file(s)".green().bold()
                    } else {
                        format!("{} file(s)", matched_results.len()).red().bold()
                    }
                );
                if !matched_results.is_empty() {
                    println!(
                        "Severity:       {} critical, {} high, {} medium, {} low, {} info",
                        critical_count.to_string().red().bold(),
                        high_count.to_string().bright_red().bold(),
                        medium_count.to_string().yellow().bold(),
                        low_count.to_string().blue(),
                        info_count.to_string().cyan()
                    );
                }
                println!("Scan duration:  {:.3}s", elapsed.as_secs_f64());

                if !errors.is_empty() {
                    println!(
                        "\n{} Encountered {} file read error(s):",
                        "WARNING:".yellow().bold(),
                        errors.len()
                    );
                    for (path, err) in errors.iter().take(5) {
                        println!("  {}: {}", path.display(), err);
                    }
                    if errors.len() > 5 {
                        println!("  ... and {} more", errors.len() - 5);
                    }
                }
            }
        }
    }

    if matched_results.is_empty() {
        0
    } else {
        1
    }
}
