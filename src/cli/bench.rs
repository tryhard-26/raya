use crate::engine::Engine;
use crate::parser::parse_rules_from_file;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use walkdir::WalkDir;

pub struct BenchArgs {
    pub target: PathBuf,
    pub rules: Option<PathBuf>,
    pub iterations: usize,
}

pub fn run_bench(args: BenchArgs) -> i32 {
    let rules_dir = args.rules.clone().unwrap_or_else(|| PathBuf::from("rules"));

    let mut rule_files = Vec::new();
    if rules_dir.is_file() {
        rule_files.push(rules_dir);
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

    let compile_start = Instant::now();
    let mut parsed_rules = Vec::new();
    for rf in &rule_files {
        if let Ok(rules) = parse_rules_from_file(rf) {
            parsed_rules.extend(rules);
        }
    }
    let total_rule_count = parsed_rules.len();
    let engine = match Engine::compile_rules(parsed_rules) {
        Ok(eng) => eng,
        Err(e) => {
            eprintln!("{} Failed to compile rules: {}", "ERROR:".red().bold(), e);
            return 2;
        }
    };
    let compile_duration = compile_start.elapsed();

    // Collect target payload or files
    let mut files_to_scan = Vec::new();
    let mut total_bytes: u64 = 0;

    if args.target.is_file() {
        if let Ok(meta) = fs::metadata(&args.target) {
            total_bytes += meta.len();
            files_to_scan.push(args.target.clone());
        }
    } else if args.target.is_dir() {
        for entry in WalkDir::new(&args.target)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.path().is_file() {
                if let Ok(meta) = entry.metadata() {
                    total_bytes += meta.len();
                    files_to_scan.push(entry.path().to_path_buf());
                }
            }
        }
    } else {
        eprintln!(
            "{} Target '{}' does not exist.",
            "ERROR:".red().bold(),
            args.target.display()
        );
        return 2;
    }

    if files_to_scan.is_empty() {
        eprintln!("{} No files found to benchmark.", "ERROR:".red().bold());
        return 2;
    }

    println!("\n=== Raya Performance Benchmark ===");
    println!("Target:               {}", args.target.display());
    println!("Files in dataset:     {}", files_to_scan.len());
    println!(
        "Dataset total size:   {:.2} MB",
        total_bytes as f64 / (1024.0 * 1024.0)
    );
    println!("Rules loaded:         {}", total_rule_count);
    println!("Rule compile time:    {:.2?}", compile_duration);
    println!("Benchmark iterations: {}", args.iterations);
    println!("\nExecuting benchmark runs...\n");

    let mut iteration_durations = Vec::with_capacity(args.iterations);

    for _ in 0..args.iterations {
        let run_start = Instant::now();
        for file in &files_to_scan {
            let _ = engine.scan_file(file);
        }
        iteration_durations.push(run_start.elapsed());
    }

    let avg_duration_secs: f64 = iteration_durations
        .iter()
        .map(|d| d.as_secs_f64())
        .sum::<f64>()
        / (args.iterations as f64);

    let total_mb = (total_bytes as f64) / (1024.0 * 1024.0);
    let throughput_mb_per_sec = total_mb / avg_duration_secs;
    let files_per_sec = (files_to_scan.len() as f64) / avg_duration_secs;
    let avg_ms_per_file = (avg_duration_secs * 1000.0) / (files_to_scan.len() as f64);

    println!("=== Benchmark Results ===");
    println!("Average scan time:    {:.3} s", avg_duration_secs);
    println!(
        "Throughput:           {} MB/s",
        format!("{:.2}", throughput_mb_per_sec).green().bold()
    );
    println!(
        "Files scanned / sec:  {} files/s",
        format!("{:.1}", files_per_sec).cyan().bold()
    );
    println!("Average latency/file: {:.3} ms", avg_ms_per_file);

    0
}
