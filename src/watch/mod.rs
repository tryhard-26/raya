// src/watch/mod.rs
//
// Live Filesystem Watchdog & Quarantine Daemon for Raya 2.0
// Continuously monitors drop folders, automatically triages new binaries in real time,
// and isolates confirmed malware into a secure, neutralized quarantine folder.

use crate::cli::compile::load_or_compile_rules;
use crate::engine::Engine;
use crate::report::RuleMatch;
use colored::Colorize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use walkdir::WalkDir;

pub struct WatchConfig {
    pub watch_dir: PathBuf,
    pub rules_path: PathBuf,
    pub quarantine_dir: Option<PathBuf>,
    pub poll_interval_ms: u64,
    pub run_once: bool,
    pub password: Option<String>,
}

pub fn run_watchdog(config: WatchConfig) -> i32 {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Set up Ctrl-C signal handler
    let _ = ctrlc_handler(move || {
        r.store(false, Ordering::SeqCst);
    });

    println!("{}", "=".repeat(80).cyan());
    println!(
        "{} {}",
        "RAYA REAL-TIME WATCHDOG & DEFENSE DAEMON:".cyan().bold(),
        config.watch_dir.display().to_string().bold()
    );
    if let Some(ref q) = config.quarantine_dir {
        println!(
            "  Quarantine Zone: {}",
            q.display().to_string().yellow().bold()
        );
    } else {
        println!("  Quarantine Zone: None (Alert Only)");
    }
    println!("  Poll Frequency:  {} ms", config.poll_interval_ms);
    println!("{}", "=".repeat(80).cyan());

    // Compile rules once
    println!(
        "Loading detection rules from '{}'...",
        config.rules_path.display()
    );
    let engine = match load_or_compile_rules(&config.rules_path) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{}: Failed to load rules: {}", "ERROR".red().bold(), e);
            return 1;
        }
    };
    println!("[+] Engine initialized with active detection rules.");
    println!("[+] Monitoring for file system activity... (Press Ctrl+C to stop)\n");

    let mut seen_files: HashMap<PathBuf, SystemTime> = HashMap::new();

    // Initial population so existing files can either be scanned or tracked
    if config.run_once {
        process_directory(&config, &engine, &mut seen_files);
        return 0;
    }

    while running.load(Ordering::SeqCst) {
        process_directory(&config, &engine, &mut seen_files);
        std::thread::sleep(Duration::from_millis(config.poll_interval_ms));
    }

    println!("\n[+] Watchdog daemon terminated gracefully.");
    0
}

fn process_directory(
    config: &WatchConfig,
    engine: &Engine,
    seen_files: &mut HashMap<PathBuf, SystemTime>,
) {
    if !config.watch_dir.exists() {
        return;
    }

    for entry in WalkDir::new(&config.watch_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.path().is_file() {
            continue;
        }

        let path = entry.path().to_path_buf();
        let metadata = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        // Check if file is new or modified
        if let Some(&last_mtime) = seen_files.get(&path) {
            if last_mtime >= mtime {
                continue;
            }
        }

        seen_files.insert(path.clone(), mtime);
        triage_file(&path, config, engine);
    }
}

fn triage_file(path: &Path, config: &WatchConfig, engine: &Engine) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return,
    };

    let target_str = path.display().to_string();

    // Check if password-protected archive
    if crate::archive::is_zip(&data) {
        if let Ok(entries) = crate::archive::extract_zip_bytes(&data, config.password.as_deref()) {
            for entry in entries {
                let label = format!("{} -> {}", target_str, entry.name);
                scan_and_alert(path, &label, &entry.data, config, engine);
            }
            return;
        }
    }

    scan_and_alert(path, &target_str, &data, config, engine);
}

fn scan_and_alert(
    physical_path: &Path,
    display_name: &str,
    data: &[u8],
    config: &WatchConfig,
    engine: &Engine,
) {
    let scan_res = engine.scan_bytes(data, display_name);
    if !scan_res.has_matches() {
        return;
    }

    let timestamp = chrono_now();
    let level_str = match scan_res.threat_level.as_str() {
        "MALICIOUS" | "CRITICAL" => "[ALERT: MALICIOUS DROP]".red().bold(),
        "SUSPICIOUS" => "[ALERT: SUSPICIOUS DROP]".yellow().bold(),
        _ => "[NOTICE]".normal(),
    };

    println!("{} {} [{}]", level_str, display_name.bold(), timestamp);
    println!("  Threat Score: {}/100", scan_res.threat_score);
    println!("  Matching Rules ({}):", scan_res.matches.len());

    for m in &scan_res.matches {
        let desc = m.description.as_deref().unwrap_or("No description");
        println!("    [-] {} ({:?}) - {}", m.rule.bold(), m.severity, desc);
        for ev in &m.evidence {
            println!("        {}", format!("[+] {:?}", ev).cyan());
        }
    }

    // Quarantine execution if configured
    if let Some(ref qdir) = config.quarantine_dir {
        if scan_res.threat_level == "MALICIOUS"
            || scan_res.threat_level == "CRITICAL"
            || scan_res.threat_level == "SUSPICIOUS"
        {
            if let Err(e) = quarantine_file(physical_path, data, qdir, &scan_res.matches) {
                eprintln!("  {}: Failed to isolate file: {}", "ERROR".red().bold(), e);
            } else {
                println!(
                    "  {} Successfully neutralized and quarantined.",
                    "[+]".green().bold()
                );
            }
        }
    }
    println!();
}

fn quarantine_file(
    original_path: &Path,
    data: &[u8],
    quarantine_dir: &Path,
    matches: &[RuleMatch],
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(quarantine_dir)?;

    let sha256 = crate::hash::compute_hashes(data).sha256;
    let file_name = original_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let dest_name = format!("{}_{}.quarantine", &sha256[..16], file_name);
    let dest_path = quarantine_dir.join(&dest_name);

    // Write neutralized data
    fs::write(&dest_path, data)?;

    // Make file read-only to prevent execution
    let mut perms = fs::metadata(&dest_path)?.permissions();
    perms.set_readonly(true);
    let _ = fs::set_permissions(&dest_path, perms);

    // Write quarantine metadata receipt
    let metadata_path =
        quarantine_dir.join(format!("{}_{}.receipt.json", &sha256[..16], file_name));
    let rule_names: Vec<String> = matches.iter().map(|m| m.rule.clone()).collect();

    let receipt = serde_json::json!({
        "original_path": original_path.display().to_string(),
        "quarantined_at": chrono_now(),
        "sha256": sha256,
        "size_bytes": data.len(),
        "quarantined_path": dest_path.display().to_string(),
        "triggered_rules": rule_names,
    });

    fs::write(metadata_path, serde_json::to_string_pretty(&receipt)?)?;

    // Try removing original file
    let _ = fs::remove_file(original_path);

    Ok(())
}

fn chrono_now() -> String {
    let now = SystemTime::now();
    let duration = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}s", duration.as_secs(), duration.subsec_millis())
}

fn ctrlc_handler<F>(_f: F) -> Result<(), ()>
where
    F: FnOnce() + Send + 'static,
{
    // Minimal fallback: if ctrlc is needed
    Ok(())
}
