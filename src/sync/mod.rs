// src/sync/mod.rs
//
// Threat Intel Community Rule Feed Sync for Raya 2.0
// Synchronizes, transpiles, and precompiles trusted external detection feeds
// (Signature-Base, YARA-Rules, CISA) into zero-overhead native rule caches.

use crate::cli::convert::transpile_yara_to_raya;
use crate::engine::Engine;
use crate::parser::parse_rules_from_file;
use colored::Colorize;
use std::fs;
use std::path::{Path, PathBuf};

pub struct SyncConfig {
    pub feed_name_or_url: String,
    pub output_dir: PathBuf,
    pub compile_cache: bool,
}

pub struct FeedSource {
    pub name: &'static str,
    pub description: &'static str,
    pub sample_urls: &'static [&'static str],
}

pub const KNOWN_FEEDS: &[FeedSource] = &[
    FeedSource {
        name: "signature-base",
        description: "Florian Roth (Neo23x0) Signature-Base APT & Ransomware Rules",
        sample_urls: &[
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_mal_indicators.yar",
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_wannacry.yar",
        ],
    },
    FeedSource {
        name: "yara-rules",
        description: "YARA-Rules Official Community Malware Detection Feed",
        sample_urls: &[
            "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_WannaCry.yar",
            "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Mirai.yar",
        ],
    },
];

pub fn run_sync(config: SyncConfig) -> i32 {
    println!("{}", "=".repeat(80).cyan());
    println!(
        "{} {}",
        "RAYA THREAT INTEL RULE FEED SYNC:".cyan().bold(),
        config.feed_name_or_url.bold()
    );
    println!(
        "  Destination Directory: {}",
        config.output_dir.display().to_string().cyan()
    );
    println!("{}", "=".repeat(80).cyan());

    if let Err(e) = fs::create_dir_all(&config.output_dir) {
        eprintln!(
            "{}: Failed to create output directory {}: {}",
            "ERROR".red().bold(),
            config.output_dir.display(),
            e
        );
        return 1;
    }

    let mut urls_to_fetch = Vec::new();

    // Check if feed name matches a preset
    let feed_lower = config.feed_name_or_url.to_lowercase();
    if let Some(preset) = KNOWN_FEEDS.iter().find(|f| f.name == feed_lower) {
        println!(
            "[+] Selected feed preset: {} ({})",
            preset.name.bold(),
            preset.description
        );
        for &u in preset.sample_urls {
            urls_to_fetch.push(u.to_string());
        }
    } else if config.feed_name_or_url.starts_with("http://")
        || config.feed_name_or_url.starts_with("https://")
    {
        urls_to_fetch.push(config.feed_name_or_url.clone());
    } else {
        // Assume local folder or wildcard
        let local_path = Path::new(&config.feed_name_or_url);
        if local_path.is_dir() {
            return sync_local_directory(local_path, &config.output_dir, config.compile_cache);
        } else {
            eprintln!(
                "{}: Unknown feed preset or invalid URL/path: '{}'",
                "ERROR".red().bold(),
                config.feed_name_or_url
            );
            println!("\nAvailable presets:");
            for f in KNOWN_FEEDS {
                println!("  - {:<18} ({})", f.name.bold(), f.description);
            }
            return 1;
        }
    }

    let mut synced_count = 0;
    let mut transpiled_count = 0;

    for url in urls_to_fetch {
        println!("Fetching {} ...", url);
        match ureq::get(&url)
            .timeout(std::time::Duration::from_secs(10))
            .call()
        {
            Ok(resp) => {
                if let Ok(body) = resp.into_string() {
                    let file_name = url.rsplit('/').next().unwrap_or("feed_rule.yar");
                    let dest_file = config.output_dir.join(file_name);

                    // Transpile if YARA
                    let final_content =
                        if file_name.ends_with(".yar") || file_name.ends_with(".yara") {
                            transpiled_count += 1;
                            transpile_yara_to_raya(&body)
                        } else {
                            body
                        };

                    let raya_filename =
                        if dest_file.extension().and_then(|e| e.to_str()) == Some("yar") {
                            dest_file.with_extension("raya")
                        } else {
                            dest_file
                        };

                    if let Err(e) = fs::write(&raya_filename, final_content) {
                        eprintln!(
                            "  {}: Failed to save {}: {}",
                            "ERROR".red(),
                            raya_filename.display(),
                            e
                        );
                    } else {
                        println!(
                            "  [+] Successfully synchronized and transpiled to '{}'",
                            raya_filename
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                        );
                        synced_count += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "  {}: Failed to download {}: {}",
                    "WARNING".yellow().bold(),
                    url,
                    e
                );
            }
        }
    }

    if config.compile_cache && synced_count > 0 {
        compile_synced_directory(&config.output_dir);
    }

    println!("\n=== Threat Intelligence Sync Summary ===");
    println!("Files Synced:      {}", synced_count);
    println!("Rules Transpiled:  {}", transpiled_count);
    println!("{}", "=".repeat(80).cyan());

    0
}

fn sync_local_directory(src_dir: &Path, dst_dir: &Path, compile_cache: bool) -> i32 {
    let mut count = 0;
    for entry in walkdir::WalkDir::new(src_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().is_file() {
            let ext = entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if ext == "yar" || ext == "yara" || ext == "raya" {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    let out_name = entry
                        .path()
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy();
                    let dst_path = dst_dir.join(format!("{}.raya", out_name));
                    let transpiled = transpile_yara_to_raya(&content);
                    let _ = fs::write(dst_path, transpiled);
                    count += 1;
                }
            }
        }
    }
    println!(
        "[+] Synced and transpiled {} local rule files to '{}'.",
        count,
        dst_dir.display()
    );
    if compile_cache {
        compile_synced_directory(dst_dir);
    }
    0
}

fn compile_synced_directory(dir: &Path) {
    let cache_path = dir.join("rules.rcache");
    println!(
        "Precompiling synchronized rules to '{}'...",
        cache_path.display()
    );

    let mut all_rules = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().is_file() {
            let ext = entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if ext == "raya" {
                if let Ok(rules) = parse_rules_from_file(entry.path()) {
                    all_rules.extend(rules);
                }
            }
        }
    }

    if !all_rules.is_empty() {
        if let Ok(engine) = Engine::compile_rules(all_rules) {
            if engine.save_compiled_rules(&cache_path).is_ok() {
                println!(
                    "[+] Rule cache '{}' ready for instant startup.",
                    cache_path.display().to_string().green()
                );
            }
        }
    }
}
