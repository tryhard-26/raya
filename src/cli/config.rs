// src/cli/config.rs
//
// CLI command handler for `raya config <target>`
// Extracts and displays C2 configurations, botnet indicators, and crypto keys.

use crate::extractor::{extract_all_configs, ExtractedConfig};
use colored::Colorize;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

pub struct ConfigArgs {
    pub target: PathBuf,
    pub json: bool,
    pub password: Option<String>,
}

#[derive(Serialize)]
struct ConfigOutput<'a> {
    target: &'a str,
    configs: &'a [ExtractedConfig],
}

pub fn run_config(args: ConfigArgs) -> i32 {
    let target_path = &args.target;
    let data = match fs::read(target_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "{}: Failed to read target file: {}",
                "ERROR".red().bold(),
                e
            );
            return 1;
        }
    };

    let target_str = target_path.display().to_string();

    // Check if target is a ZIP archive
    if crate::archive::is_zip(&data) {
        if let Ok(entries) = crate::archive::extract_zip_bytes(&data, args.password.as_deref()) {
            if !entries.is_empty() {
                for entry in entries {
                    let label = format!("{} -> {}", target_str, entry.name);
                    extract_and_print(&label, &entry.data, args.json);
                }
                return 0;
            }
        }
    }

    extract_and_print(&target_str, &data, args.json);
    0
}

fn extract_and_print(target_str: &str, data: &[u8], json: bool) {
    let configs = extract_all_configs(data);

    if json {
        let out = ConfigOutput {
            target: target_str,
            configs: &configs,
        };
        if let Ok(json_str) = serde_json::to_string_pretty(&out) {
            println!("{}", json_str);
        }
        return;
    }

    println!("{}", "=".repeat(80).cyan());
    println!(
        "{} {}",
        "RAYA C2 CONFIGURATION EXTRACTOR:".cyan().bold(),
        target_str.bold()
    );
    println!("{}", "=".repeat(80).cyan());

    if configs.is_empty() {
        println!("{}", "[-] No embedded C2 configurations detected.".yellow());
        println!("{}", "=".repeat(80).cyan());
        return;
    }

    for cfg in &configs {
        println!(
            "\n{} {}",
            "[+] MALWARE FAMILY:".red().bold(),
            cfg.family.bold()
        );
        if !cfg.c2_servers.is_empty() {
            println!("    C2 Servers / Callbacks:");
            for s in &cfg.c2_servers {
                println!("      [-] {}", s.green().bold());
            }
        }
        if !cfg.ports.is_empty() {
            println!("    Ports: {:?}", cfg.ports);
        }
        if let Some(sleep) = cfg.sleep_time_ms {
            println!("    Sleep Time: {} ms", sleep);
        }
        if let Some(jitter) = cfg.jitter_percent {
            println!("    Jitter: {}%", jitter);
        }
        if let Some(ref ua) = cfg.user_agent {
            println!("    User-Agent: {}", ua);
        }
        if let Some(ref pipe) = cfg.pipe_name {
            println!("    Named Pipe: {}", pipe);
        }
        if let Some(wm) = cfg.watermark {
            println!("    Watermark ID: 0x{:08x} ({})", wm, wm);
        }
        if !cfg.crypto_keys.is_empty() {
            println!("    Extracted Cryptographic Keys / Passwords:");
            for k in &cfg.crypto_keys {
                println!("      [-] {}", k.yellow());
            }
        }
        if !cfg.dead_drop_resolvers.is_empty() {
            println!("    Dead-Drop Resolvers / Webhooks:");
            for r in &cfg.dead_drop_resolvers {
                println!("      [-] {}", r.cyan());
            }
        }
        if !cfg.extra.is_empty() {
            println!("    Additional Attributes:");
            for (k, v) in &cfg.extra {
                println!("      [-] {}: {}", k.bold(), v);
            }
        }
    }
    println!("\n{}", "=".repeat(80).cyan());
}
