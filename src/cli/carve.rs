// src/cli/carve.rs
//
// CLI command handler for `raya carve <target> -o <out_dir>`
// Carves and extracts nested executables, overlays, and archives to disk.

use crate::carve::carve_artifacts;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

pub struct CarveArgs {
    pub target: PathBuf,
    pub output_dir: Option<PathBuf>,
    pub json: bool,
}

pub fn run_carve(args: CarveArgs) -> i32 {
    let data = match fs::read(&args.target) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "{}: Failed to read target file {}: {}",
                "ERROR".red().bold(),
                args.target.display(),
                e
            );
            return 1;
        }
    };

    let artifacts = carve_artifacts(&data);

    if let Some(ref out_dir) = args.output_dir {
        if let Err(e) = fs::create_dir_all(out_dir) {
            eprintln!(
                "{}: Failed to create output directory {}: {}",
                "ERROR".red().bold(),
                out_dir.display(),
                e
            );
            return 1;
        }

        for art in &artifacts {
            let file_path = out_dir.join(&art.filename);
            if let Err(e) = fs::write(&file_path, &art.data) {
                eprintln!(
                    "{}: Failed to write carved artifact {}: {}",
                    "ERROR".red().bold(),
                    file_path.display(),
                    e
                );
            }
        }
    }

    if args.json {
        if let Ok(json_str) = serde_json::to_string_pretty(&artifacts) {
            println!("{}", json_str);
        }
        return 0;
    }

    println!("{}", "=".repeat(80).cyan());
    println!(
        "{} {}",
        "RAYA ARTIFACT & OVERLAY CARVER:".cyan().bold(),
        args.target.display().to_string().bold()
    );
    println!("{}", "=".repeat(80).cyan());

    if artifacts.is_empty() {
        println!(
            "{}",
            "[-] No embedded executables, archives, or overlay payloads discovered.".yellow()
        );
        println!("{}", "=".repeat(80).cyan());
        return 0;
    }

    println!("DISCOVERED CARVED ARTIFACTS: {}", artifacts.len());
    for (i, art) in artifacts.iter().enumerate() {
        println!(
            "\n[{}] {} ({})",
            i + 1,
            art.filename.bold(),
            art.format.green().bold()
        );
        println!("    Offset:    0x{:08x} ({} bytes)", art.offset, art.offset);
        println!("    Size:      {} bytes", art.size);
        println!("    Entropy:   {:.4}", art.entropy);
        println!("    SHA-256:   {}", art.sha256);
        if let Some(ref out_dir) = args.output_dir {
            println!(
                "    Extracted: {}",
                out_dir.join(&art.filename).display().to_string().cyan()
            );
        }
    }

    if args.output_dir.is_none() {
        println!(
            "\n{}",
            "Tip: Specify '-o <output_directory>' to extract carved artifacts to disk.".italic()
        );
    }

    println!("\n{}", "=".repeat(80).cyan());
    0
}
