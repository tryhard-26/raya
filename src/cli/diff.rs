// src/cli/diff.rs
//
// CLI command handler for `raya diff <file_a> <file_b>`
// Compares two binaries across CFG, sections, imports, and fuzzy hashes.

use crate::diff::diff_binaries;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

pub struct DiffArgs {
    pub file_a: PathBuf,
    pub file_b: PathBuf,
    pub json: bool,
}

pub fn run_diff(args: DiffArgs) -> i32 {
    let data_a = match fs::read(&args.file_a) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "{}: Failed to read file A ({}): {}",
                "ERROR".red().bold(),
                args.file_a.display(),
                e
            );
            return 1;
        }
    };

    let data_b = match fs::read(&args.file_b) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "{}: Failed to read file B ({}): {}",
                "ERROR".red().bold(),
                args.file_b.display(),
                e
            );
            return 1;
        }
    };

    let (data_a, name_a) = if crate::archive::is_zip(&data_a) {
        if let Ok(entries) = crate::archive::extract_zip_bytes(&data_a, None) {
            if let Some(first) = entries.into_iter().next() {
                (
                    first.data,
                    format!("{} -> {}", args.file_a.display(), first.name),
                )
            } else {
                (data_a, args.file_a.display().to_string())
            }
        } else {
            (data_a, args.file_a.display().to_string())
        }
    } else {
        (data_a, args.file_a.display().to_string())
    };

    let (data_b, name_b) = if crate::archive::is_zip(&data_b) {
        if let Ok(entries) = crate::archive::extract_zip_bytes(&data_b, None) {
            if let Some(first) = entries.into_iter().next() {
                (
                    first.data,
                    format!("{} -> {}", args.file_b.display(), first.name),
                )
            } else {
                (data_b, args.file_b.display().to_string())
            }
        } else {
            (data_b, args.file_b.display().to_string())
        }
    } else {
        (data_b, args.file_b.display().to_string())
    };

    let report = diff_binaries(&data_a, &data_b);

    if args.json {
        if let Ok(json_str) = serde_json::to_string_pretty(&report) {
            println!("{}", json_str);
        }
        return 0;
    }

    println!("{}", "=".repeat(80).cyan());
    println!(
        "{} {} vs {}",
        "RAYA BINARY & CFG PATCH DIFF REPORT:".bold().cyan(),
        name_a.yellow(),
        name_b.yellow()
    );
    println!("{}", "=".repeat(80).cyan());

    let sim_color = if report.similarity_score >= 85.0 {
        format!("{:.1}% (High Similarity)", report.similarity_score)
            .green()
            .bold()
    } else if report.similarity_score >= 50.0 {
        format!("{:.1}% (Moderate Divergence)", report.similarity_score)
            .yellow()
            .bold()
    } else {
        format!(
            "{:.1}% (Divergent / Different Families)",
            report.similarity_score
        )
        .red()
        .bold()
    };
    println!("COMPOSITE SIMILARITY SCORE: {}", sim_color);

    println!("\nFILE OVERVIEW:");
    println!(
        "  Target A: {:<12} bytes | {:<10} | Entropy: {:.2} | SHA256: {}...",
        report.file_a_metrics.size,
        report.file_a_metrics.format,
        report.file_a_metrics.entropy,
        &report.file_a_metrics.sha256[..16]
    );
    println!(
        "  Target B: {:<12} bytes | {:<10} | Entropy: {:.2} | SHA256: {}...",
        report.file_b_metrics.size,
        report.file_b_metrics.format,
        report.file_b_metrics.entropy,
        &report.file_b_metrics.sha256[..16]
    );

    println!("\nCONTROL FLOW GRAPH (CFG) COMPARISON:");
    println!(
        "  Basic Blocks:          {:<6} -> {:<6} ({:+})",
        report.cfg_diff.blocks_a, report.cfg_diff.blocks_b, report.cfg_diff.blocks_delta
    );
    println!(
        "  Directed Edges:        {:<6} -> {:<6} ({:+})",
        report.cfg_diff.edges_a, report.cfg_diff.edges_b, report.cfg_diff.edges_delta
    );
    println!(
        "  Cyclomatic Complexity: {:<6} -> {:<6} ({:+})",
        report.cfg_diff.complexity_a,
        report.cfg_diff.complexity_b,
        report.cfg_diff.complexity_delta
    );
    println!(
        "  Natural Loops:         {:<6} -> {:<6} ({:+})",
        report.cfg_diff.loops_a, report.cfg_diff.loops_b, report.cfg_diff.loops_delta
    );
    println!(
        "  CFF Obfuscation:       Target A: {:<5} | Target B: {:<5}",
        if report.cfg_diff.cff_obfuscation_a {
            "YES".red().bold()
        } else {
            "NO".normal()
        },
        if report.cfg_diff.cff_obfuscation_b {
            "YES".red().bold()
        } else {
            "NO".normal()
        }
    );
    println!(
        "  CFG Topological Match: {:.1}%",
        report.cfg_diff.cfg_similarity
    );

    println!("\nSECTION STRUCTURE DELTA:");
    println!(
        "  Common Sections:  {:?}",
        report.section_diff.common_sections
    );
    if !report.section_diff.added_sections.is_empty() {
        println!(
            "  Added in B:       {}",
            format!("{:?}", report.section_diff.added_sections).green()
        );
    }
    if !report.section_diff.removed_sections.is_empty() {
        println!(
            "  Removed from A:   {}",
            format!("{:?}", report.section_diff.removed_sections).red()
        );
    }
    for (name, ent_a, ent_b) in &report.section_diff.entropy_deltas {
        let delta = ent_b - ent_a;
        if delta.abs() > 0.3 {
            println!(
                "  Entropy Shift in {}: {:.2} -> {:.2} ({:+.2})",
                name.bold(),
                ent_a,
                ent_b,
                delta
            );
        }
    }

    println!("\nIMPORT TABLE SIMILARITY:");
    println!(
        "  Jaccard Index:    {:.1}%",
        report.import_diff.jaccard_similarity
    );
    println!("  Shared Imports:   {}", report.import_diff.common_imports);
    if !report.import_diff.added_imports.is_empty() {
        println!("  Added Imports (sample):");
        for imp in report.import_diff.added_imports.iter().take(5) {
            println!("    [-] + {}", imp.green());
        }
    }
    if !report.import_diff.removed_imports.is_empty() {
        println!("  Removed Imports (sample):");
        for imp in report.import_diff.removed_imports.iter().take(5) {
            println!("    [-] - {}", imp.red());
        }
    }

    if !report.structural_summary.is_empty() {
        println!("\nKEY STRUCTURAL DIVERGENCES:");
        for summary in &report.structural_summary {
            println!("  [!] {}", summary.yellow());
        }
    }

    println!("\n{}", "=".repeat(80).cyan());
    0
}
