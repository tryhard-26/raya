use crate::engine::CompiledRulePatterns;
use crate::parser::parse_rules_from_file;
use colored::Colorize;
use std::path::PathBuf;
use walkdir::WalkDir;

pub struct CheckArgs {
    pub path: PathBuf,
    pub verbose: bool,
}

pub fn run_check(args: CheckArgs) -> i32 {
    let mut files_to_check = Vec::new();

    if args.path.is_file() {
        files_to_check.push(args.path.clone());
    } else if args.path.is_dir() {
        for entry in WalkDir::new(&args.path).into_iter().filter_map(|e| e.ok()) {
            if entry.path().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "raya" || ext == "yar" || ext == "yara" {
                        files_to_check.push(entry.path().to_path_buf());
                    }
                }
            }
        }
    } else {
        eprintln!(
            "{} Path '{}' does not exist.",
            "ERROR:".red().bold(),
            args.path.display()
        );
        return 2;
    }

    if files_to_check.is_empty() {
        eprintln!(
            "{} No rule files (.raya, .yar, .yara) found in '{}'.",
            "ERROR:".red().bold(),
            args.path.display()
        );
        return 2;
    }

    println!(
        "\nValidating {} rule file(s) in '{}'...\n",
        files_to_check.len(),
        args.path.display()
    );

    let mut total_rules = 0;
    let mut total_passed = 0;
    let mut total_failed = 0;

    for file_path in &files_to_check {
        match parse_rules_from_file(file_path) {
            Ok(rules) => {
                for rule in rules {
                    total_rules += 1;
                    // Validate string patterns compile
                    match CompiledRulePatterns::compile(&rule.strings) {
                        Ok(_) => {
                            total_passed += 1;
                            if args.verbose {
                                println!(
                                    "  [{}] rule '{}' in {}",
                                    "PASS".green().bold(),
                                    rule.name.bold(),
                                    file_path.display()
                                );
                            }
                        }
                        Err(e) => {
                            total_failed += 1;
                            println!(
                                "  [{}] rule '{}' in {}: {}",
                                "FAIL".red().bold(),
                                rule.name.bold(),
                                file_path.display(),
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                total_failed += 1;
                println!(
                    "  [{}] file {}: {}",
                    "FAIL".red().bold(),
                    file_path.display().to_string().bold(),
                    e
                );
            }
        }
    }

    println!("\n=== Validation Summary ===");
    println!("Files checked:   {}", files_to_check.len());
    println!("Rules verified:  {}", total_rules);
    println!("Passed:          {}", total_passed.to_string().green());
    println!(
        "Failed:          {}",
        if total_failed > 0 {
            total_failed.to_string().red().bold()
        } else {
            "0".normal()
        }
    );

    if total_failed > 0 {
        2
    } else {
        println!("\n{}", "✓ All rules validated successfully.".green().bold());
        0
    }
}
