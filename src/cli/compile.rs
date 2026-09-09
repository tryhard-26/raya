use crate::engine::Engine;
use crate::parser::parse_rules_from_file;
use colored::Colorize;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct CompileArgs {
    pub rules: PathBuf,
    pub output: PathBuf,
}

pub fn run_compile(args: CompileArgs) -> i32 {
    let mut rule_files = Vec::new();
    let rules_path = &args.rules;

    if rules_path.is_file() {
        rule_files.push(rules_path.clone());
    } else if rules_path.is_dir() {
        for entry in WalkDir::new(rules_path).into_iter().filter_map(|e| e.ok()) {
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
            rules_path.display()
        );
        return 2;
    }

    if rule_files.is_empty() {
        eprintln!(
            "{} No rule files (.raya, .yar, .yara) found in '{}'.",
            "ERROR:".red().bold(),
            rules_path.display()
        );
        return 2;
    }

    let mut parsed_rules = Vec::new();
    for rf in &rule_files {
        match parse_rules_from_file(rf) {
            Ok(rules) => parsed_rules.extend(rules),
            Err(e) => {
                eprintln!(
                    "{} Failed to parse rule '{}': {}",
                    "ERROR:".red().bold(),
                    rf.display(),
                    e
                );
                return 2;
            }
        }
    }

    let rule_count = parsed_rules.len();
    let engine = match Engine::compile_rules(parsed_rules) {
        Ok(eng) => eng,
        Err(e) => {
            eprintln!("{} Failed to compile rules: {}", "ERROR:".red().bold(), e);
            return 2;
        }
    };

    if let Err(e) = engine.save_compiled_rules(&args.output) {
        eprintln!(
            "{} Failed to save compiled rules to '{}': {}",
            "ERROR:".red().bold(),
            args.output.display(),
            e
        );
        return 2;
    }

    println!(
        "{} Successfully compiled {} rules into '{}'.",
        "SUCCESS:".green().bold(),
        rule_count,
        args.output.display()
    );

    0
}

pub fn load_or_compile_rules(rules_path: &Path) -> Result<Engine, String> {
    if rules_path.is_file() {
        if let Some(ext) = rules_path.extension() {
            if ext == "rc" || ext == "bin" {
                return Engine::load_compiled_rules(rules_path)
                    .map_err(|e| format!("Failed to load precompiled rules: {}", e));
            }
        }
    }

    let mut rule_files = Vec::new();
    if rules_path.is_file() {
        rule_files.push(rules_path.to_path_buf());
    } else if rules_path.is_dir() {
        for entry in WalkDir::new(rules_path).into_iter().filter_map(|e| e.ok()) {
            if entry.path().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "raya" || ext == "yar" || ext == "yara" {
                        rule_files.push(entry.path().to_path_buf());
                    }
                }
            }
        }
    } else {
        return Err(format!("Rules path '{}' does not exist", rules_path.display()));
    }

    let mut parsed_rules = Vec::new();
    for rf in &rule_files {
        let rules = parse_rules_from_file(rf)
            .map_err(|e| format!("Failed to parse '{}': {}", rf.display(), e))?;
        parsed_rules.extend(rules);
    }

    Engine::compile_rules(parsed_rules)
        .map_err(|e| format!("Failed to compile rules: {}", e))
}
