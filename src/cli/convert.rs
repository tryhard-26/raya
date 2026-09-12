//! YARA-to-Raya Rule Transpiler Subcommand
//!
//! Automatically converts legacy YARA detection rules (.yar / .yara) into native Raya rules:
//! - Strips redundant `import "pe"`, `import "elf"`, `import "math"` module declarations
//! - Maps YARA PE module functions (e.g. `pe.imphash()`, `pe.imports()`) to Raya native expressions
//! - Validates the transpiled rule file with Raya's parser before persisting

use crate::parser::parse_rules_from_str;
use colored::Colorize;
use regex::Regex;
use std::fs;
use std::path::PathBuf;

pub struct ConvertArgs {
    pub input: PathBuf,
    pub output: PathBuf,
}

pub fn run_convert(args: ConvertArgs) -> i32 {
    let source = match fs::read_to_string(&args.input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{} Failed to read input rule file {}: {}",
                "ERROR:".red().bold(),
                args.input.display(),
                e
            );
            return 1;
        }
    };

    let transpiled = transpile_yara_to_raya(&source);

    // Validate that the output parses correctly as Raya rules
    match parse_rules_from_str(&transpiled) {
        Ok(rules) => {
            if let Err(e) = fs::write(&args.output, &transpiled) {
                eprintln!(
                    "{} Failed to write output rule file {}: {}",
                    "ERROR:".red().bold(),
                    args.output.display(),
                    e
                );
                return 1;
            }

            println!(
                "{} Successfully transpiled {} rule(s) from {} -> {}",
                "SUCCESS:".green().bold(),
                rules.len(),
                args.input.display().to_string().cyan(),
                args.output.display().to_string().cyan()
            );
            0
        }
        Err(e) => {
            eprintln!(
                "{} Transpiled output failed parser validation: {}",
                "ERROR:".red().bold(),
                e
            );
            // Write to output anyway with a warning so user can inspect
            let _ = fs::write(&args.output, &transpiled);
            1
        }
    }
}

/// Transpiles YARA rule source code into Raya syntax.
pub fn transpile_yara_to_raya(yara_src: &str) -> String {
    let mut out = String::new();

    // 1. Remove module imports: import "pe", import "elf", import "math", etc.
    let re_import = Regex::new(r#"(?m)^\s*import\s+"[^"]+"\s*;?\s*$"#).unwrap();
    let src_clean = re_import.replace_all(yara_src, "");

    // 2. Transpile PE module function calls:
    // pe.imphash() -> pe.imphash
    let re_imphash = Regex::new(r"\bpe\.imphash\s*\(\s*\)").unwrap();
    let src_clean = re_imphash.replace_all(&src_clean, "pe.imphash");

    // pe.imports("dll", "func") -> pe.import("dll", "func")
    let re_imports = Regex::new(r"\bpe\.imports\s*\(").unwrap();
    let src_clean = re_imports.replace_all(&src_clean, "pe.import(");

    // pe.exports("func") -> pe.export("func")
    let re_exports = Regex::new(r"\bpe\.exports\s*\(").unwrap();
    let src_clean = re_exports.replace_all(&src_clean, "pe.export(");

    // 3. Transpile entrypoint: entrypoint -> pe.entry_point
    let re_entrypoint = Regex::new(r"\bentrypoint\b").unwrap();
    let src_clean = re_entrypoint.replace_all(&src_clean, "pe.entry_point");

    out.push_str(&src_clean);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transpile_yara_rule() {
        let yara_rule = r#"
            import "pe"
            import "math"

            rule Trojan_Downloader {
                meta:
                    author = "Analyst"
                    description = "Detects test dropper"
                strings:
                    $mz = "MZ"
                    $url = "http://malicious-c2.test"
                condition:
                    $mz at 0 and pe.imphash() == "b484b162670d8591" and pe.imports("ws2_32.dll", "connect")
            }
        "#;

        let transpiled = transpile_yara_to_raya(yara_rule);
        assert!(!transpiled.contains("import \"pe\""));
        assert!(!transpiled.contains("import \"math\""));
        assert!(transpiled.contains("pe.imphash =="));
        assert!(transpiled.contains("pe.import(\"ws2_32.dll\", \"connect\")"));

        let parsed = parse_rules_from_str(&transpiled);
        assert!(parsed.is_ok(), "Parsed rule: {:?}", parsed.err());
    }
}
