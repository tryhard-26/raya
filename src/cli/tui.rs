// src/cli/tui.rs
//
// CLI command handler for `raya tui <target>`
// Launches interactive terminal forensic triage dashboard.

use crate::tui::launch_tui;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

pub struct TuiArgs {
    pub target: PathBuf,
    pub password: Option<String>,
}

pub fn run_tui_cli(args: TuiArgs) -> i32 {
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

    let target_str = args.target.display().to_string();

    // Check if target is a ZIP archive
    if crate::archive::is_zip(&data) {
        if let Ok(entries) = crate::archive::extract_zip_bytes(&data, args.password.as_deref()) {
            if let Some(first_entry) = entries.into_iter().next() {
                let label = format!("{} -> {}", target_str, first_entry.name);
                return launch_tui(&label, &first_entry.data);
            }
        }
    }

    launch_tui(&target_str, &data)
}
