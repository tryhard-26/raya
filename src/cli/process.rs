use crate::engine::Engine;
use crate::report::ScanResult;
use colored::Colorize;

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom};

pub fn scan_process_memory(
    engine: &Engine,
    pid: u32,
    json: bool,
    quiet: bool,
    format: Option<&str>,
) -> i32 {
    #[cfg(target_os = "linux")]
    {
        scan_linux_process(engine, pid, json, quiet, format)
    }

    #[cfg(not(target_os = "linux"))]
    {
        scan_generic_process(engine, pid, json, quiet, format)
    }
}

#[cfg(target_os = "linux")]
fn scan_linux_process(
    engine: &Engine,
    pid: u32,
    json: bool,
    quiet: bool,
    format: Option<&str>,
) -> i32 {
    let maps_path = format!("/proc/{}/maps", pid);
    let mem_path = format!("/proc/{}/mem", pid);

    let maps_content = match std::fs::read_to_string(&maps_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Cannot access process maps for PID {} (requires root/ptrace): {}",
                "ERROR:".red().bold(),
                pid,
                e
            );
            return 2;
        }
    };

    let mut mem_file = match File::open(&mem_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "{} Cannot open process memory for PID {} (requires root/ptrace): {}",
                "ERROR:".red().bold(),
                pid,
                e
            );
            return 2;
        }
    };

    let mut results = Vec::new();

    for line in maps_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let perms = parts[1];
        if !perms.starts_with('r') {
            continue;
        }

        let range: Vec<&str> = parts[0].split('-').collect();
        if range.len() != 2 {
            continue;
        }

        let start = match usize::from_str_radix(range[0], 16) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let end = match usize::from_str_radix(range[1], 16) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let size = end.saturating_sub(start);
        if size == 0 || size > 32 * 1024 * 1024 {
            continue;
        }

        if mem_file.seek(SeekFrom::Start(start as u64)).is_err() {
            continue;
        }

        let mut buffer = vec![0u8; size];
        if mem_file.read_exact(&mut buffer).is_err() {
            continue;
        }

        let target_name = format!("PID:{} [0x{:x}-0x{:x} {}]", pid, start, end, perms);
        let res = engine.scan_bytes(&buffer, &target_name);
        if res.has_matches() {
            results.push(res);
        }
    }

    emit_results(&results, json, quiet, format)
}

#[cfg(not(target_os = "linux"))]
fn scan_generic_process(
    _engine: &Engine,
    pid: u32,
    json: bool,
    quiet: bool,
    format: Option<&str>,
) -> i32 {
    eprintln!(
        "{} Live virtual memory scanning for PID {} requires Linux /proc or elevated macOS debugging entitlements (task_for_pid).",
        "WARNING:".yellow().bold(),
        pid
    );
    eprintln!(
        "{} For memory dumps or process core dumps, use: raya scan <dump_file>",
        "INFO:".cyan().bold()
    );
    emit_results(&[], json, quiet, format)
}

pub fn emit_results(results: &[ScanResult], json: bool, quiet: bool, format: Option<&str>) -> i32 {
    let fmt = format.unwrap_or(if json { "json" } else { "text" });

    match fmt {
        "json" => match serde_json::to_string_pretty(results) {
            Ok(j) => println!("{}", j),
            Err(e) => {
                eprintln!("Failed to serialize JSON: {}", e);
                return 2;
            }
        },
        "sarif" => match crate::report::to_sarif(results) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("Failed to serialize SARIF: {}", e);
                return 2;
            }
        },
        "stix" => match crate::report::to_stix(results) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("Failed to serialize STIX: {}", e);
                return 2;
            }
        },
        _ => {
            if quiet {
                for r in results {
                    for m in &r.matches {
                        println!("{}: {}", r.target, m.rule);
                    }
                }
            } else if results.is_empty() {
                println!(
                    "{}",
                    "✓ Process memory scan complete: 0 matches (clean)"
                        .green()
                        .bold()
                );
            } else {
                for r in results {
                    print!("{}", r.render_terminal());
                }
            }
        }
    }

    if results.iter().any(|r| r.has_matches()) {
        1
    } else {
        0
    }
}
