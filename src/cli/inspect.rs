//! Deep Forensic Triage & Binary Inspection Subcommand
//!
//! Provides a terminal inspection dashboard and forensic breakdown:
//! - File hashes (MD5, SHA-1, SHA-256, SSDEEP, Imphash, RichPV, Exphash)
//! - Binary headers, entry point, image base, and machine architecture
//! - Section table with entropy meters and RWX permission auditing
//! - Security mitigation analysis (Authenticode, TLS callbacks, Rich checksum validation)
//! - Cryptographic constants (AES S-box, ChaCha20, MD5/SHA-256 IVs, CRC32, SM4)
//! - Recovered stack strings with instruction VAs
//! - Runtime introspection (.NET CLR, Golang pclntab, Rust toolchain & crates)

use crate::binary::{
    analyze_crypto, detect_format, parse_elf, parse_go, parse_macho, parse_pe, parse_rust,
    BinaryFormat,
};
use crate::entropy::shannon_entropy;
use crate::hash::compute_hashes;
use colored::Colorize;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

pub struct InspectArgs {
    pub target: PathBuf,
    pub json: bool,
}

#[derive(Serialize)]
struct InspectOutput<'a> {
    target: &'a str,
    filesize: usize,
    entropy: f64,
    hashes: HashesOutput<'a>,
    format: &'static str,
    pe: Option<PeInspectOutput>,
    crypto: Vec<crate::binary::CryptoMatch>,
    stack_strings: Vec<crate::binary::StackString>,
    dotnet: Option<crate::binary::DotNetInfo>,
    golang: Option<crate::binary::GoInfo>,
    rust: Option<crate::binary::RustInfo>,
}

#[derive(Serialize)]
struct HashesOutput<'a> {
    md5: &'a str,
    sha1: &'a str,
    sha256: &'a str,
    ssdeep: &'a str,
    imphash: Option<&'a str>,
    rich_hash: Option<&'a str>,
    exphash: Option<&'a str>,
}

#[derive(Serialize)]
struct PeInspectOutput {
    is_64: bool,
    is_dll: bool,
    machine: u16,
    entry_point: u64,
    image_base: u64,
    is_signed: bool,
    has_rich_header: bool,
    rich_checksum_mismatch: bool,
    tls_callbacks: Vec<u64>,
    sections: Vec<SectionInspectOutput>,
}

#[derive(Serialize)]
struct SectionInspectOutput {
    name: String,
    virtual_size: u32,
    raw_size: u32,
    entropy: f64,
    is_executable: bool,
    is_writable: bool,
    is_rwx: bool,
}

fn entropy_bar(entropy: f64) -> String {
    let filled = ((entropy / 8.0) * 10.0).round() as usize;
    let filled = filled.min(10);
    let empty = 10 - filled;
    let bar = format!("[{}{}]", "█".repeat(filled), "░".repeat(empty));
    if entropy >= 7.2 {
        bar.red().bold().to_string()
    } else if entropy >= 6.5 {
        bar.yellow().bold().to_string()
    } else {
        bar.green().to_string()
    }
}

pub fn run_inspect(args: InspectArgs) -> i32 {
    let data = match fs::read(&args.target) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "{} Failed to read target file: {}",
                "ERROR:".red().bold(),
                e
            );
            return 1;
        }
    };

    let target_str = args.target.display().to_string();
    let hashes = compute_hashes(&data);
    let fuzzy = hashes.ssdeep.as_deref().unwrap_or("N/A");
    let whole_entropy = shannon_entropy(&data);
    let format = detect_format(&data);

    let pe_info = if format.is_pe() {
        parse_pe(&data)
    } else {
        None
    };
    let elf_info = if format.is_elf() {
        parse_elf(&data)
    } else {
        None
    };
    let macho_info = if format.is_macho() {
        parse_macho(&data)
    } else {
        None
    };

    let crypto = analyze_crypto(&data);
    let golang = parse_go(&data);
    let rust = parse_rust(&data);
    let dotnet = pe_info.as_ref().and_then(|p| p.dotnet.clone());

    let stack_strings = if let Some(ref p) = pe_info {
        p.stack_strings.clone()
    } else {
        Vec::new()
    };

    if args.json {
        let pe_inspect = pe_info.as_ref().map(|p| PeInspectOutput {
            is_64: p.is_pe32_plus,
            is_dll: p.is_dll,
            machine: p.machine,
            entry_point: p.entry_point,
            image_base: p.image_base,
            is_signed: p.is_signed,
            has_rich_header: p.has_rich_header,
            rich_checksum_mismatch: p.rich_checksum_mismatch,
            tls_callbacks: p.tls_callbacks.clone(),
            sections: p
                .sections
                .iter()
                .map(|s| SectionInspectOutput {
                    name: s.name.clone(),
                    virtual_size: s.virtual_size,
                    raw_size: s.raw_size,
                    entropy: s.entropy,
                    is_executable: s.is_executable,
                    is_writable: s.is_writable,
                    is_rwx: s.is_executable && s.is_writable,
                })
                .collect(),
        });

        let out = InspectOutput {
            target: &target_str,
            filesize: data.len(),
            entropy: whole_entropy,
            hashes: HashesOutput {
                md5: &hashes.md5,
                sha1: &hashes.sha1,
                sha256: &hashes.sha256,
                ssdeep: fuzzy,
                imphash: pe_info.as_ref().and_then(|p| p.imphash.as_deref()),
                rich_hash: pe_info.as_ref().and_then(|p| p.rich_hash.as_deref()),
                exphash: pe_info.as_ref().and_then(|p| p.exphash.as_deref()),
            },
            format: format.as_str(),
            pe: pe_inspect,
            crypto: crypto.matches,
            stack_strings,
            dotnet,
            golang,
            rust,
        };

        if let Ok(serialized) = serde_json::to_string_pretty(&out) {
            println!("{}", serialized);
        }
        return 0;
    }

    // Terminal Dashboard View
    println!(
        "{}",
        "================================================================================".dimmed()
    );
    println!(
        "{} {}",
        "RAYA BINARY INSPECTOR - FORENSIC TRIAGE REPORT:"
            .bold()
            .cyan(),
        target_str.bold()
    );
    println!(
        "{}",
        "================================================================================".dimmed()
    );

    // File Metadata
    println!("{}", "FILE METRICS:".bold());
    println!("  Size:      {} bytes", data.len());
    let entropy_status = if whole_entropy >= 7.2 {
        "CRITICAL: Packed / Encrypted".red().bold()
    } else if whole_entropy >= 6.5 {
        "ELEVATED: High density".yellow().bold()
    } else {
        "NORMAL: Typical code/data".green()
    };
    println!(
        "  Entropy:   {:.4} {} ({})",
        whole_entropy,
        entropy_bar(whole_entropy),
        entropy_status
    );
    println!(
        "  Format:    {}",
        match format {
            BinaryFormat::Pe32 => "Windows Portable Executable 32-bit (PE32)".cyan(),
            BinaryFormat::Pe32Plus => "Windows Portable Executable 64-bit (PE32+)".cyan(),
            BinaryFormat::Elf32 => "Linux Executable and Linkable Format 32-bit (ELF32)".cyan(),
            BinaryFormat::Elf64 => "Linux Executable and Linkable Format 64-bit (ELF64)".cyan(),
            BinaryFormat::MachO => "macOS Mach-O Executable".cyan(),
            BinaryFormat::MachO32 => "macOS Mach-O 32-bit".cyan(),
            BinaryFormat::MachO64 => "macOS Mach-O 64-bit".cyan(),
            BinaryFormat::MachOFat => "macOS Universal Multi-Architecture Fat Binary".cyan(),
            BinaryFormat::Raw => "Raw Binary Data".yellow(),
        }
    );

    // Cryptographic Hashes
    println!("\n{}", "CRYPTOGRAPHIC IDENTIFIERS:".bold());
    println!("  MD5:       {}", hashes.md5.yellow());
    println!("  SHA-1:     {}", hashes.sha1.yellow());
    println!("  SHA-256:   {}", hashes.sha256.yellow());
    println!("  SSDEEP:    {}", fuzzy.dimmed());
    if let Some(ref p) = pe_info {
        if let Some(ref imp) = p.imphash {
            println!("  Imphash:   {}", imp.cyan().bold());
        }
        if let Some(ref rh) = p.rich_hash {
            println!("  RichPV:    {}", rh.dimmed());
        }
        if let Some(ref exp) = p.exphash {
            println!("  Exphash:   {}", exp.cyan());
        }
    }

    // PE Forensics & Sections
    if let Some(ref p) = pe_info {
        println!("\n{}", "PORTABLE EXECUTABLE METADATA:".bold());
        println!("  Entry Point:      0x{:08X}", p.entry_point);
        println!("  Image Base:       0x{:016X}", p.image_base);
        println!(
            "  Authenticode:     {}",
            if p.is_signed {
                "Valid / Certificate Present".green()
            } else {
                "Unsigned".yellow()
            }
        );
        if p.has_rich_header {
            let rich_status = if p.rich_checksum_mismatch {
                "CHECKSUM MISMATCH (Suspected Forgery / Header Tampering)"
                    .red()
                    .bold()
            } else {
                "Valid Checksum".green()
            };
            println!("  Rich Header:      {} ({})", "Present".cyan(), rich_status);
        }
        if p.has_tls {
            println!(
                "  TLS Callbacks:    {} registered [{}]",
                p.tls_callbacks.len(),
                p.tls_callbacks
                    .iter()
                    .map(|va| format!("0x{:X}", va))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        println!("\n{}", "SECTION TABLE & ENTROPY BAR:".bold());
        println!(
            "  {:<10} {:>10} {:>10} {:>8}  {:>14}  Flags",
            "Section", "VirtSize", "RawSize", "Entropy", "Heatmap"
        );
        println!(
            "  {}",
            "----------------------------------------------------------------------".dimmed()
        );
        for sec in &p.sections {
            let rwx_marker = if sec.is_executable && sec.is_writable {
                " [RWX ANOMALY]".red().bold().to_string()
            } else {
                String::new()
            };
            let perms = format!(
                "{}{}{}",
                if sec.is_readable { "R" } else { "-" },
                if sec.is_writable { "W" } else { "-" },
                if sec.is_executable { "X" } else { "-" }
            );
            println!(
                "  {:<10} {:>10} {:>10} {:>8.4}  {:>14}  {}{}",
                sec.name.cyan(),
                sec.virtual_size,
                sec.raw_size,
                sec.entropy,
                entropy_bar(sec.entropy),
                perms.dimmed(),
                rwx_marker
            );
        }
    } else if let Some(ref e) = elf_info {
        println!("\n{}", "ELF SECTIONS:".bold());
        for sec in &e.sections {
            let perms = format!(
                "{}{}",
                if sec.is_writable { "W" } else { "-" },
                if sec.is_executable { "X" } else { "-" }
            );
            println!(
                "  {:<16} {:>10} bytes  entropy:{:>6.4}  {}",
                sec.name.cyan(),
                sec.size,
                sec.entropy,
                perms.dimmed()
            );
        }
    } else if let Some(ref m) = macho_info {
        println!("\n{}", "MACH-O SEGMENTS & COMMANDS:".bold());
        println!("  CPU Type: {}", m.cpu_type);
        println!("  Commands: {}", m.number_of_commands);
        for seg in &m.segments {
            println!(
                "  {:<16} {:>10} bytes ({} sections)",
                seg.name.cyan(),
                seg.filesize,
                seg.sections.len()
            );
        }
    }

    // Cryptographic Primitives
    if crypto.has_any() {
        println!("\n{}", "CRYPTOGRAPHIC CONSTANTS DETECTED:".bold().magenta());
        for m in &crypto.matches {
            println!(
                "  ✓ [{}] {} at offset 0x{:X}",
                m.algorithm.bold(),
                m.description,
                m.offset
            );
        }
    }

    // Stack Strings
    if !stack_strings.is_empty() {
        println!("\n{}", "RECOVERED STACK STRINGS:".bold().green());
        for s in stack_strings.iter().take(12) {
            println!(
                "  ✓ \"{}\" (VA: 0x{:X}{})",
                s.value.bold(),
                s.offset,
                if s.is_wide { ", UTF-16LE" } else { "" }
            );
        }
        if stack_strings.len() > 12 {
            println!("  ... and {} more stack strings", stack_strings.len() - 12);
        }
    }

    // Toolchain & Runtime Fingerprinting
    if let Some(ref dn) = dotnet {
        println!("\n{}", ".NET / CLR RUNTIME METADATA:".bold().cyan());
        println!("  Version:       {}", dn.clr_version);
        if let Some(ref asm) = dn.assembly_name {
            println!("  Assembly Name: {}", asm.bold());
        }
        if let Some(ref module) = dn.module_name {
            println!("  Module Name:   {}", module);
        }
        println!(
            "  User Strings:  {} entries in #US heap",
            dn.user_strings.len()
        );
        if !dn.user_strings.is_empty() {
            for us in dn.user_strings.iter().take(5) {
                println!("    • \"{}\"", us.dimmed());
            }
        }
    }

    if let Some(ref go) = golang {
        println!("\n{}", "GOLANG RUNTIME METADATA:".bold().cyan());
        if let Some(ref v) = go.version {
            println!("  Toolchain:     {}", v.bold());
        }
        println!("  Packages:      {} identified", go.packages.len());
        if !go.packages.is_empty() {
            println!(
                "  Top Packages:  {}",
                go.packages
                    .iter()
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
                    .dimmed()
            );
        }
    }

    if let Some(ref r) = rust {
        println!("\n{}", "RUST RUNTIME METADATA:".bold().cyan());
        if let Some(ref c) = r.rustc_commit {
            println!("  rustc Commit:  {}", c.bold());
        }
        if !r.crates.is_empty() {
            println!("  Linked Crates: {}", r.crates.join(", ").dimmed());
        }
    }

    println!(
        "{}",
        "================================================================================".dimmed()
    );
    0
}
