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

use crate::binary::{BinaryAnalysis, BinaryFormat, SyscallType};
use crate::entropy::shannon_entropy;
use crate::hash::compute_hashes;
use colored::Colorize;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

pub struct InspectArgs {
    pub target: PathBuf,
    pub json: bool,
    pub password: Option<String>,
}

#[derive(Serialize)]
struct InspectOutput<'a> {
    target: &'a str,
    filesize: usize,
    entropy: f64,
    hashes: HashesOutput<'a>,
    format: &'static str,
    pe: Option<PeInspectOutput>,
    elf: Option<ElfInspectOutput>,
    macho: Option<MachoInspectOutput>,
    cfg: Option<CfgInspectOutput>,
    syscalls: Vec<crate::binary::SyscallStub>,
    api_hashes: Vec<crate::binary::ApiHashMatch>,
    authenticode: Option<crate::binary::AuthenticodeInfo>,
    crypto: Vec<crate::binary::CryptoMatch>,
    stack_strings: Vec<crate::binary::StackString>,
    dotnet: Option<crate::binary::DotNetInfo>,
    golang: Option<crate::binary::GoInfo>,
    rust: Option<crate::binary::RustInfo>,
    deobfuscated_strings: Vec<crate::deobfuscate::DecryptedPayload>,
    c2_configs: Vec<crate::extractor::ExtractedConfig>,
}

#[derive(Serialize)]
struct HashesOutput<'a> {
    md5: &'a str,
    sha1: &'a str,
    sha256: &'a str,
    ssdeep: &'a str,
    tlsh: Option<&'a str>,
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
    overlay: Option<crate::binary::pe::PeOverlay>,
}

#[derive(Serialize)]
struct CfgInspectOutput {
    blocks_count: usize,
    edges_count: usize,
    cyclomatic_complexity: usize,
    loops_count: usize,
    is_flattened: bool,
}

#[derive(Serialize)]
struct ElfInspectOutput {
    is_64: bool,
    is_pie: bool,
    has_nx: bool,
    has_canary: bool,
    relro: String,
    entry_point: u64,
    number_of_sections: usize,
}

#[derive(Serialize)]
struct MachoInspectOutput {
    is_64: bool,
    is_fat: bool,
    is_signed: bool,
    cpu_type: u32,
    number_of_commands: usize,
    has_dangerous_entitlement: bool,
    entitlements: Vec<String>,
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

    if crate::archive::is_zip(&data) {
        if let Ok(entries) = crate::archive::extract_zip_bytes(&data, args.password.as_deref()) {
            if !entries.is_empty() {
                for entry in entries {
                    let label = format!("{} -> {}", target_str, entry.name);
                    inspect_buffer(&label, &entry.data, args.json);
                }
                return 0;
            }
        }
    }

    inspect_buffer(&target_str, &data, args.json)
}

pub fn inspect_buffer(target_str: &str, data: &[u8], json: bool) -> i32 {
    let hashes = compute_hashes(data);
    let fuzzy = hashes.ssdeep.as_deref().unwrap_or("N/A");
    let whole_entropy = shannon_entropy(data);
    let analysis = BinaryAnalysis::analyze(data);
    let format = analysis.format;
    let pe_info = analysis.pe.as_ref();
    let elf_info = analysis.elf.as_ref();
    let macho_info = analysis.macho.as_ref();
    let crypto = &analysis.crypto;
    let golang = analysis.golang.clone();
    let rust = analysis.rust.clone();
    let dotnet = analysis.dotnet.clone();
    let stack_strings = analysis.stack_strings.clone();
    let cfg_info = analysis.cfg.as_ref();
    let syscalls = &analysis.syscalls;
    let api_hashes = &analysis.api_hashes;
    let authenticode = analysis.authenticode.as_ref();

    if json {
        let pe_inspect = pe_info.map(|p| PeInspectOutput {
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
            overlay: p.overlay.clone(),
        });

        let elf_inspect = elf_info.map(|e| ElfInspectOutput {
            is_64: e.is_64,
            is_pie: e.is_pie,
            has_nx: e.has_nx,
            has_canary: e.has_canary,
            relro: e.relro.clone(),
            entry_point: e.entry_point,
            number_of_sections: e.number_of_sections,
        });

        let macho_inspect = macho_info.map(|m| MachoInspectOutput {
            is_64: m.is_64,
            is_fat: m.is_fat,
            is_signed: m.is_signed,
            cpu_type: m.cpu_type,
            number_of_commands: m.number_of_commands,
            has_dangerous_entitlement: m.has_dangerous_entitlement,
            entitlements: m.entitlements.clone(),
        });

        let cfg_inspect = cfg_info.map(|c| CfgInspectOutput {
            blocks_count: c.blocks.len(),
            edges_count: c.edges.len(),
            cyclomatic_complexity: c.cyclomatic_complexity,
            loops_count: c.loops.len(),
            is_flattened: c.is_flattened,
        });

        let out = InspectOutput {
            target: target_str,
            filesize: data.len(),
            entropy: whole_entropy,
            hashes: HashesOutput {
                md5: &hashes.md5,
                sha1: &hashes.sha1,
                sha256: &hashes.sha256,
                ssdeep: fuzzy,
                tlsh: hashes.tlsh.as_deref(),
                imphash: pe_info.and_then(|p| p.imphash.as_deref()),
                rich_hash: pe_info.and_then(|p| p.rich_hash.as_deref()),
                exphash: pe_info.and_then(|p| p.exphash.as_deref()),
            },
            format: format.as_str(),
            pe: pe_inspect,
            elf: elf_inspect,
            macho: macho_inspect,
            cfg: cfg_inspect,
            syscalls: syscalls.clone(),
            api_hashes: api_hashes.clone(),
            authenticode: authenticode.cloned(),
            crypto: crypto.matches.clone(),
            stack_strings,
            dotnet,
            golang,
            rust,
            deobfuscated_strings: analysis.deobfuscated_strings.clone(),
            c2_configs: analysis.c2_configs.clone(),
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
    if let Some(ref tlsh_str) = hashes.tlsh {
        println!("  TLSH:      {}", tlsh_str.dimmed());
    }
    if let Some(p) = pe_info {
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
    if let Some(p) = pe_info {
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

        // PE Overlay Forensics
        if let Some(ref overlay) = p.overlay {
            println!("\n{}", "PE OVERLAY FORENSICS:".bold());
            println!("  Offset:         0x{:08X}", overlay.offset);
            let overlay_desc = overlay.file_type.as_deref().unwrap_or("Appended Data");
            let size_desc = if overlay.is_high_entropy {
                format!("{} bytes ({})", overlay.size, overlay_desc)
                    .red()
                    .bold()
            } else {
                format!("{} bytes ({})", overlay.size, overlay_desc)
                    .cyan()
                    .bold()
            };
            println!("  Size:           {}", size_desc);
            let entropy_label = if overlay.entropy >= 7.2 {
                "CRITICAL: Encrypted/Compressed".red().bold()
            } else if overlay.entropy >= 6.5 {
                "ELEVATED: High Density".yellow().bold()
            } else {
                "NORMAL".green()
            };
            println!(
                "  Entropy:        {:.4} {} ({})",
                overlay.entropy,
                entropy_bar(overlay.entropy),
                entropy_label
            );
            let hex_preview: Vec<String> = overlay
                .preview
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect();
            println!("  Header Bytes:   {}", hex_preview.join(" ").dimmed());
        }

        // Authenticode Digital Signature Audit
        if let Some(auth) = authenticode {
            println!("\n{}", "AUTHENTICODE DIGITAL SIGNATURE AUDIT:".bold());
            println!(
                "  Status:         {}",
                if auth.is_signed {
                    "Signed".green()
                } else {
                    "Unsigned".yellow()
                }
            );
            if let Some(ref cn) = auth.subject_cn {
                println!("  Subject CN:     {}", cn.cyan());
            }
            if let Some(ref org) = auth.organization {
                println!("  Organization:   {}", org);
            }
            if let Some(ref issuer) = auth.issuer_cn {
                println!("  Issuer CN:      {}", issuer.dimmed());
            }
            if auth.is_self_signed {
                println!(
                    "  Self-Signed:    {}",
                    "WARNING: Self-Signed Certificate".yellow().bold()
                );
            }
            if auth.has_signature_overlay {
                println!(
                    "  Overlay Audit:  {}",
                    format!(
                        "ANOMALY: Trailing Signature Overlay ({} bytes beyond PE boundary)",
                        auth.overlay_size
                    )
                    .red()
                    .bold()
                );
            } else {
                println!(
                    "  Overlay Audit:  {}",
                    "Clean (No trailing overlay detected)".green()
                );
            }
        }
    } else if let Some(e) = elf_info {
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

        println!("\n{}", "ELF COMPILER HARDENING & MITIGATIONS:".bold());
        println!(
            "  Non-Executable Stack (NX):  {}",
            if e.has_nx {
                "Enabled".green()
            } else {
                "DISABLED".red().bold()
            }
        );
        println!(
            "  Stack Canary Protection:    {}",
            if e.has_canary {
                "Enabled".green()
            } else {
                "DISABLED".yellow()
            }
        );
        println!(
            "  RELRO Hardening:            {}",
            match e.relro.as_str() {
                "Full" => "Full RELRO".green().bold(),
                "Partial" => "Partial RELRO".yellow(),
                _ => "None (No RELRO)".red().bold(),
            }
        );
        println!(
            "  Position Independent (PIE): {}",
            if e.is_pie {
                "Enabled (PIE)".green()
            } else {
                "Disabled".dimmed()
            }
        );
    } else if let Some(m) = macho_info {
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

        println!("\n{}", "MACH-O SECURITY & ENTITLEMENTS:".bold());
        println!(
            "  Code Signed:                {}",
            if m.is_signed {
                "Signed".green()
            } else {
                "Unsigned".yellow()
            }
        );
        println!(
            "  Dangerous Entitlements:     {}",
            if m.has_dangerous_entitlement {
                "DETECTED (e.g. get-task-allow)".red().bold()
            } else {
                "None".green()
            }
        );
        if !m.entitlements.is_empty() {
            println!("  Entitlements ({}):", m.entitlements.len());
            for ent in &m.entitlements {
                println!("    [-] {}", ent.dimmed());
            }
        }
    }

    // Direct / Indirect Syscall Hunter
    if !syscalls.is_empty() {
        println!("\n{}", "KERNEL EVASION & SYSCALL HUNTER:".bold().red());
        println!(
            "  {:<20} {:<12} {:<8} {:<28} Disassembly",
            "Type", "Address", "SSN", "Estimated API"
        );
        println!(
            "  {}",
            "--------------------------------------------------------------------------------"
                .dimmed()
        );
        for s in syscalls {
            let type_str = match s.stub_type {
                SyscallType::Direct => "DIRECT SYSCALL".red().bold(),
                SyscallType::Indirect => "INDIRECT TRAMPOLINE".magenta().bold(),
                SyscallType::LegacyInterrupt => "LEGACY INT 0x2E".yellow().bold(),
            };
            let ssn_str = s
                .ssn
                .map(|n| format!("0x{:04X}", n))
                .unwrap_or_else(|| "-".to_string());
            let api_str = s.estimated_api.as_deref().unwrap_or("Unknown").cyan();
            println!(
                "  {:<20} 0x{:08X}   {:<8} {:<28} {}",
                type_str,
                s.address,
                ssn_str,
                api_str,
                s.disassembly.dimmed()
            );
        }
    }

    // Control Flow Graph (CFG) Metrics
    if let Some(cfg) = cfg_info {
        if !cfg.blocks.is_empty() {
            println!("\n{}", "CONTROL FLOW GRAPH (CFG) METRICS:".bold());
            println!("  Basic Blocks:          {}", cfg.blocks.len());
            println!("  Directed Edges:        {}", cfg.edges.len());
            let cc_label = if cfg.cyclomatic_complexity >= 40 {
                "EXTREME: Suspected Obfuscation".red().bold()
            } else if cfg.cyclomatic_complexity >= 20 {
                "HIGH: Complex Logic".yellow().bold()
            } else {
                "NORMAL".green()
            };
            println!(
                "  Cyclomatic Complexity: {} ({})",
                cfg.cyclomatic_complexity, cc_label
            );
            println!("  Natural Loops:         {}", cfg.loops.len());
            if cfg.is_flattened {
                println!(
                    "  CFF Obfuscation:       {}",
                    "DETECTED (Dispatcher / Switch State-Machine Pattern)"
                        .red()
                        .bold()
                );
            }
        }
    }

    // Micro-Emulation API Hash Hunter
    if !api_hashes.is_empty() {
        println!(
            "\n{}",
            "RESOLVED API HASHES (MICRO-EMULATION):".bold().cyan()
        );
        println!(
            "  {:<12} {:<12} {:<32} Offset",
            "Algorithm", "Hash Value", "Resolved Win32 / NT API"
        );
        println!(
            "  {}",
            "----------------------------------------------------------------------".dimmed()
        );
        for h in api_hashes {
            println!(
                "  {:<12} 0x{:08X}   {:<32} 0x{:08X}",
                h.algorithm.yellow(),
                h.hash_value,
                h.api_name.green().bold(),
                h.offset
            );
        }
    }

    // Cryptographic Primitives
    if crypto.has_any() {
        println!("\n{}", "CRYPTOGRAPHIC CONSTANTS DETECTED:".bold().magenta());
        for m in &crypto.matches {
            println!(
                "  [-] [{}] {} at offset 0x{:X}",
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
                "  [-] \"{}\" (VA: 0x{:X}{})",
                s.value.bold(),
                s.offset,
                if s.is_wide { ", UTF-16LE" } else { "" }
            );
        }
        if stack_strings.len() > 12 {
            println!("  ... and {} more stack strings", stack_strings.len() - 12);
        }
    }

    // Automated XOR / Rolling Key Deobfuscation
    if !analysis.deobfuscated_strings.is_empty() {
        println!(
            "\n{}",
            "RECOVERED DEOBFUSCATED STRINGS / XOR BUFFERS:"
                .bold()
                .cyan()
        );
        for s in analysis.deobfuscated_strings.iter().take(10) {
            println!(
                "  [-] \"{}\" ({} | Key: {} at offset 0x{:X})",
                s.plaintext.bold(),
                s.algorithm.dimmed(),
                s.key_repr.yellow(),
                s.offset
            );
        }
        if analysis.deobfuscated_strings.len() > 10 {
            println!(
                "  ... and {} more deobfuscated strings",
                analysis.deobfuscated_strings.len() - 10
            );
        }
    }

    // Extracted C2 Configurations
    if !analysis.c2_configs.is_empty() {
        println!(
            "\n{}",
            "EXTRACTED C2 CONFIGURATIONS & THREAT INTEL:".bold().cyan()
        );
        for cfg in &analysis.c2_configs {
            println!("  [+] {}", cfg.family.red().bold());
            for c2 in &cfg.c2_servers {
                println!("      [-] C2: {}", c2.green().bold());
            }
            for k in &cfg.crypto_keys {
                println!("      [-] Key: {}", k.yellow());
            }
            for (k, v) in &cfg.extra {
                println!("      [-] {}: {}", k, v.bold());
            }
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
                println!("    [-] \"{}\"", us.dimmed());
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
