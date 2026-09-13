//! # Executable Binary Analysis & Introspection
//!
//! Provides zero-copy executable file format detection and parsing for:
//! - **PE / PE32+** (Windows executables, DLLs, drivers via [`pe`])
//! - **ELF32 / ELF64** (Linux binaries, shared objects via [`elf`])
//! - **Mach-O** (macOS binaries, dylibs, Fat multi-arch bundles via [`macho`])
//! - **Linear Disassembly & Argument Tracking** (x86/x64 instruction decoding, basic-block scoping, stack string extraction via [`disasm`])
//! - **.NET / CLR Metadata** (BSJB streams, user strings, types via [`dotnet`])
//! - **Cryptographic Constants** (AES, ChaCha20, MD5, SHA-256, CRC32, SM4 via [`crypto`])
//! - **Golang Introspection** (pclntab, Go versions, packages via [`golang`])
//! - **Rust Introspection** (rustc toolchain commit, crates via [`rust`])

pub mod api_hash;
pub mod authenticode;
pub mod cfg;
pub mod crypto;
pub mod disasm;
pub mod dotnet;
pub mod elf;
pub mod format;
pub mod golang;
pub mod macho;
pub mod pe;
pub mod rust;
pub mod syscall;

pub use api_hash::{scan_api_hashes, ApiHashDatabase, ApiHashMatch};
pub use authenticode::{parse_authenticode, AuthenticodeInfo};
pub use cfg::{CfgBlock, CfgEdge, CfgLoop, ControlFlowGraph, EdgeType};
pub use crypto::{analyze_crypto, CryptoAnalysis, CryptoMatch};
pub use disasm::{extract_stack_strings, ApiCallArgMatch, BasicBlock, ScopedFunction, StackString};
pub use dotnet::{parse_dotnet, DotNetInfo};
pub use elf::{parse_elf, ElfInfo, ElfSection};
pub use format::{detect_format, BinaryFormat};
pub use golang::{parse_go, GoInfo};
pub use macho::{parse_macho, MachoInfo, MachoSection, MachoSegment};
pub use pe::{parse_pe, PeImport, PeInfo, PeSection, RichEntry};
pub use rust::{parse_rust, RustInfo};
pub use syscall::{detect_syscall_stubs, SyscallStub, SyscallType};

/// Extracted structural metadata from an executable binary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BinaryAnalysis {
    /// Detected format (such as PE32, PE32+, ELF, Mach-O, or Raw).
    pub format: BinaryFormat,
    /// Extracted Windows PE metadata, if the sample is a PE binary.
    pub pe: Option<PeInfo>,
    /// Extracted Linux ELF metadata, if the sample is an ELF binary.
    pub elf: Option<ElfInfo>,
    /// Extracted macOS Mach-O metadata, if the sample is a Mach-O binary.
    pub macho: Option<MachoInfo>,
    /// Extracted .NET / CLR metadata, if present.
    pub dotnet: Option<DotNetInfo>,
    /// Detected cryptographic constant and S-box signatures.
    pub crypto: CryptoAnalysis,
    /// Extracted Go runtime and symbol metadata, if compiled with Go.
    pub golang: Option<GoInfo>,
    /// Extracted Rust toolchain and crate metadata, if compiled with Rust.
    pub rust: Option<RustInfo>,
    /// Extracted stack-constructed strings across executable sections.
    pub stack_strings: Vec<StackString>,
    /// Reconstructed Control Flow Graph for executable sections.
    pub cfg: Option<ControlFlowGraph>,
    /// Detected direct and indirect system call stubs.
    pub syscalls: Vec<SyscallStub>,
    /// Resolved API hashes (e.g. ROR13, DJB2).
    pub api_hashes: Vec<ApiHashMatch>,
    /// Digital signature and Authenticode metadata, if signed.
    pub authenticode: Option<AuthenticodeInfo>,
    /// Automatically deobfuscated plaintext strings and XOR buffers.
    pub deobfuscated_strings: Vec<crate::deobfuscate::DecryptedPayload>,
    /// Extracted C2 configurations and threat intelligence indicators.
    pub c2_configs: Vec<crate::extractor::ExtractedConfig>,
}

impl BinaryAnalysis {
    /// Detects binary format and executes header, section, and runtime introspection parsers.
    pub fn analyze(data: &[u8]) -> Self {
        let format = detect_format(data);
        let pe = if format.is_pe() { parse_pe(data) } else { None };
        let elf = if format.is_elf() {
            parse_elf(data)
        } else {
            None
        };
        let macho = if format.is_macho() {
            parse_macho(data)
        } else {
            None
        };

        // .NET metadata from PE or standalone BSJB
        let dotnet = pe.as_ref().and_then(|p| p.dotnet.clone());

        // Cryptographic constant identification
        let crypto = analyze_crypto(data);

        // Go and Rust runtime introspection
        let golang = parse_go(data);
        let rust = parse_rust(data);

        // Stack strings: from PE or extracted from ELF/Mach-O code
        let mut stack_strings = pe
            .as_ref()
            .map(|p| p.stack_strings.clone())
            .unwrap_or_default();

        if stack_strings.is_empty() {
            if let Some(ref elf_info) = elf {
                for sec in &elf_info.sections {
                    if sec.is_executable && sec.size > 0 && (sec.offset as usize) < data.len() {
                        let start = sec.offset as usize;
                        let end = (start + (sec.size as usize).min(256 * 1024)).min(data.len());
                        let bitness = if elf_info.is_64 { 64 } else { 32 };
                        stack_strings.extend(extract_stack_strings(
                            &data[start..end],
                            bitness,
                            sec.addr,
                        ));
                    }
                }
            }
        }

        let mut cfg = pe.as_ref().and_then(|p| p.cfg.clone());
        let mut syscalls = pe.as_ref().map(|p| p.syscalls.clone()).unwrap_or_default();
        let mut api_hashes = pe
            .as_ref()
            .map(|p| p.api_hashes.clone())
            .unwrap_or_default();
        let authenticode = pe.as_ref().and_then(|p| p.authenticode.clone());

        if cfg.is_none() {
            let api_db = crate::binary::api_hash::ApiHashDatabase::new();
            if let Some(ref elf_info) = elf {
                let bitness = if elf_info.is_64 { 64 } else { 32 };
                for sec in &elf_info.sections {
                    if sec.is_executable && sec.size > 0 && (sec.offset as usize) < data.len() {
                        let start = sec.offset as usize;
                        let end = (start + (sec.size as usize).min(512 * 1024)).min(data.len());
                        let sec_bytes = &data[start..end];
                        let mut decoder = iced_x86::Decoder::with_ip(
                            bitness,
                            sec_bytes,
                            sec.addr,
                            iced_x86::DecoderOptions::NONE,
                        );
                        let mut instructions = Vec::new();
                        let mut instr = iced_x86::Instruction::default();
                        while decoder.can_decode() && instructions.len() < 32768 {
                            decoder.decode_out(&mut instr);
                            if !instr.is_invalid() {
                                instructions.push(instr);
                            }
                        }
                        if !instructions.is_empty() {
                            syscalls.extend(crate::binary::syscall::detect_syscall_stubs(
                                &instructions,
                            ));
                            api_hashes.extend(crate::binary::api_hash::scan_api_hashes(
                                sec_bytes,
                                &instructions,
                                &api_db,
                            ));
                            if cfg.is_none() {
                                cfg =
                                    Some(crate::binary::cfg::ControlFlowGraph::from_instructions(
                                        &instructions,
                                    ));
                            }
                        }
                    }
                }
            } else if let Some(ref macho_info) = macho {
                let bitness = if macho_info.is_64 { 64 } else { 32 };
                for seg in &macho_info.segments {
                    for sec in &seg.sections {
                        if sec.is_executable && sec.size > 0 && (sec.offset as usize) < data.len() {
                            let start = sec.offset as usize;
                            let end = (start + (sec.size as usize).min(512 * 1024)).min(data.len());
                            let sec_bytes = &data[start..end];
                            let mut decoder = iced_x86::Decoder::with_ip(
                                bitness,
                                sec_bytes,
                                sec.addr,
                                iced_x86::DecoderOptions::NONE,
                            );
                            let mut instructions = Vec::new();
                            let mut instr = iced_x86::Instruction::default();
                            while decoder.can_decode() && instructions.len() < 32768 {
                                decoder.decode_out(&mut instr);
                                if !instr.is_invalid() {
                                    instructions.push(instr);
                                }
                            }
                            if !instructions.is_empty() {
                                syscalls.extend(crate::binary::syscall::detect_syscall_stubs(
                                    &instructions,
                                ));
                                api_hashes.extend(crate::binary::api_hash::scan_api_hashes(
                                    sec_bytes,
                                    &instructions,
                                    &api_db,
                                ));
                                if cfg.is_none() {
                                    cfg = Some(
                                        crate::binary::cfg::ControlFlowGraph::from_instructions(
                                            &instructions,
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
            } else if format == BinaryFormat::Raw && data.len() >= 16 {
                for &bitness in &[64, 32] {
                    let end = data.len().min(64 * 1024);
                    let mut decoder = iced_x86::Decoder::with_ip(
                        bitness,
                        &data[..end],
                        0x1000,
                        iced_x86::DecoderOptions::NONE,
                    );
                    let mut instructions = Vec::new();
                    let mut instr = iced_x86::Instruction::default();
                    while decoder.can_decode() && instructions.len() < 8192 {
                        decoder.decode_out(&mut instr);
                        if !instr.is_invalid() {
                            instructions.push(instr);
                        }
                    }
                    if instructions.len() >= 4 {
                        syscalls
                            .extend(crate::binary::syscall::detect_syscall_stubs(&instructions));
                        api_hashes.extend(crate::binary::api_hash::scan_api_hashes(
                            &data[..end],
                            &instructions,
                            &api_db,
                        ));
                        cfg = Some(crate::binary::cfg::ControlFlowGraph::from_instructions(
                            &instructions,
                        ));
                        break;
                    }
                }
            }
        }

        let deobfuscated_strings = crate::deobfuscate::hunt_deobfuscated_strings(data);
        let c2_configs = crate::extractor::extract_all_configs(data);

        Self {
            format,
            pe,
            elf,
            macho,
            dotnet,
            crypto,
            golang,
            rust,
            stack_strings,
            cfg,
            syscalls,
            api_hashes,
            authenticode,
            deobfuscated_strings,
            c2_configs,
        }
    }
}
