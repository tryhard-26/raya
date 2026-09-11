//! # Executable Binary Analysis & Introspection
//!
//! Provides zero-copy executable file format detection and parsing for:
//! - **PE / PE32+** (Windows executables, DLLs, drivers via [`pe`])
//! - **ELF32 / ELF64** (Linux binaries, shared objects via [`elf`])
//! - **Mach-O** (macOS binaries, dylibs, Fat multi-arch bundles via [`macho`])
//! - **Linear Disassembly & Argument Tracking** (x86/x64 instruction decoding, basic-block scoping via [`disasm`])

pub mod disasm;
pub mod elf;
pub mod format;
pub mod macho;
pub mod pe;

pub use elf::{parse_elf, ElfInfo, ElfSection};
pub use format::{detect_format, BinaryFormat};
pub use macho::{parse_macho, MachoInfo, MachoSection, MachoSegment};
pub use pe::{parse_pe, PeImport, PeInfo, PeSection};

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
}

impl BinaryAnalysis {
    /// Detects binary format and executes the corresponding header and section parsers.
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

        Self {
            format,
            pe,
            elf,
            macho,
        }
    }
}
