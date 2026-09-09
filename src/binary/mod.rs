pub mod disasm;
pub mod elf;
pub mod format;
pub mod macho;
pub mod pe;

pub use elf::{parse_elf, ElfInfo, ElfSection};
pub use format::{detect_format, BinaryFormat};
pub use macho::{parse_macho, MachoInfo, MachoSection, MachoSegment};
pub use pe::{parse_pe, PeImport, PeInfo, PeSection};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BinaryAnalysis {
    pub format: BinaryFormat,
    pub pe: Option<PeInfo>,
    pub elf: Option<ElfInfo>,
    pub macho: Option<MachoInfo>,
}

impl BinaryAnalysis {
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
