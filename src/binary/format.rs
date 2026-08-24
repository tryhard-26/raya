use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    Pe32,
    Pe32Plus,
    Elf32,
    Elf64,
    MachO,
    Raw,
}

impl BinaryFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            BinaryFormat::Pe32 => "PE32",
            BinaryFormat::Pe32Plus => "PE32+",
            BinaryFormat::Elf32 => "ELF32",
            BinaryFormat::Elf64 => "ELF64",
            BinaryFormat::MachO => "Mach-O",
            BinaryFormat::Raw => "Raw/Unknown",
        }
    }

    pub fn is_pe(&self) -> bool {
        matches!(self, BinaryFormat::Pe32 | BinaryFormat::Pe32Plus)
    }

    pub fn is_elf(&self) -> bool {
        matches!(self, BinaryFormat::Elf32 | BinaryFormat::Elf64)
    }
}

impl fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub fn detect_format(data: &[u8]) -> BinaryFormat {
    // Check PE
    if data.len() >= 0x40 && data[0] == b'M' && data[1] == b'Z' {
        let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if e_lfanew + 24 <= data.len() && &data[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
            let magic_offset = e_lfanew + 24;
            if magic_offset + 2 <= data.len() {
                let opt_magic = u16::from_le_bytes([data[magic_offset], data[magic_offset + 1]]);
                return match opt_magic {
                    0x10B => BinaryFormat::Pe32,
                    0x20B => BinaryFormat::Pe32Plus,
                    _ => BinaryFormat::Pe32,
                };
            }
            return BinaryFormat::Pe32;
        }
    }

    // Check ELF
    if data.len() >= 5 && &data[0..4] == b"\x7fELF" {
        return match data[4] {
            1 => BinaryFormat::Elf32,
            2 => BinaryFormat::Elf64,
            _ => BinaryFormat::Elf64,
        };
    }

    // Check Mach-O
    if data.len() >= 4 {
        let magic = &data[0..4];
        if magic == b"\xfe\xed\xfa\xce"
            || magic == b"\xce\xfa\xed\xfe"
            || magic == b"\xfe\xed\xfa\xcf"
            || magic == b"\xcf\xfa\xed\xfe"
            || magic == b"\xca\xfe\xba\xbe"
            || magic == b"\xbe\xba\xfe\xca"
        {
            return BinaryFormat::MachO;
        }
    }

    BinaryFormat::Raw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pe() {
        let mut mock_pe = vec![0u8; 0x100];
        mock_pe[0] = b'M';
        mock_pe[1] = b'Z';
        // e_lfanew at 0x3C -> points to 0x80
        mock_pe[0x3C] = 0x80;
        // Signature at 0x80
        mock_pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        // Optional magic at 0x80 + 24 = 0x98 -> 0x20B (PE32+)
        mock_pe[0x98] = 0x0B;
        mock_pe[0x99] = 0x02;

        assert_eq!(detect_format(&mock_pe), BinaryFormat::Pe32Plus);
    }

    #[test]
    fn test_detect_elf() {
        let mock_elf64 = b"\x7fELF\x02\x01\x01\x00";
        assert_eq!(detect_format(mock_elf64), BinaryFormat::Elf64);
        let mock_elf32 = b"\x7fELF\x01\x01\x01\x00";
        assert_eq!(detect_format(mock_elf32), BinaryFormat::Elf32);
    }

    #[test]
    fn test_detect_raw() {
        let raw = b"Random binary or text content";
        assert_eq!(detect_format(raw), BinaryFormat::Raw);
    }
}
