use crate::entropy::shannon_entropy;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ElfSection {
    pub name: String,
    pub sh_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ElfInfo {
    pub is_elf: bool,
    pub is_64: bool,
    pub is_executable: bool,
    pub is_shared_object: bool,
    pub machine: u16,
    pub entry_point: u64,
    pub number_of_sections: usize,
    pub sections: Vec<ElfSection>,
    pub dynamic_libraries: Vec<String>,
    pub symbols: Vec<String>,
    pub has_nx: bool,
    pub has_canary: bool,
    pub relro: String,
    pub is_pie: bool,
}

impl ElfInfo {
    pub fn empty() -> Self {
        Self {
            is_elf: false,
            is_64: false,
            is_executable: false,
            is_shared_object: false,
            machine: 0,
            entry_point: 0,
            number_of_sections: 0,
            sections: Vec::new(),
            dynamic_libraries: Vec::new(),
            symbols: Vec::new(),
            has_nx: false,
            has_canary: false,
            relro: "None".to_string(),
            is_pie: false,
        }
    }

    pub fn get_section(&self, name: &str) -> Option<&ElfSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn has_section(&self, name: &str) -> bool {
        self.get_section(name).is_some()
    }
}

pub fn parse_elf(data: &[u8]) -> Option<ElfInfo> {
    if data.len() < 16 || &data[0..4] != b"\x7fELF" {
        return None;
    }

    let is_64 = match data[4] {
        1 => false,
        2 => true,
        _ => return None,
    };

    let is_little_endian = match data[5] {
        1 => true,
        2 => false,
        _ => return None,
    };

    if !is_little_endian {
        // We primarily target little-endian for modern x86/x64/arm64
        // (big-endian can be supported or handled gracefully)
    }

    let read_u16 = |offset: usize| -> Option<u16> {
        if offset + 2 <= data.len() {
            if is_little_endian {
                Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
            } else {
                Some(u16::from_be_bytes([data[offset], data[offset + 1]]))
            }
        } else {
            None
        }
    };

    let read_u32 = |offset: usize| -> Option<u32> {
        if offset + 4 <= data.len() {
            if is_little_endian {
                Some(u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]))
            } else {
                Some(u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]))
            }
        } else {
            None
        }
    };

    let read_u64 = |offset: usize| -> Option<u64> {
        if offset + 8 <= data.len() {
            if is_little_endian {
                Some(u64::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]))
            } else {
                Some(u64::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]))
            }
        } else {
            None
        }
    };

    let elf_type = read_u16(16)?;
    let machine = read_u16(18)?;
    let is_executable = elf_type == 2; // ET_EXEC
    let is_shared_object = elf_type == 3; // ET_DYN

    let (
        entry_point,
        sh_offset,
        sh_entry_size,
        sh_num,
        sh_str_ndx,
        ph_offset,
        ph_entry_size,
        ph_num,
    ) = if is_64 {
        if data.len() < 64 {
            return None;
        }
        let ep = read_u64(24)?;
        let phoff = read_u64(32)? as usize;
        let shoff = read_u64(40)? as usize;
        let phents = read_u16(54)? as usize;
        let phnum = read_u16(56)? as usize;
        let shents = read_u16(58)? as usize;
        let shnum = read_u16(60)? as usize;
        let shstr = read_u16(62)? as usize;
        (ep, shoff, shents, shnum, shstr, phoff, phents, phnum)
    } else {
        if data.len() < 52 {
            return None;
        }
        let ep = read_u32(24)? as u64;
        let phoff = read_u32(28)? as usize;
        let shoff = read_u32(32)? as usize;
        let phents = read_u16(42)? as usize;
        let phnum = read_u16(44)? as usize;
        let shents = read_u16(46)? as usize;
        let shnum = read_u16(48)? as usize;
        let shstr = read_u16(50)? as usize;
        (ep, shoff, shents, shnum, shstr, phoff, phents, phnum)
    };

    // Locate section string table (.shstrtab)
    let get_shstrtab_slice = || -> Option<&[u8]> {
        if sh_str_ndx >= sh_num {
            return None;
        }
        let str_header_offset = sh_offset + (sh_str_ndx * sh_entry_size);
        let (offset, size) = if is_64 {
            let off = read_u64(str_header_offset + 24)? as usize;
            let sz = read_u64(str_header_offset + 32)? as usize;
            (off, sz)
        } else {
            let off = read_u32(str_header_offset + 16)? as usize;
            let sz = read_u32(str_header_offset + 20)? as usize;
            (off, sz)
        };
        if offset + size <= data.len() {
            Some(&data[offset..offset + size])
        } else {
            None
        }
    };

    let shstrtab = get_shstrtab_slice();

    let mut sections = Vec::new();
    for i in 0..sh_num {
        let sec_hdr_offset = sh_offset + (i * sh_entry_size);
        if sec_hdr_offset + sh_entry_size > data.len() {
            break;
        }

        let sh_name_idx = read_u32(sec_hdr_offset)? as usize;
        let sh_type = read_u32(sec_hdr_offset + 4)?;

        let (flags, addr, offset, size) = if is_64 {
            let fl = read_u64(sec_hdr_offset + 8)?;
            let ad = read_u64(sec_hdr_offset + 16)?;
            let off = read_u64(sec_hdr_offset + 24)?;
            let sz = read_u64(sec_hdr_offset + 32)?;
            (fl, ad, off, sz)
        } else {
            let fl = read_u32(sec_hdr_offset + 8)? as u64;
            let ad = read_u32(sec_hdr_offset + 12)? as u64;
            let off = read_u32(sec_hdr_offset + 16)? as u64;
            let sz = read_u32(sec_hdr_offset + 20)? as u64;
            (fl, ad, off, sz)
        };

        let sec_name = if let Some(strtab) = shstrtab {
            if sh_name_idx < strtab.len() {
                let end = strtab[sh_name_idx..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|pos| sh_name_idx + pos)
                    .unwrap_or(strtab.len());
                String::from_utf8_lossy(&strtab[sh_name_idx..end]).to_string()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let is_writable = (flags & 0x1) != 0; // SHF_WRITE
        let is_alloc = (flags & 0x2) != 0; // SHF_ALLOC
        let is_executable = (flags & 0x4) != 0; // SHF_EXECINSTR

        let entropy = if size > 0 && (offset as usize) < data.len() {
            let start = offset as usize;
            let end = (start + size as usize).min(data.len());
            shannon_entropy(&data[start..end])
        } else {
            0.0
        };

        sections.push(ElfSection {
            name: sec_name,
            sh_type,
            flags,
            addr,
            offset,
            size,
            entropy,
            is_readable: is_alloc,
            is_writable,
            is_executable,
        });
    }

    // Parse Program Headers for Security Mitigations
    let mut has_nx = false;
    let mut has_relro = false;

    if ph_offset > 0 && ph_num > 0 && ph_entry_size >= 32 {
        for i in 0..ph_num {
            let p_start = ph_offset + i * ph_entry_size;
            if p_start + ph_entry_size <= data.len() {
                let p_type = read_u32(p_start).unwrap_or(0);
                if p_type == 0x6474e551 {
                    // PT_GNU_STACK
                    let p_flags = if is_64 {
                        read_u32(p_start + 4).unwrap_or(0)
                    } else {
                        read_u32(p_start + 24).unwrap_or(0)
                    };
                    // Non-executable stack if PF_X (0x1) is NOT set
                    if (p_flags & 0x1) == 0 {
                        has_nx = true;
                    }
                } else if p_type == 0x6474e552 {
                    // PT_GNU_RELRO
                    has_relro = true;
                }
            }
        }
    }

    let relro = if has_relro {
        "Partial".to_string()
    } else {
        "None".to_string()
    };

    let has_canary = data.windows(16).any(|w| w == b"__stack_chk_fail");
    let is_pie = is_shared_object && entry_point != 0;

    Some(ElfInfo {
        is_elf: true,
        is_64,
        is_executable,
        is_shared_object,
        machine,
        entry_point,
        number_of_sections: sections.len(),
        sections,
        dynamic_libraries: Vec::new(),
        symbols: Vec::new(),
        has_nx,
        has_canary,
        relro,
        is_pie,
    })
}
