use crate::entropy::shannon_entropy;
use std::fmt;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MachoSection {
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub entropy: f64,
    pub is_executable: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MachoSegment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub sections: Vec<MachoSection>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MachoInfo {
    pub is_macho: bool,
    pub is_64: bool,
    pub is_fat: bool,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub file_type: u32,
    pub number_of_commands: usize,
    pub entry_point: u64,
    pub is_signed: bool,
    pub segments: Vec<MachoSegment>,
    pub dylibs: Vec<String>,
}

impl MachoInfo {
    pub fn empty() -> Self {
        Self {
            is_macho: false,
            is_64: false,
            is_fat: false,
            cpu_type: 0,
            cpu_subtype: 0,
            file_type: 0,
            number_of_commands: 0,
            entry_point: 0,
            is_signed: false,
            segments: Vec::new(),
            dylibs: Vec::new(),
        }
    }

    pub fn get_segment(&self, name: &str) -> Option<&MachoSegment> {
        self.segments
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
    }

    pub fn get_section(&self, segname: &str, sectname: &str) -> Option<&MachoSection> {
        self.segments
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(segname))
            .and_then(|seg| {
                seg.sections
                    .iter()
                    .find(|sec| sec.sectname.eq_ignore_ascii_case(sectname))
            })
    }

    pub fn has_dylib(&self, target_dylib: &str) -> bool {
        let clean = target_dylib.to_ascii_lowercase();
        self.dylibs.iter().any(|d| {
            let dl = d.to_ascii_lowercase();
            dl == clean || dl.ends_with(&format!("/{}", clean)) || dl.contains(&clean)
        })
    }
}

impl fmt::Display for MachoInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Mach-O: 64-bit={}, CPU={:#x}, Cmds={}, Segments={}, Signed={}",
            self.is_64,
            self.cpu_type,
            self.number_of_commands,
            self.segments.len(),
            self.is_signed
        )
    }
}

pub fn parse_macho(data: &[u8]) -> Option<MachoInfo> {
    if data.len() < 4 {
        return None;
    }

    let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

    match magic {
        // Universal / FAT
        0xCAFEBABE | 0xBEBAFECA => parse_fat_macho(data, magic == 0xCAFEBABE),
        // 64-bit Mach-O (Little / Big Endian)
        0xFEEDFACF | 0xCFFAEDFE => {
            let is_little_endian =
                magic == 0xCFFAEDFE || (magic == 0xFEEDFACF && cfg!(target_endian = "little"));
            parse_single_macho(data, true, is_little_endian)
        }
        // 32-bit Mach-O (Little / Big Endian)
        0xFEEDFACE | 0xCEFAEDFE => {
            let is_little_endian =
                magic == 0xCEFAEDFE || (magic == 0xFEEDFACE && cfg!(target_endian = "little"));
            parse_single_macho(data, false, is_little_endian)
        }
        _ => None,
    }
}

fn parse_fat_macho(data: &[u8], is_big_endian: bool) -> Option<MachoInfo> {
    if data.len() < 8 {
        return None;
    }

    let read_u32 = |offset: usize| -> Option<u32> {
        if offset + 4 <= data.len() {
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            Some(if is_big_endian {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            })
        } else {
            None
        }
    };

    let nfat_arch = read_u32(4)? as usize;
    if nfat_arch == 0 || nfat_arch > 32 {
        return None;
    }

    let mut preferred_offset = None;
    let mut preferred_size = None;
    let mut fallback_offset = None;
    let mut fallback_size = None;

    for i in 0..nfat_arch {
        let arch_offset = 8 + (i * 20);
        if arch_offset + 20 > data.len() {
            break;
        }

        let cputype = read_u32(arch_offset)?;
        let offset = read_u32(arch_offset + 8)? as usize;
        let size = read_u32(arch_offset + 12)? as usize;

        if fallback_offset.is_none() {
            fallback_offset = Some(offset);
            fallback_size = Some(size);
        }

        if (cputype & 0x01000000) != 0 {
            preferred_offset = Some(offset);
            preferred_size = Some(size);
            break;
        }
    }

    let slice_offset = preferred_offset.or(fallback_offset)?;
    let slice_size = preferred_size.or(fallback_size)?;

    if slice_offset + slice_size <= data.len() {
        let mut info = parse_macho(&data[slice_offset..slice_offset + slice_size])?;
        info.is_fat = true;
        Some(info)
    } else {
        None
    }
}

fn parse_single_macho(data: &[u8], is_64: bool, is_little_endian: bool) -> Option<MachoInfo> {
    let header_size = if is_64 { 32 } else { 28 };
    if data.len() < header_size {
        return None;
    }

    let read_u32 = |offset: usize| -> Option<u32> {
        if offset + 4 <= data.len() {
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            Some(if is_little_endian {
                u32::from_le_bytes(bytes)
            } else {
                u32::from_be_bytes(bytes)
            })
        } else {
            None
        }
    };

    let read_u64 = |offset: usize| -> Option<u64> {
        if offset + 8 <= data.len() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&data[offset..offset + 8]);
            Some(if is_little_endian {
                u64::from_le_bytes(bytes)
            } else {
                u64::from_be_bytes(bytes)
            })
        } else {
            None
        }
    };

    let cpu_type = read_u32(4)?;
    let cpu_subtype = read_u32(8)?;
    let file_type = read_u32(12)?;
    let ncmds = read_u32(16)? as usize;

    let mut segments = Vec::new();
    let mut dylibs = Vec::new();
    let mut is_signed = false;
    let mut entry_point = 0u64;

    let mut cmd_offset = header_size;

    for _ in 0..ncmds {
        if cmd_offset + 8 > data.len() {
            break;
        }

        let cmd = read_u32(cmd_offset)?;
        let cmdsize = read_u32(cmd_offset + 4)? as usize;

        if cmdsize < 8 || cmd_offset + cmdsize > data.len() {
            break;
        }

        match cmd {
            // LC_SEGMENT_64
            0x19 if is_64 => {
                if cmdsize >= 72 {
                    let segname_raw = &data[cmd_offset + 8..cmd_offset + 24];
                    let segname = String::from_utf8_lossy(segname_raw)
                        .trim_matches('\0')
                        .to_string();
                    let vmaddr = read_u64(cmd_offset + 24).unwrap_or(0);
                    let vmsize = read_u64(cmd_offset + 32).unwrap_or(0);
                    let fileoff = read_u64(cmd_offset + 40).unwrap_or(0);
                    let filesize = read_u64(cmd_offset + 48).unwrap_or(0);
                    let maxprot = read_u32(cmd_offset + 56).unwrap_or(0);
                    let initprot = read_u32(cmd_offset + 60).unwrap_or(0);
                    let nsects = read_u32(cmd_offset + 64).unwrap_or(0) as usize;

                    let mut sections = Vec::with_capacity(nsects);
                    let mut sect_offset = cmd_offset + 72;

                    for _ in 0..nsects {
                        if sect_offset + 80 > cmd_offset + cmdsize || sect_offset + 80 > data.len()
                        {
                            break;
                        }

                        let sectname_raw = &data[sect_offset..sect_offset + 16];
                        let sectname = String::from_utf8_lossy(sectname_raw)
                            .trim_matches('\0')
                            .to_string();
                        let s_segname_raw = &data[sect_offset + 16..sect_offset + 32];
                        let s_segname = String::from_utf8_lossy(s_segname_raw)
                            .trim_matches('\0')
                            .to_string();

                        let s_addr = read_u64(sect_offset + 32).unwrap_or(0);
                        let s_size = read_u64(sect_offset + 40).unwrap_or(0);
                        let s_offset = read_u32(sect_offset + 48).unwrap_or(0);
                        let s_flags = read_u32(sect_offset + 64).unwrap_or(0);

                        let is_executable = (initprot & 0x04) != 0 || (s_flags & 0x400) != 0;
                        let is_writable = (initprot & 0x02) != 0;

                        let s_off_usize = s_offset as usize;
                        let s_sz_usize = s_size as usize;
                        let entropy = if s_sz_usize > 0 && s_off_usize + s_sz_usize <= data.len() {
                            shannon_entropy(&data[s_off_usize..s_off_usize + s_sz_usize])
                        } else {
                            0.0
                        };

                        sections.push(MachoSection {
                            sectname,
                            segname: s_segname,
                            addr: s_addr,
                            size: s_size,
                            offset: s_offset,
                            entropy,
                            is_executable,
                            is_writable,
                        });

                        sect_offset += 80;
                    }

                    segments.push(MachoSegment {
                        name: segname,
                        vmaddr,
                        vmsize,
                        fileoff,
                        filesize,
                        maxprot,
                        initprot,
                        sections,
                    });
                }
            }
            // LC_SEGMENT (32-bit)
            0x01 if !is_64 => {
                if cmdsize >= 56 {
                    let segname_raw = &data[cmd_offset + 8..cmd_offset + 24];
                    let segname = String::from_utf8_lossy(segname_raw)
                        .trim_matches('\0')
                        .to_string();
                    let vmaddr = read_u32(cmd_offset + 24).unwrap_or(0) as u64;
                    let vmsize = read_u32(cmd_offset + 28).unwrap_or(0) as u64;
                    let fileoff = read_u32(cmd_offset + 32).unwrap_or(0) as u64;
                    let filesize = read_u32(cmd_offset + 36).unwrap_or(0) as u64;
                    let maxprot = read_u32(cmd_offset + 40).unwrap_or(0);
                    let initprot = read_u32(cmd_offset + 44).unwrap_or(0);
                    let nsects = read_u32(cmd_offset + 48).unwrap_or(0) as usize;

                    let mut sections = Vec::with_capacity(nsects);
                    let mut sect_offset = cmd_offset + 56;

                    for _ in 0..nsects {
                        if sect_offset + 68 > cmd_offset + cmdsize || sect_offset + 68 > data.len()
                        {
                            break;
                        }

                        let sectname_raw = &data[sect_offset..sect_offset + 16];
                        let sectname = String::from_utf8_lossy(sectname_raw)
                            .trim_matches('\0')
                            .to_string();
                        let s_segname_raw = &data[sect_offset + 16..sect_offset + 32];
                        let s_segname = String::from_utf8_lossy(s_segname_raw)
                            .trim_matches('\0')
                            .to_string();

                        let s_addr = read_u32(sect_offset + 32).unwrap_or(0) as u64;
                        let s_size = read_u32(sect_offset + 36).unwrap_or(0) as u64;
                        let s_offset = read_u32(sect_offset + 40).unwrap_or(0);
                        let s_flags = read_u32(sect_offset + 56).unwrap_or(0);

                        let is_executable = (initprot & 0x04) != 0 || (s_flags & 0x400) != 0;
                        let is_writable = (initprot & 0x02) != 0;

                        let s_off_usize = s_offset as usize;
                        let s_sz_usize = s_size as usize;
                        let entropy = if s_sz_usize > 0 && s_off_usize + s_sz_usize <= data.len() {
                            shannon_entropy(&data[s_off_usize..s_off_usize + s_sz_usize])
                        } else {
                            0.0
                        };

                        sections.push(MachoSection {
                            sectname,
                            segname: s_segname,
                            addr: s_addr,
                            size: s_size,
                            offset: s_offset,
                            entropy,
                            is_executable,
                            is_writable,
                        });

                        sect_offset += 68;
                    }

                    segments.push(MachoSegment {
                        name: segname,
                        vmaddr,
                        vmsize,
                        fileoff,
                        filesize,
                        maxprot,
                        initprot,
                        sections,
                    });
                }
            }
            // LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB
            0x0C | 0x80000018 | 0x8000001F => {
                if cmdsize >= 16 {
                    let stroff = read_u32(cmd_offset + 8).unwrap_or(0) as usize;
                    if stroff >= 16 && stroff < cmdsize {
                        let str_start = cmd_offset + stroff;
                        let str_end = (cmd_offset + cmdsize).min(data.len());
                        if str_start < str_end {
                            let raw = &data[str_start..str_end];
                            let name = String::from_utf8_lossy(raw)
                                .trim_end_matches('\0')
                                .to_string();
                            if !name.is_empty() {
                                dylibs.push(name);
                            }
                        }
                    }
                }
            }
            // LC_MAIN (entry point offset)
            0x80000028 => {
                if cmdsize >= 24 {
                    entry_point = read_u64(cmd_offset + 8).unwrap_or(0);
                }
            }
            // LC_CODE_SIGNATURE
            0x1D => {
                is_signed = true;
            }
            _ => {}
        }

        cmd_offset += cmdsize;
    }

    Some(MachoInfo {
        is_macho: true,
        is_64,
        is_fat: false,
        cpu_type,
        cpu_subtype,
        file_type,
        number_of_commands: ncmds,
        entry_point,
        is_signed,
        segments,
        dylibs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_data() {
        assert!(parse_macho(&[]).is_none());
        assert!(parse_macho(&[0, 1, 2]).is_none());
    }

    #[test]
    fn test_mock_macho_64() {
        let mut buf = vec![0u8; 128];
        // Magic 0xFEEDFACF (64-bit)
        buf[0..4].copy_from_slice(&0xFEEDFACFu32.to_ne_bytes());
        // CPU type x86_64
        buf[4..8].copy_from_slice(&0x01000007u32.to_ne_bytes());
        // File type execute (2)
        buf[12..16].copy_from_slice(&2u32.to_ne_bytes());
        // ncmds = 1
        buf[16..20].copy_from_slice(&1u32.to_ne_bytes());
        // sizeofcmds = 72
        buf[20..24].copy_from_slice(&72u32.to_ne_bytes());

        // Command 1: LC_SEGMENT_64 (0x19), size 72
        buf[32..36].copy_from_slice(&0x19u32.to_ne_bytes());
        buf[36..40].copy_from_slice(&72u32.to_ne_bytes());
        // Segment name "__TEXT"
        buf[40..46].copy_from_slice(b"__TEXT");

        let info = parse_macho(&buf).expect("Should parse mock 64-bit Mach-O");
        assert!(info.is_macho);
        assert!(info.is_64);
        assert_eq!(info.segments.len(), 1);
        assert_eq!(info.segments[0].name, "__TEXT");
    }
}
