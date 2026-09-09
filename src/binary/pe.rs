use crate::entropy::shannon_entropy;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
    pub entropy: f64,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PeImport {
    pub dll: String,
    pub functions: Vec<String>,
    pub ordinals: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RichEntry {
    pub comp_id: u16,
    pub product_id: u16,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PeInfo {
    pub is_pe: bool,
    pub is_pe32_plus: bool,
    pub is_dll: bool,
    pub machine: u16,
    pub entry_point: u64,
    pub image_base: u64,
    pub number_of_sections: usize,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImport>,
    pub exports: Vec<String>,
    pub has_rich_header: bool,
    pub rich_entries: Vec<RichEntry>,
    pub is_signed: bool,
    pub security_dir_size: u32,
}

impl PeInfo {
    pub fn empty() -> Self {
        Self {
            is_pe: false,
            is_pe32_plus: false,
            is_dll: false,
            machine: 0,
            entry_point: 0,
            image_base: 0,
            number_of_sections: 0,
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            has_rich_header: false,
            rich_entries: Vec::new(),
            is_signed: false,
            security_dir_size: 0,
        }
    }

    pub fn has_rich_comp_id(&self, target_comp_id: u16) -> bool {
        self.rich_entries
            .iter()
            .any(|e| e.comp_id == target_comp_id)
    }

    pub fn has_rich_product_id(&self, target_product_id: u16) -> bool {
        self.rich_entries
            .iter()
            .any(|e| e.product_id == target_product_id)
    }

    pub fn get_section(&self, name: &str) -> Option<&PeSection> {
        self.sections.iter().find(|s| {
            s.name.eq_ignore_ascii_case(name)
                || s.name.trim_end_matches('\0').eq_ignore_ascii_case(name)
        })
    }

    pub fn has_import(&self, target_dll: &str, target_func: &str) -> bool {
        let clean_dll = target_dll.to_ascii_lowercase();
        let stripped_dll = clean_dll.trim_end_matches(".dll");

        for imp in &self.imports {
            let imp_dll = imp.dll.to_ascii_lowercase();
            let imp_stripped = imp_dll.trim_end_matches(".dll");

            if imp_dll == clean_dll || imp_stripped == stripped_dll {
                for func in &imp.functions {
                    if func.eq_ignore_ascii_case(target_func) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn has_export(&self, target_func: &str) -> bool {
        self.exports
            .iter()
            .any(|e| e.eq_ignore_ascii_case(target_func))
    }

    pub fn has_rwx_section(&self) -> bool {
        self.sections
            .iter()
            .any(|s| s.is_readable && s.is_writable && s.is_executable)
    }

    pub fn entry_point_in_section(&self, name: &str) -> bool {
        if let Some(sec) = self.get_section(name) {
            let ep = self.entry_point as u32;
            ep >= sec.virtual_address
                && ep < (sec.virtual_address + sec.virtual_size.max(sec.raw_size))
        } else {
            false
        }
    }

    pub fn has_instruction_sequence(&self, data: &[u8], seq: &[&str]) -> bool {
        let bitness = if self.is_pe32_plus { 64 } else { 32 };
        for sec in &self.sections {
            if sec.is_executable && sec.raw_size > 0 {
                let start = sec.raw_offset as usize;
                let end = (start + sec.raw_size as usize).min(data.len());
                if start < data.len()
                    && end > start
                    && crate::binary::disasm::has_mnemonic_sequence(&data[start..end], bitness, seq)
                {
                    return true;
                }
            }
        }
        false
    }

    pub fn has_instruction(&self, data: &[u8], instr: &str) -> bool {
        let bitness = if self.is_pe32_plus { 64 } else { 32 };
        for sec in &self.sections {
            if sec.is_executable && sec.raw_size > 0 {
                let start = sec.raw_offset as usize;
                let end = (start + sec.raw_size as usize).min(data.len());
                if start < data.len()
                    && end > start
                    && crate::binary::disasm::has_mnemonic(&data[start..end], bitness, instr)
                {
                    return true;
                }
            }
        }
        false
    }
}

pub fn parse_pe(data: &[u8]) -> Option<PeInfo> {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return None;
    }

    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    let coff_offset = e_lfanew + 4;
    let machine = u16::from_le_bytes([data[coff_offset], data[coff_offset + 1]]);
    let num_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]) as usize;
    let size_of_opt_header =
        u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;
    let characteristics = u16::from_le_bytes([data[coff_offset + 18], data[coff_offset + 19]]);
    let is_dll = (characteristics & 0x2000) != 0;

    let opt_offset = coff_offset + 20;
    if opt_offset + size_of_opt_header > data.len() || size_of_opt_header < 2 {
        return None;
    }

    let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    let is_pe32_plus = opt_magic == 0x20B;

    let (entry_point, image_base, data_dirs_offset) = if is_pe32_plus {
        if size_of_opt_header < 112 {
            return None;
        }
        let ep = u32::from_le_bytes([
            data[opt_offset + 16],
            data[opt_offset + 17],
            data[opt_offset + 18],
            data[opt_offset + 19],
        ]) as u64;
        let base = u64::from_le_bytes([
            data[opt_offset + 24],
            data[opt_offset + 25],
            data[opt_offset + 26],
            data[opt_offset + 27],
            data[opt_offset + 28],
            data[opt_offset + 29],
            data[opt_offset + 30],
            data[opt_offset + 31],
        ]);
        (ep, base, opt_offset + 112)
    } else {
        if size_of_opt_header < 96 {
            return None;
        }
        let ep = u32::from_le_bytes([
            data[opt_offset + 16],
            data[opt_offset + 17],
            data[opt_offset + 18],
            data[opt_offset + 19],
        ]) as u64;
        let base = u32::from_le_bytes([
            data[opt_offset + 28],
            data[opt_offset + 29],
            data[opt_offset + 30],
            data[opt_offset + 31],
        ]) as u64;
        (ep, base, opt_offset + 96)
    };

    // Extract Export and Import data directories
    let (export_rva, _export_size) = if data_dirs_offset + 8 <= opt_offset + size_of_opt_header {
        let rva = u32::from_le_bytes([
            data[data_dirs_offset],
            data[data_dirs_offset + 1],
            data[data_dirs_offset + 2],
            data[data_dirs_offset + 3],
        ]);
        let size = u32::from_le_bytes([
            data[data_dirs_offset + 4],
            data[data_dirs_offset + 5],
            data[data_dirs_offset + 6],
            data[data_dirs_offset + 7],
        ]);
        (rva, size)
    } else {
        (0, 0)
    };

    let (import_rva, _import_size) = if data_dirs_offset + 16 <= opt_offset + size_of_opt_header {
        let rva = u32::from_le_bytes([
            data[data_dirs_offset + 8],
            data[data_dirs_offset + 9],
            data[data_dirs_offset + 10],
            data[data_dirs_offset + 11],
        ]);
        let size = u32::from_le_bytes([
            data[data_dirs_offset + 12],
            data[data_dirs_offset + 13],
            data[data_dirs_offset + 14],
            data[data_dirs_offset + 15],
        ]);
        (rva, size)
    } else {
        (0, 0)
    };

    // Security Directory (Index 4 in Data Directories, each entry 8 bytes: offset/RVA + size)
    let (sec_dir_offset, sec_dir_size) =
        if data_dirs_offset + 32 + 8 <= opt_offset + size_of_opt_header {
            let raw_off = u32::from_le_bytes([
                data[data_dirs_offset + 32],
                data[data_dirs_offset + 33],
                data[data_dirs_offset + 34],
                data[data_dirs_offset + 35],
            ]);
            let size = u32::from_le_bytes([
                data[data_dirs_offset + 36],
                data[data_dirs_offset + 37],
                data[data_dirs_offset + 38],
                data[data_dirs_offset + 39],
            ]);
            (raw_off, size)
        } else {
            (0, 0)
        };

    let is_signed = sec_dir_size > 0
        && sec_dir_offset > 0
        && (sec_dir_offset as usize + sec_dir_size as usize) <= data.len();

    let (has_rich_header, rich_entries) = parse_rich_header(data, e_lfanew);

    // Parse Sections
    let section_headers_offset = opt_offset + size_of_opt_header;
    let mut sections = Vec::new();

    for i in 0..num_sections {
        let sec_offset = section_headers_offset + (i * 40);
        if sec_offset + 40 > data.len() {
            break;
        }

        let name_bytes = &data[sec_offset..sec_offset + 8];
        let name_end = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let sec_name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

        let virt_size = u32::from_le_bytes([
            data[sec_offset + 8],
            data[sec_offset + 9],
            data[sec_offset + 10],
            data[sec_offset + 11],
        ]);
        let virt_addr = u32::from_le_bytes([
            data[sec_offset + 12],
            data[sec_offset + 13],
            data[sec_offset + 14],
            data[sec_offset + 15],
        ]);
        let raw_size = u32::from_le_bytes([
            data[sec_offset + 16],
            data[sec_offset + 17],
            data[sec_offset + 18],
            data[sec_offset + 19],
        ]);
        let raw_offset = u32::from_le_bytes([
            data[sec_offset + 20],
            data[sec_offset + 21],
            data[sec_offset + 22],
            data[sec_offset + 23],
        ]);
        let chars = u32::from_le_bytes([
            data[sec_offset + 36],
            data[sec_offset + 37],
            data[sec_offset + 38],
            data[sec_offset + 39],
        ]);

        let is_readable = (chars & 0x4000_0000) != 0;
        let is_writable = (chars & 0x8000_0000) != 0;
        let is_executable = (chars & 0x2000_0000) != 0;

        // Calculate section entropy
        let entropy = if raw_size > 0 && (raw_offset as usize) < data.len() {
            let start = raw_offset as usize;
            let end = (start + raw_size as usize).min(data.len());
            shannon_entropy(&data[start..end])
        } else {
            0.0
        };

        sections.push(PeSection {
            name: sec_name,
            virtual_size: virt_size,
            virtual_address: virt_addr,
            raw_size,
            raw_offset,
            characteristics: chars,
            entropy,
            is_readable,
            is_writable,
            is_executable,
        });
    }

    // Helper closure to translate RVA to file offset
    let rva_to_offset = |rva: u32| -> Option<usize> {
        if rva == 0 {
            return None;
        }
        for sec in &sections {
            let sec_size = sec.virtual_size.max(sec.raw_size);
            if rva >= sec.virtual_address && rva < sec.virtual_address + sec_size {
                let delta = rva - sec.virtual_address;
                let offset = sec.raw_offset as usize + delta as usize;
                if offset < data.len() {
                    return Some(offset);
                }
            }
        }
        None
    };

    // Helper to read null-terminated ASCII string at file offset
    let read_ascii_string = |offset: usize| -> Option<String> {
        if offset >= data.len() {
            return None;
        }
        let mut end = offset;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }
        if end > offset {
            Some(String::from_utf8_lossy(&data[offset..end]).to_string())
        } else {
            None
        }
    };

    // Parse Imports
    let mut imports = Vec::new();
    if import_rva > 0 {
        if let Some(mut desc_offset) = rva_to_offset(import_rva) {
            // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes
            while desc_offset + 20 <= data.len() {
                let original_first_thunk = u32::from_le_bytes([
                    data[desc_offset],
                    data[desc_offset + 1],
                    data[desc_offset + 2],
                    data[desc_offset + 3],
                ]);
                let name_rva = u32::from_le_bytes([
                    data[desc_offset + 12],
                    data[desc_offset + 13],
                    data[desc_offset + 14],
                    data[desc_offset + 15],
                ]);
                let first_thunk = u32::from_le_bytes([
                    data[desc_offset + 16],
                    data[desc_offset + 17],
                    data[desc_offset + 18],
                    data[desc_offset + 19],
                ]);

                // All zeros indicates end of import descriptor array
                if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                    break;
                }

                if let Some(name_offset) = rva_to_offset(name_rva) {
                    if let Some(dll_name) = read_ascii_string(name_offset) {
                        let thunk_rva = if original_first_thunk != 0 {
                            original_first_thunk
                        } else {
                            first_thunk
                        };

                        let mut functions = Vec::new();
                        let mut ordinals = Vec::new();

                        if let Some(mut thunk_offset) = rva_to_offset(thunk_rva) {
                            loop {
                                if is_pe32_plus {
                                    if thunk_offset + 8 > data.len() {
                                        break;
                                    }
                                    let thunk_val = u64::from_le_bytes([
                                        data[thunk_offset],
                                        data[thunk_offset + 1],
                                        data[thunk_offset + 2],
                                        data[thunk_offset + 3],
                                        data[thunk_offset + 4],
                                        data[thunk_offset + 5],
                                        data[thunk_offset + 6],
                                        data[thunk_offset + 7],
                                    ]);
                                    if thunk_val == 0 {
                                        break;
                                    }
                                    if (thunk_val & 0x8000_0000_0000_0000) != 0 {
                                        ordinals.push((thunk_val & 0xFFFF) as u16);
                                    } else {
                                        let hint_name_rva = (thunk_val & 0x7FFF_FFFF) as u32;
                                        if let Some(hn_offset) = rva_to_offset(hint_name_rva) {
                                            // Skip 2-byte hint
                                            if let Some(fn_name) = read_ascii_string(hn_offset + 2)
                                            {
                                                functions.push(fn_name);
                                            }
                                        }
                                    }
                                    thunk_offset += 8;
                                } else {
                                    if thunk_offset + 4 > data.len() {
                                        break;
                                    }
                                    let thunk_val = u32::from_le_bytes([
                                        data[thunk_offset],
                                        data[thunk_offset + 1],
                                        data[thunk_offset + 2],
                                        data[thunk_offset + 3],
                                    ]);
                                    if thunk_val == 0 {
                                        break;
                                    }
                                    if (thunk_val & 0x8000_0000) != 0 {
                                        ordinals.push((thunk_val & 0xFFFF) as u16);
                                    } else {
                                        let hint_name_rva = thunk_val & 0x7FFF_FFFF;
                                        if let Some(hn_offset) = rva_to_offset(hint_name_rva) {
                                            if let Some(fn_name) = read_ascii_string(hn_offset + 2)
                                            {
                                                functions.push(fn_name);
                                            }
                                        }
                                    }
                                    thunk_offset += 4;
                                }
                            }
                        }

                        imports.push(PeImport {
                            dll: dll_name,
                            functions,
                            ordinals,
                        });
                    }
                }

                desc_offset += 20;
            }
        }
    }

    // Parse Exports
    let mut exports = Vec::new();
    if export_rva > 0 {
        if let Some(exp_offset) = rva_to_offset(export_rva) {
            // IMAGE_EXPORT_DIRECTORY is 40 bytes
            if exp_offset + 40 <= data.len() {
                let number_of_names = u32::from_le_bytes([
                    data[exp_offset + 24],
                    data[exp_offset + 25],
                    data[exp_offset + 26],
                    data[exp_offset + 27],
                ]) as usize;
                let address_of_names = u32::from_le_bytes([
                    data[exp_offset + 32],
                    data[exp_offset + 33],
                    data[exp_offset + 34],
                    data[exp_offset + 35],
                ]);

                if let Some(mut names_offset) = rva_to_offset(address_of_names) {
                    for _ in 0..number_of_names.min(4096) {
                        if names_offset + 4 > data.len() {
                            break;
                        }
                        let name_rva = u32::from_le_bytes([
                            data[names_offset],
                            data[names_offset + 1],
                            data[names_offset + 2],
                            data[names_offset + 3],
                        ]);
                        if let Some(fn_name_offset) = rva_to_offset(name_rva) {
                            if let Some(exp_name) = read_ascii_string(fn_name_offset) {
                                exports.push(exp_name);
                            }
                        }
                        names_offset += 4;
                    }
                }
            }
        }
    }

    Some(PeInfo {
        is_pe: true,
        is_pe32_plus,
        is_dll,
        machine,
        entry_point,
        image_base,
        number_of_sections: sections.len(),
        sections,
        imports,
        exports,
        has_rich_header,
        rich_entries,
        is_signed,
        security_dir_size: sec_dir_size,
    })
}

fn parse_rich_header(data: &[u8], e_lfanew: usize) -> (bool, Vec<RichEntry>) {
    if e_lfanew < 0x80 || e_lfanew > data.len() {
        return (false, Vec::new());
    }
    let stub = &data[0x40..e_lfanew];
    let mut rich_pos = None;
    for i in (0..stub.len().saturating_sub(7)).step_by(4) {
        if &stub[i..i + 4] == b"Rich" {
            rich_pos = Some(0x40 + i);
            break;
        }
    }

    let rich_off = match rich_pos {
        Some(pos) => pos,
        None => return (false, Vec::new()),
    };

    if rich_off + 8 > e_lfanew {
        return (false, Vec::new());
    }

    let xor_key = u32::from_le_bytes([
        data[rich_off + 4],
        data[rich_off + 5],
        data[rich_off + 6],
        data[rich_off + 7],
    ]);

    let dans_marker = u32::from_le_bytes(*b"DanS") ^ xor_key;

    let mut dans_pos = None;
    let mut curr = rich_off.saturating_sub(4);
    while curr >= 0x40 {
        let val = u32::from_le_bytes([data[curr], data[curr + 1], data[curr + 2], data[curr + 3]]);
        if val == dans_marker {
            dans_pos = Some(curr);
            break;
        }
        if curr < 4 {
            break;
        }
        curr -= 4;
    }

    let start_entries = match dans_pos {
        Some(pos) => pos + 16,
        None => return (false, Vec::new()),
    };

    if start_entries >= rich_off {
        return (true, Vec::new());
    }

    let mut entries = Vec::new();
    let mut off = start_entries;
    while off + 8 <= rich_off {
        let dword1 =
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) ^ xor_key;
        let dword2 =
            u32::from_le_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]])
                ^ xor_key;

        let comp_id = (dword1 & 0xFFFF) as u16;
        let product_id = ((dword1 >> 16) & 0xFFFF) as u16;
        let count = dword2;

        entries.push(RichEntry {
            comp_id,
            product_id,
            count,
        });

        off += 8;
    }

    (true, entries)
}
