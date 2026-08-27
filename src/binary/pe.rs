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
        }
    }

    pub fn get_section(&self, name: &str) -> Option<&PeSection> {
        self.sections.iter().find(|s| {
            s.name.eq_ignore_ascii_case(name) || s.name.trim_end_matches('\0').eq_ignore_ascii_case(name)
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
            ep >= sec.virtual_address && ep < (sec.virtual_address + sec.virtual_size.max(sec.raw_size))
        } else {
            false
        }
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
    let size_of_opt_header = u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;
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
                                            if let Some(fn_name) = read_ascii_string(hn_offset + 2) {
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
                                            if let Some(fn_name) = read_ascii_string(hn_offset + 2) {
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
    })
}
