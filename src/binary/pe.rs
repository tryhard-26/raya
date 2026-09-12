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
    pub rich_checksum_mismatch: bool,
    pub is_rich_checksum_valid: Option<bool>,
    pub is_signed: bool,
    pub security_dir_size: u32,
    pub imphash: Option<String>,
    pub rich_hash: Option<String>,
    pub has_tls: bool,
    pub tls_callbacks: Vec<u64>,
    pub exphash: Option<String>,
    pub dotnet: Option<crate::binary::dotnet::DotNetInfo>,
    pub stack_strings: Vec<crate::binary::disasm::StackString>,
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
            rich_checksum_mismatch: false,
            is_rich_checksum_valid: None,
            is_signed: false,
            security_dir_size: 0,
            imphash: None,
            rich_hash: None,
            has_tls: false,
            tls_callbacks: Vec::new(),
            exphash: None,
            dotnet: None,
            stack_strings: Vec::new(),
        }
    }

    pub fn has_imphash(&self, target: &str) -> bool {
        self.imphash
            .as_deref()
            .map(|h| h.eq_ignore_ascii_case(target))
            .unwrap_or(false)
    }

    pub fn has_rich_hash(&self, target: &str) -> bool {
        self.rich_hash
            .as_deref()
            .map(|h| h.eq_ignore_ascii_case(target))
            .unwrap_or(false)
    }

    pub fn rich_checksum_mismatch(&self) -> bool {
        self.rich_checksum_mismatch
    }

    pub fn has_dotnet(&self) -> bool {
        self.dotnet.as_ref().map(|d| d.is_dotnet).unwrap_or(false)
    }

    pub fn has_stack_string(&self, target: &str) -> bool {
        let lower = target.to_ascii_lowercase();
        self.stack_strings
            .iter()
            .any(|s| s.value.to_ascii_lowercase().contains(&lower))
    }

    pub fn has_exphash(&self, target: &str) -> bool {
        self.exphash
            .as_deref()
            .map(|h| h.eq_ignore_ascii_case(target))
            .unwrap_or(false)
    }

    pub fn has_tls(&self) -> bool {
        self.has_tls
    }

    pub fn number_of_tls_callbacks(&self) -> usize {
        self.tls_callbacks.len()
    }

    pub fn has_section(&self, target: &str) -> bool {
        self.get_section(target).is_some()
    }

    pub fn number_of_imports(&self) -> usize {
        self.imports
            .iter()
            .map(|i| i.functions.len() + i.ordinals.len())
            .sum()
    }

    pub fn number_of_exports(&self) -> usize {
        self.exports.len()
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

    pub fn rwx_sections(&self) -> Vec<&PeSection> {
        self.sections
            .iter()
            .filter(|s| s.is_readable && s.is_writable && s.is_executable)
            .collect()
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

    pub fn find_basic_block_sequence(&self, data: &[u8], seq: &[&str]) -> Option<u64> {
        let bitness = if self.is_pe32_plus { 64 } else { 32 };
        for sec in &self.sections {
            if sec.is_executable && sec.raw_size > 0 {
                let start = sec.raw_offset as usize;
                let end = (start + sec.raw_size as usize).min(data.len());
                if start < data.len() && end > start {
                    let base_va = self.image_base + sec.virtual_address as u64;
                    if let Some(va) = crate::binary::disasm::find_basic_block_sequence(
                        &data[start..end],
                        bitness,
                        base_va,
                        seq,
                    ) {
                        return Some(va);
                    }
                }
            }
        }
        None
    }

    pub fn has_basic_block_sequence(&self, data: &[u8], seq: &[&str]) -> bool {
        self.find_basic_block_sequence(data, seq).is_some()
    }

    pub fn find_basic_block_all(&self, data: &[u8], required: &[&str]) -> Option<u64> {
        let bitness = if self.is_pe32_plus { 64 } else { 32 };
        for sec in &self.sections {
            if sec.is_executable && sec.raw_size > 0 {
                let start = sec.raw_offset as usize;
                let end = (start + sec.raw_size as usize).min(data.len());
                if start < data.len() && end > start {
                    let base_va = self.image_base + sec.virtual_address as u64;
                    if let Some(va) = crate::binary::disasm::find_basic_block_all(
                        &data[start..end],
                        bitness,
                        base_va,
                        required,
                    ) {
                        return Some(va);
                    }
                }
            }
        }
        None
    }

    pub fn has_basic_block_all(&self, data: &[u8], required: &[&str]) -> bool {
        self.find_basic_block_all(data, required).is_some()
    }

    pub fn find_function_sequence(&self, data: &[u8], seq: &[&str]) -> Option<u64> {
        let bitness = if self.is_pe32_plus { 64 } else { 32 };
        for sec in &self.sections {
            if sec.is_executable && sec.raw_size > 0 {
                let start = sec.raw_offset as usize;
                let end = (start + sec.raw_size as usize).min(data.len());
                if start < data.len() && end > start {
                    let base_va = self.image_base + sec.virtual_address as u64;
                    if let Some(va) = crate::binary::disasm::find_function_sequence(
                        &data[start..end],
                        bitness,
                        base_va,
                        seq,
                    ) {
                        return Some(va);
                    }
                }
            }
        }
        None
    }

    pub fn has_function_sequence(&self, data: &[u8], seq: &[&str]) -> bool {
        self.find_function_sequence(data, seq).is_some()
    }

    pub fn detect_api_call_arg(
        &self,
        data: &[u8],
        api_name: &str,
        target_val: u64,
    ) -> Option<crate::binary::disasm::ApiCallArgMatch> {
        let is_imported = self.imports.iter().any(|imp| {
            imp.functions
                .iter()
                .any(|f| f.eq_ignore_ascii_case(api_name))
        });

        let has_api_ref = is_imported || {
            let pattern = api_name.as_bytes();
            data.windows(pattern.len()).any(|w| w == pattern)
        };

        if !has_api_ref {
            return None;
        }

        let bitness = if self.is_pe32_plus { 64 } else { 32 };
        for sec in &self.sections {
            if sec.is_executable && sec.raw_size > 0 {
                let start = sec.raw_offset as usize;
                let end = (start + sec.raw_size as usize).min(data.len());
                if start < data.len() && end > start {
                    let base_va = self.image_base + sec.virtual_address as u64;
                    if let Some(m) = crate::binary::disasm::detect_api_call_arguments(
                        &data[start..end],
                        bitness,
                        base_va,
                        api_name,
                        target_val,
                    ) {
                        return Some(m);
                    }
                }
            }
        }
        None
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

    // TLS Directory (Index 9 in Data Directories, each entry 8 bytes: RVA + size)
    let (tls_rva, tls_size) = if data_dirs_offset + 72 + 8 <= opt_offset + size_of_opt_header {
        let rva = u32::from_le_bytes([
            data[data_dirs_offset + 72],
            data[data_dirs_offset + 73],
            data[data_dirs_offset + 74],
            data[data_dirs_offset + 75],
        ]);
        let size = u32::from_le_bytes([
            data[data_dirs_offset + 76],
            data[data_dirs_offset + 77],
            data[data_dirs_offset + 78],
            data[data_dirs_offset + 79],
        ]);
        (rva, size)
    } else {
        (0, 0)
    };

    // CLR Runtime Header Directory (Index 14 in Data Directories, offset 112)
    let (clr_rva, clr_size) = if data_dirs_offset + 112 + 8 <= opt_offset + size_of_opt_header {
        let rva = u32::from_le_bytes([
            data[data_dirs_offset + 112],
            data[data_dirs_offset + 113],
            data[data_dirs_offset + 114],
            data[data_dirs_offset + 115],
        ]);
        let size = u32::from_le_bytes([
            data[data_dirs_offset + 116],
            data[data_dirs_offset + 117],
            data[data_dirs_offset + 118],
            data[data_dirs_offset + 119],
        ]);
        (rva, size)
    } else {
        (0, 0)
    };

    let (
        has_rich_header,
        rich_entries,
        canonical_rich_hash,
        rich_checksum_mismatch,
        is_rich_checksum_valid,
    ) = parse_rich_header(data, e_lfanew);

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
                if delta < sec.raw_size {
                    let offset = sec.raw_offset as usize + delta as usize;
                    if offset < data.len() {
                        return Some(offset);
                    }
                }
            }
        }
        None
    };

    let dotnet = if clr_rva > 0 && clr_size > 0 {
        crate::binary::dotnet::parse_dotnet(data, clr_rva, clr_size, rva_to_offset)
    } else {
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

    // Parse Imports and compute imphash (Mandiant standard)
    let mut imports = Vec::new();
    let mut imphash_items = Vec::new();

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
                        let mut clean_dll = dll_name.to_ascii_lowercase();
                        for ext in [".dll", ".sys", ".ocx"] {
                            if clean_dll.ends_with(ext) {
                                clean_dll.truncate(clean_dll.len() - ext.len());
                                break;
                            }
                        }

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
                                        let ord = (thunk_val & 0xFFFF) as u16;
                                        ordinals.push(ord);
                                        imphash_items.push(format!("{}.ord{}", clean_dll, ord));
                                    } else {
                                        let hint_name_rva = (thunk_val & 0x7FFF_FFFF) as u32;
                                        if let Some(hn_offset) = rva_to_offset(hint_name_rva) {
                                            // Skip 2-byte hint
                                            if let Some(fn_name) = read_ascii_string(hn_offset + 2)
                                            {
                                                imphash_items.push(format!(
                                                    "{}.{}",
                                                    clean_dll,
                                                    fn_name.to_ascii_lowercase()
                                                ));
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
                                        let ord = (thunk_val & 0xFFFF) as u16;
                                        ordinals.push(ord);
                                        imphash_items.push(format!("{}.ord{}", clean_dll, ord));
                                    } else {
                                        let hint_name_rva = thunk_val & 0x7FFF_FFFF;
                                        if let Some(hn_offset) = rva_to_offset(hint_name_rva) {
                                            if let Some(fn_name) = read_ascii_string(hn_offset + 2)
                                            {
                                                imphash_items.push(format!(
                                                    "{}.{}",
                                                    clean_dll,
                                                    fn_name.to_ascii_lowercase()
                                                ));
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

    let imphash = if !imphash_items.is_empty() {
        let joined = imphash_items.join(",");
        Some(crate::hash::compute_md5(joined.as_bytes()))
    } else {
        None
    };

    let rich_hash = canonical_rich_hash.or_else(|| {
        if has_rich_header && !rich_entries.is_empty() {
            let mut parts = Vec::new();
            for e in &rich_entries {
                parts.push(format!("{}:{}:{}", e.comp_id, e.product_id, e.count));
            }
            Some(crate::hash::compute_md5(parts.join(",").as_bytes()))
        } else {
            None
        }
    });

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

    let exphash = if !exports.is_empty() {
        let mut sorted_exports: Vec<String> =
            exports.iter().map(|s| s.to_ascii_lowercase()).collect();
        sorted_exports.sort();
        Some(crate::hash::compute_md5(
            sorted_exports.join(",").as_bytes(),
        ))
    } else {
        None
    };

    // Parse TLS Callbacks
    let mut has_tls = tls_rva > 0 && tls_size > 0;
    let mut tls_callbacks = Vec::new();
    if tls_rva > 0 {
        if let Some(tls_offset) = rva_to_offset(tls_rva) {
            has_tls = true;
            let callbacks_va = if is_pe32_plus {
                if tls_offset + 32 <= data.len() {
                    Some(u64::from_le_bytes([
                        data[tls_offset + 24],
                        data[tls_offset + 25],
                        data[tls_offset + 26],
                        data[tls_offset + 27],
                        data[tls_offset + 28],
                        data[tls_offset + 29],
                        data[tls_offset + 30],
                        data[tls_offset + 31],
                    ]))
                } else {
                    None
                }
            } else if tls_offset + 16 <= data.len() {
                let va = u32::from_le_bytes([
                    data[tls_offset + 12],
                    data[tls_offset + 13],
                    data[tls_offset + 14],
                    data[tls_offset + 15],
                ]);
                Some(va as u64)
            } else {
                None
            };

            if let Some(cb_va) = callbacks_va {
                if cb_va >= image_base {
                    let cb_rva = (cb_va - image_base) as u32;
                    if let Some(mut cb_offset) = rva_to_offset(cb_rva) {
                        let step = if is_pe32_plus { 8 } else { 4 };
                        while cb_offset + step <= data.len() && tls_callbacks.len() < 64 {
                            let val = if is_pe32_plus {
                                u64::from_le_bytes([
                                    data[cb_offset],
                                    data[cb_offset + 1],
                                    data[cb_offset + 2],
                                    data[cb_offset + 3],
                                    data[cb_offset + 4],
                                    data[cb_offset + 5],
                                    data[cb_offset + 6],
                                    data[cb_offset + 7],
                                ])
                            } else {
                                u32::from_le_bytes([
                                    data[cb_offset],
                                    data[cb_offset + 1],
                                    data[cb_offset + 2],
                                    data[cb_offset + 3],
                                ]) as u64
                            };
                            if val == 0 {
                                break;
                            }
                            tls_callbacks.push(val);
                            cb_offset += step;
                        }
                    }
                }
            }
        }
    }

    // Extract stack strings from executable sections
    let mut stack_strings = Vec::new();
    for sec in &sections {
        if sec.is_executable && sec.raw_size > 0 && (sec.raw_offset as usize) < data.len() {
            let start = sec.raw_offset as usize;
            let end = (start + (sec.raw_size as usize).min(256 * 1024)).min(data.len());
            let sec_bytes = &data[start..end];
            let bitness = if is_pe32_plus { 64 } else { 32 };
            let strings = crate::binary::disasm::extract_stack_strings(
                sec_bytes,
                bitness,
                image_base + sec.virtual_address as u64,
            );
            stack_strings.extend(strings);
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
        rich_checksum_mismatch,
        is_rich_checksum_valid,
        is_signed,
        security_dir_size: sec_dir_size,
        imphash,
        rich_hash,
        has_tls,
        tls_callbacks,
        exphash,
        dotnet,
        stack_strings,
    })
}

fn parse_rich_header(
    data: &[u8],
    e_lfanew: usize,
) -> (bool, Vec<RichEntry>, Option<String>, bool, Option<bool>) {
    if e_lfanew < 0x80 || e_lfanew > data.len() {
        return (false, Vec::new(), None, false, None);
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
        None => return (false, Vec::new(), None, false, None),
    };

    if rich_off + 8 > e_lfanew {
        return (false, Vec::new(), None, false, None);
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

    let dans_offset = match dans_pos {
        Some(pos) => pos,
        None => return (false, Vec::new(), None, false, None),
    };

    // Calculate standard Mandiant/pefile Rich header hash (MD5 of decrypted buffer DanS -> Rich)
    let mut decrypted_rich = Vec::with_capacity(rich_off.saturating_sub(dans_offset));
    let mut p = dans_offset;
    while p + 4 <= rich_off {
        let dword = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]) ^ xor_key;
        decrypted_rich.extend_from_slice(&dword.to_le_bytes());
        p += 4;
    }
    let canonical_rich_hash = if !decrypted_rich.is_empty() {
        Some(crate::hash::compute_md5(&decrypted_rich))
    } else {
        None
    };

    let start_entries = dans_offset + 16;
    let mut entries = Vec::new();
    if start_entries < rich_off {
        let mut off = start_entries;
        while off + 8 <= rich_off {
            let dword1 =
                u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                    ^ xor_key;
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
    }

    // Verify Rich Header Checksum against xor_key
    let mut calc_checksum: u32 = e_lfanew as u32;
    for (i, &b) in data.iter().enumerate().take(0x3C.min(data.len())) {
        calc_checksum = calc_checksum.wrapping_add((b as u32).rotate_left((i as u32) & 0x1F));
    }
    if dans_offset > 0x40 {
        for (i, &b) in data
            .iter()
            .enumerate()
            .take(dans_offset.min(data.len()))
            .skip(0x40)
        {
            calc_checksum = calc_checksum.wrapping_add((b as u32).rotate_left((i as u32) & 0x1F));
        }
    }
    for e in &entries {
        let comp_val = ((e.product_id as u32) << 16) | (e.comp_id as u32);
        calc_checksum = calc_checksum.wrapping_add(comp_val.rotate_left(e.count & 0x1F));
    }

    let is_valid = calc_checksum == xor_key;
    let mismatch = !is_valid;

    (true, entries, canonical_rich_hash, mismatch, Some(is_valid))
}
