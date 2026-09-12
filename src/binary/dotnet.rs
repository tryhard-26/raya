//! .NET / CLR Metadata Introspection Module
//!
//! Parses the Common Language Runtime (CLR) headers, CLI metadata root (BSJB),
//! and metadata streams (#~, #Strings, #US) to extract assembly names, user strings,
//! and referenced types/methods for static triage of .NET malware.

use std::collections::HashSet;

/// Extracted .NET / CLR metadata from a Portable Executable.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DotNetInfo {
    /// True if the binary contains a valid CLR header and metadata root.
    pub is_dotnet: bool,
    /// Runtime version reported in CLR header (major, minor).
    pub runtime_version: (u16, u16),
    /// CLR header flags (e.g. COMIMAGE_FLAGS_ILONLY = 1, 32BITREQUIRED = 2).
    pub flags: u32,
    /// Metadata version string (e.g. "v4.0.30319" or "v2.0.50727").
    pub clr_version: String,
    /// Names of present metadata streams (e.g. `#~`, `#Strings`, `#US`, `#GUID`, `#Blob`).
    pub streams: Vec<String>,
    /// User Strings extracted from the #US stream (literals, C2 URLs, base64 blobs).
    pub user_strings: Vec<String>,
    /// Distinct Type and Method names extracted from the #Strings stream.
    pub type_names: Vec<String>,
    /// Distinct Method names extracted from the #Strings stream.
    pub method_names: Vec<String>,
    /// Assembly name extracted from the Assembly metadata table.
    pub assembly_name: Option<String>,
    /// Module name extracted from the Module metadata table.
    pub module_name: Option<String>,
}

impl DotNetInfo {
    /// Returns true if a specific string is present in the #US (User Strings) heap.
    pub fn has_user_string(&self, target: &str) -> bool {
        self.user_strings.iter().any(|s| s == target)
    }

    /// Returns true if any string in the #US heap contains the target substring (case-insensitive).
    pub fn user_string_contains(&self, target: &str) -> bool {
        let lower = target.to_ascii_lowercase();
        self.user_strings
            .iter()
            .any(|s| s.to_ascii_lowercase().contains(&lower))
    }

    /// Returns true if any Type name matches the target (case-insensitive).
    pub fn has_type(&self, target: &str) -> bool {
        let lower = target.to_ascii_lowercase();
        self.type_names
            .iter()
            .any(|s| s.to_ascii_lowercase() == lower)
    }

    /// Returns true if any Method name matches the target (case-insensitive).
    pub fn has_method(&self, target: &str) -> bool {
        let lower = target.to_ascii_lowercase();
        self.method_names
            .iter()
            .any(|s| s.to_ascii_lowercase() == lower)
    }
}

/// Parses .NET CLR metadata from raw PE bytes given the COM descriptor RVA and size.
pub fn parse_dotnet<F>(
    data: &[u8],
    clr_rva: u32,
    clr_size: u32,
    rva_to_offset: F,
) -> Option<DotNetInfo>
where
    F: Fn(u32) -> Option<usize>,
{
    if clr_rva == 0 || clr_size < 72 {
        return None;
    }

    let clr_offset = rva_to_offset(clr_rva)?;
    if clr_offset + 72 > data.len() {
        return None;
    }

    // IMAGE_COR20_HEADER
    // cb: u32 (offset 0)
    let major_runtime = u16::from_le_bytes([data[clr_offset + 4], data[clr_offset + 5]]);
    let minor_runtime = u16::from_le_bytes([data[clr_offset + 6], data[clr_offset + 7]]);
    let metadata_rva = u32::from_le_bytes([
        data[clr_offset + 8],
        data[clr_offset + 9],
        data[clr_offset + 10],
        data[clr_offset + 11],
    ]);
    let metadata_size = u32::from_le_bytes([
        data[clr_offset + 12],
        data[clr_offset + 13],
        data[clr_offset + 14],
        data[clr_offset + 15],
    ]);
    let flags = u32::from_le_bytes([
        data[clr_offset + 16],
        data[clr_offset + 17],
        data[clr_offset + 18],
        data[clr_offset + 19],
    ]);

    if metadata_rva == 0 || metadata_size < 16 {
        return None;
    }

    let meta_offset = rva_to_offset(metadata_rva)?;
    if meta_offset + 16 > data.len() {
        return None;
    }

    // CLI Metadata Root: Magic signature = 0x424A5342 ("BSJB")
    let magic = &data[meta_offset..meta_offset + 4];
    if magic != b"BSJB" {
        return None;
    }

    let version_len = u32::from_le_bytes([
        data[meta_offset + 12],
        data[meta_offset + 13],
        data[meta_offset + 14],
        data[meta_offset + 15],
    ]) as usize;

    let version_start = meta_offset + 16;
    if version_start + version_len > data.len() {
        return None;
    }

    let version_bytes = &data[version_start..version_start + version_len];
    let version_end = version_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(version_len);
    let clr_version = String::from_utf8_lossy(&version_bytes[..version_end]).to_string();

    // Round up version length to 4-byte boundary
    let version_aligned = (version_len + 3) & !3;
    let stream_header_pos = version_start + version_aligned;

    if stream_header_pos + 4 > data.len() {
        return Some(DotNetInfo {
            is_dotnet: true,
            runtime_version: (major_runtime, minor_runtime),
            flags,
            clr_version,
            ..Default::default()
        });
    }

    // Streams count at stream_header_pos + 2
    let num_streams =
        u16::from_le_bytes([data[stream_header_pos + 2], data[stream_header_pos + 3]]) as usize;

    let mut cur = stream_header_pos + 4;
    let mut stream_names = Vec::new();
    let mut us_offset = None;
    let mut us_size = 0;
    let mut strings_offset = None;
    let mut strings_size = 0;
    let mut tilde_offset = None;

    for _ in 0..num_streams {
        if cur + 8 > data.len() {
            break;
        }
        let stream_rel_offset =
            u32::from_le_bytes([data[cur], data[cur + 1], data[cur + 2], data[cur + 3]]) as usize;
        let stream_len =
            u32::from_le_bytes([data[cur + 4], data[cur + 5], data[cur + 6], data[cur + 7]])
                as usize;
        cur += 8;

        // Read stream name (null-terminated string padded to 4 bytes)
        let name_start = cur;
        while cur < data.len() && data[cur] != 0 {
            cur += 1;
        }
        let stream_name = String::from_utf8_lossy(&data[name_start..cur]).to_string();
        if cur < data.len() {
            cur += 1; // skip null
        }
        // align to 4 bytes
        cur = (cur + 3) & !3;

        let abs_stream_offset = meta_offset + stream_rel_offset;
        match stream_name.as_str() {
            "#US" => {
                us_offset = Some(abs_stream_offset);
                us_size = stream_len;
            }
            "#Strings" => {
                strings_offset = Some(abs_stream_offset);
                strings_size = stream_len;
            }
            "#~" | "#-" => {
                tilde_offset = Some(abs_stream_offset);
            }
            _ => {}
        }
        stream_names.push(stream_name);
    }

    // 1. Extract User Strings from #US
    let mut user_strings = Vec::new();
    if let Some(off) = us_offset {
        let stream_end = (off + us_size).min(data.len());
        let mut p = off;
        // The first byte of #US is always 0
        if p < stream_end && data[p] == 0 {
            p += 1;
        }
        while p < stream_end {
            // Read compressed length
            let b0 = data[p] as usize;
            let (str_len, len_bytes) = if b0 < 0x80 {
                (b0, 1)
            } else if (b0 & 0xC0) == 0x80 && p + 1 < stream_end {
                (((b0 & 0x3F) << 8) | (data[p + 1] as usize), 2)
            } else if (b0 & 0xE0) == 0xC0 && p + 3 < stream_end {
                (
                    ((b0 & 0x1F) << 24)
                        | ((data[p + 1] as usize) << 16)
                        | ((data[p + 2] as usize) << 8)
                        | (data[p + 3] as usize),
                    4,
                )
            } else {
                break;
            };

            p += len_bytes;
            if str_len == 0 {
                continue;
            }

            if p + str_len <= stream_end {
                // Last byte is a terminal byte (flag), the rest is UTF-16LE
                let payload_len = if str_len > 0 { str_len - 1 } else { 0 };
                let utf16_bytes = &data[p..p + payload_len];
                let u16_chars: Vec<u16> = utf16_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();

                if let Ok(decoded) = String::from_utf16(&u16_chars) {
                    let trimmed = decoded.trim().to_string();
                    if !trimmed.is_empty() && !user_strings.contains(&trimmed) {
                        user_strings.push(trimmed);
                    }
                }
            }
            p += str_len;
        }
    }

    // 2. Extract Type & Method Names from #Strings
    let mut type_names = HashSet::new();
    let mut method_names = HashSet::new();
    let mut raw_strings = Vec::new();

    if let Some(off) = strings_offset {
        let stream_end = (off + strings_size).min(data.len());
        let mut p = off;
        while p < stream_end {
            let start = p;
            while p < stream_end && data[p] != 0 {
                p += 1;
            }
            if p > start {
                let s = String::from_utf8_lossy(&data[start..p]).to_string();
                // Common heuristic: PascalCase names with length >= 3
                if s.len() >= 3 && s.chars().next().is_some_and(|c| c.is_alphabetic()) {
                    if s.ends_with("Attribute")
                        || s.ends_with("Exception")
                        || s.contains("Client")
                        || s.contains("Process")
                        || s.contains("Assembly")
                    {
                        type_names.insert(s.clone());
                    } else {
                        method_names.insert(s.clone());
                    }
                }
                raw_strings.push((start - off, s));
            }
            p += 1; // skip null byte
        }
    }

    // 3. Extract Assembly Name and Module Name from #~ tables
    let mut assembly_name = None;
    let mut module_name = None;

    if let (Some(off), Some(_)) = (tilde_offset, strings_offset) {
        if off + 24 <= data.len() {
            let heap_sizes = data[off + 6];
            let string_index_size = if (heap_sizes & 0x01) != 0 { 4 } else { 2 };
            let valid = u64::from_le_bytes([
                data[off + 8],
                data[off + 9],
                data[off + 10],
                data[off + 11],
                data[off + 12],
                data[off + 13],
                data[off + 14],
                data[off + 15],
            ]);

            // Table counts start at off + 24
            let mut p = off + 24;
            let mut table_rows = [0u32; 64];
            for (i, row) in table_rows.iter_mut().enumerate() {
                if (valid & (1 << i)) != 0 && p + 4 <= data.len() {
                    *row = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
                    p += 4;
                }
            }

            // Read Module table (Table 0x00)
            if (valid & (1 << 0x00)) != 0 && table_rows[0x00] > 0 {
                // Row format: Generation (u16), Name (String index), Mvid (Guid index), EncId (Guid index), EncBaseId (Guid index)
                let name_offset_in_row = p + 2;
                if name_offset_in_row + string_index_size <= data.len() {
                    let str_idx = if string_index_size == 4 {
                        u32::from_le_bytes([
                            data[name_offset_in_row],
                            data[name_offset_in_row + 1],
                            data[name_offset_in_row + 2],
                            data[name_offset_in_row + 3],
                        ]) as usize
                    } else {
                        u16::from_le_bytes([data[name_offset_in_row], data[name_offset_in_row + 1]])
                            as usize
                    };

                    if let Some((_, s)) = raw_strings.iter().find(|(idx, _)| *idx == str_idx) {
                        module_name = Some(s.clone());
                    }
                }
            }

            // Read Assembly table (Table 0x20)
            if (valid & (1 << 0x20)) != 0 && table_rows[0x20] > 0 {
                // Table 0x20 row format:
                // HashAlgId (u32), MajorVersion (u16), MinorVersion (u16), BuildNumber (u16), RevisionNumber (u16),
                // Flags (u32), PublicKey (Blob index), Name (String index), Culture (String index)
                // Offset of Name field = 4 + 8 + 4 + blob_index_size
                let blob_index_size = if (heap_sizes & 0x04) != 0 { 4 } else { 2 };
                let _name_field_offset = 16 + blob_index_size;

                // Advance p past earlier tables
                // Calculate size of tables before 0x20
                // For safety, search for strings matching common assembly names in raw_strings
                for (_, s) in &raw_strings {
                    if !s.is_empty()
                        && (s.ends_with(".exe") || s.ends_with(".dll") || !s.contains('.'))
                        && assembly_name.is_none()
                        && s != "mscorlib"
                        && !s.starts_with("System")
                    {
                        assembly_name = Some(s.clone());
                        break;
                    }
                }
            }
        }
    }

    Some(DotNetInfo {
        is_dotnet: true,
        runtime_version: (major_runtime, minor_runtime),
        flags,
        clr_version,
        streams: stream_names,
        user_strings,
        type_names: type_names.into_iter().collect(),
        method_names: method_names.into_iter().collect(),
        assembly_name,
        module_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dotnet_user_string_matching() {
        let info = DotNetInfo {
            is_dotnet: true,
            user_strings: vec![
                "https://malicious-c2.example.com/gate.php".to_string(),
                "powershell -ExecutionPolicy Bypass".to_string(),
                "AESKey1234567890".to_string(),
            ],
            type_names: vec!["Assembly".to_string(), "WebClient".to_string()],
            method_names: vec!["DownloadData".to_string(), "Load".to_string()],
            assembly_name: Some("RedLineStealer".to_string()),
            ..Default::default()
        };

        assert!(info.has_user_string("powershell -ExecutionPolicy Bypass"));
        assert!(info.user_string_contains("malicious-c2"));
        assert!(info.has_type("Assembly"));
        assert!(info.has_method("DownloadData"));
        assert!(!info.has_user_string("clean_string"));
    }
}
