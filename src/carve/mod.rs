// src/carve/mod.rs
//
// Embedded PE & Overlay Carving Subsystem for Raya 2.0
// Extracts nested PEs, ELFs, archives, and overlay payloads hidden inside binaries.

use crate::entropy::shannon_entropy;
use crate::hash::compute_hashes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedArtifact {
    pub offset: usize,
    pub size: usize,
    pub format: String,
    pub sha256: String,
    pub entropy: f64,
    pub filename: String,
    #[serde(skip)]
    pub data: Vec<u8>,
}

/// Identifies and extracts all embedded executables, archives, and overlays.
pub fn carve_artifacts(data: &[u8]) -> Vec<CarvedArtifact> {
    let mut artifacts = Vec::new();

    // 1. Carve embedded PEs
    carve_pe_executables(data, &mut artifacts);

    // 2. Carve embedded ELFs
    carve_elf_executables(data, &mut artifacts);

    // 3. Carve embedded ZIPs
    carve_zip_archives(data, &mut artifacts);

    // 4. Carve PE overlay if target is a PE
    if let Some(overlay) = carve_pe_overlay(data) {
        artifacts.push(overlay);
    }

    artifacts
}

fn carve_pe_executables(data: &[u8], artifacts: &mut Vec<CarvedArtifact>) {
    let mut i = 0;
    while i + 64 < data.len() {
        if data[i] == b'M' && data[i + 1] == b'Z' {
            let e_lfanew = u32::from_le_bytes([
                data[i + 0x3c],
                data[i + 0x3d],
                data[i + 0x3e],
                data[i + 0x3f],
            ]) as usize;

            if (0x40..0x1000).contains(&e_lfanew) && i + e_lfanew + 24 <= data.len() {
                let pe_sig = &data[i + e_lfanew..i + e_lfanew + 4];
                if pe_sig == b"PE\0\0" {
                    let num_sections =
                        u16::from_le_bytes([data[i + e_lfanew + 6], data[i + e_lfanew + 7]])
                            as usize;
                    let opt_header_size =
                        u16::from_le_bytes([data[i + e_lfanew + 20], data[i + e_lfanew + 21]])
                            as usize;

                    if num_sections > 0 && num_sections <= 96 {
                        let sec_table_start = i + e_lfanew + 24 + opt_header_size;
                        let mut max_raw_end = 0;

                        if sec_table_start + (num_sections * 40) <= data.len() {
                            for s in 0..num_sections {
                                let offset = sec_table_start + s * 40;
                                let size_of_raw_data = u32::from_le_bytes([
                                    data[offset + 16],
                                    data[offset + 17],
                                    data[offset + 18],
                                    data[offset + 19],
                                ]) as usize;
                                let pointer_to_raw_data = u32::from_le_bytes([
                                    data[offset + 20],
                                    data[offset + 21],
                                    data[offset + 22],
                                    data[offset + 23],
                                ])
                                    as usize;

                                let sec_end = pointer_to_raw_data + size_of_raw_data;
                                if sec_end > max_raw_end {
                                    max_raw_end = sec_end;
                                }
                            }
                        }

                        if max_raw_end > 0 && i + max_raw_end <= data.len() {
                            let pe_data = data[i..i + max_raw_end].to_vec();
                            let h = compute_hashes(&pe_data);
                            let ent = shannon_entropy(&pe_data);

                            artifacts.push(CarvedArtifact {
                                offset: i,
                                size: max_raw_end,
                                format: "Windows PE Executable".to_string(),
                                sha256: h.sha256,
                                entropy: ent,
                                filename: format!("carved_pe_0x{:x}.exe", i),
                                data: pe_data,
                            });

                            i += max_raw_end;
                            continue;
                        }
                    }
                }
            }
        }
        i += 16;
    }
}

fn carve_elf_executables(data: &[u8], artifacts: &mut Vec<CarvedArtifact>) {
    let mut i = 0;
    while i + 64 <= data.len() {
        if &data[i..i + 4] == b"\x7fELF" {
            let class = data[i + 4]; // 1 = 32-bit, 2 = 64-bit
            let (shoff, shentsize, shnum) = if class == 2 && i + 64 <= data.len() {
                let shoff = u64::from_le_bytes(data[i + 40..i + 48].try_into().unwrap_or_default())
                    as usize;
                let shentsize =
                    u16::from_le_bytes(data[i + 58..i + 60].try_into().unwrap_or_default())
                        as usize;
                let shnum = u16::from_le_bytes(data[i + 60..i + 62].try_into().unwrap_or_default())
                    as usize;
                (shoff, shentsize, shnum)
            } else if class == 1 && i + 52 <= data.len() {
                let shoff = u32::from_le_bytes(data[i + 32..i + 36].try_into().unwrap_or_default())
                    as usize;
                let shentsize =
                    u16::from_le_bytes(data[i + 46..i + 48].try_into().unwrap_or_default())
                        as usize;
                let shnum = u16::from_le_bytes(data[i + 48..i + 50].try_into().unwrap_or_default())
                    as usize;
                (shoff, shentsize, shnum)
            } else {
                (0, 0, 0)
            };

            if shoff > 0 && shentsize > 0 && shnum > 0 {
                let total_len = shoff + (shentsize * shnum);
                if total_len > 64 && i + total_len <= data.len() {
                    let elf_data = data[i..i + total_len].to_vec();
                    let h = compute_hashes(&elf_data);
                    let ent = shannon_entropy(&elf_data);

                    artifacts.push(CarvedArtifact {
                        offset: i,
                        size: total_len,
                        format: "Linux ELF Binary".to_string(),
                        sha256: h.sha256,
                        entropy: ent,
                        filename: format!("carved_elf_0x{:x}.elf", i),
                        data: elf_data,
                    });

                    i += total_len;
                    continue;
                }
            }
        }
        i += 16;
    }
}

fn carve_zip_archives(data: &[u8], artifacts: &mut Vec<CarvedArtifact>) {
    let mut i = 0;
    while i + 30 <= data.len() {
        if &data[i..i + 4] == b"PK\x03\x04" {
            // Find end of central directory: PK\x05\x06
            if let Some(eocd_pos) = find_subsequence(&data[i..], b"PK\x05\x06") {
                let eocd_abs = i + eocd_pos;
                if eocd_abs + 22 <= data.len() {
                    let comment_len =
                        u16::from_le_bytes([data[eocd_abs + 20], data[eocd_abs + 21]]) as usize;
                    let zip_len = eocd_pos + 22 + comment_len;

                    if i + zip_len <= data.len() {
                        let zip_data = data[i..i + zip_len].to_vec();
                        let h = compute_hashes(&zip_data);
                        let ent = shannon_entropy(&zip_data);

                        artifacts.push(CarvedArtifact {
                            offset: i,
                            size: zip_len,
                            format: "ZIP Archive".to_string(),
                            sha256: h.sha256,
                            entropy: ent,
                            filename: format!("carved_archive_0x{:x}.zip", i),
                            data: zip_data,
                        });

                        i += zip_len;
                        continue;
                    }
                }
            }
        }
        i += 16;
    }
}

fn carve_pe_overlay(data: &[u8]) -> Option<CarvedArtifact> {
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
        return None;
    }

    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    let num_sections = u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]) as usize;
    let opt_header_size = u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]) as usize;

    let sec_table_start = e_lfanew + 24 + opt_header_size;
    if sec_table_start + (num_sections * 40) > data.len() {
        return None;
    }

    let mut max_raw_end = 0;
    for s in 0..num_sections {
        let offset = sec_table_start + s * 40;
        let size_of_raw_data = u32::from_le_bytes([
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
        ]) as usize;
        let pointer_to_raw_data = u32::from_le_bytes([
            data[offset + 20],
            data[offset + 21],
            data[offset + 22],
            data[offset + 23],
        ]) as usize;

        let sec_end = pointer_to_raw_data + size_of_raw_data;
        if sec_end > max_raw_end {
            max_raw_end = sec_end;
        }
    }

    if max_raw_end > 0 && max_raw_end < data.len() {
        let overlay_len = data.len() - max_raw_end;
        if overlay_len >= 32 {
            let overlay_bytes = data[max_raw_end..].to_vec();
            let h = compute_hashes(&overlay_bytes);
            let ent = shannon_entropy(&overlay_bytes);

            return Some(CarvedArtifact {
                offset: max_raw_end,
                size: overlay_len,
                format: "PE Overlay Data".to_string(),
                sha256: h.sha256,
                entropy: ent,
                filename: format!("carved_overlay_0x{:x}.bin", max_raw_end),
                data: overlay_bytes,
            });
        }
    }

    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carve_pe_overlay() {
        let mut mock_pe = vec![0u8; 1024];
        mock_pe[0] = b'M';
        mock_pe[1] = b'Z';
        mock_pe[0x3c] = 0x80; // e_lfanew = 128
        let pe_offset = 128;
        mock_pe[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        mock_pe[pe_offset + 6] = 1; // 1 section
        mock_pe[pe_offset + 20] = 0; // optional header size = 0

        // Section header at pe_offset + 24
        let sec_start = pe_offset + 24;
        mock_pe[sec_start + 16..sec_start + 20].copy_from_slice(&256u32.to_le_bytes()); // SizeOfRawData = 256
        mock_pe[sec_start + 20..sec_start + 24].copy_from_slice(&512u32.to_le_bytes()); // PointerToRawData = 512
                                                                                        // Section ends at 512 + 256 = 768

        // Add 256 bytes of overlay data to 1024
        let overlay = carve_pe_overlay(&mock_pe);
        assert!(overlay.is_some());
        let ov = overlay.unwrap();
        assert_eq!(ov.offset, 768);
        assert_eq!(ov.size, 256);
    }
}
