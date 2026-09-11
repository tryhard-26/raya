//! High-performance archive inspection module for nested malware analysis.
//! Supports standard and AES-encrypted ZIP archives (e.g., MalwareBazaar/theZoo drops).

use std::io::{Cursor, Read, Seek};

pub const DEFAULT_ARCHIVE_PASSWORDS: &[&str] = &["infected", "malware", "password", "clean", "1234"];
const MAX_DECOMPRESSED_FILE_SIZE: usize = 128 * 1024 * 1024; // 128 MB zip-bomb defense

/// Checks whether raw bytes start with standard ZIP local or central header magic bytes.
pub fn is_zip(data: &[u8]) -> bool {
    data.len() >= 4 && (data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06"))
}

/// Extracted entry from an archive
#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    pub name: String,
    pub data: Vec<u8>,
}

/// Attempts to extract all files from a ZIP archive stream in-memory.
/// If entries are encrypted, attempts the provided password or defaults ("infected", "malware", etc.).
pub fn extract_zip<R: Read + Seek>(
    reader: R,
    user_password: Option<&str>,
) -> Result<Vec<ArchiveEntry>, String> {
    let mut archive = match zip::ZipArchive::new(reader) {
        Ok(a) => a,
        Err(e) => return Err(format!("Invalid or unsupported ZIP archive: {}", e)),
    };

    let mut entries = Vec::new();
    let mut passwords: Vec<&str> = Vec::new();
    if let Some(pwd) = user_password {
        passwords.push(pwd);
    }
    for &p in DEFAULT_ARCHIVE_PASSWORDS {
        if !passwords.contains(&p) {
            passwords.push(p);
        }
    }

    for i in 0..archive.len() {
        // Try unencrypted read first
        let mut read_success = false;
        let mut file_data = Vec::new();
        let mut entry_name = format!("entry_{}", i);

        if let Ok(mut f) = archive.by_index(i) {
            if f.is_dir() {
                continue;
            }
            entry_name = f.name().to_string();
            if f.size() <= MAX_DECOMPRESSED_FILE_SIZE as u64 {
                let mut buf = Vec::with_capacity(f.size() as usize);
                if f.read_to_end(&mut buf).is_ok() {
                    file_data = buf;
                    read_success = true;
                }
            }
        }

        // If unencrypted read failed (e.g. encrypted entry), try password candidate list
        if !read_success {
            for pwd in &passwords {
                if let Ok(mut f) = archive.by_index_decrypt(i, pwd.as_bytes()) {
                    if f.is_dir() {
                        break;
                    }
                    entry_name = f.name().to_string();
                    let mut buf = Vec::new();
                    if f.read_to_end(&mut buf).is_ok() && !buf.is_empty() {
                        file_data = buf;
                        read_success = true;
                        break;
                    }
                }
            }
        }

        if read_success && !file_data.is_empty() {
            entries.push(ArchiveEntry {
                name: entry_name,
                data: file_data,
            });
        }
    }

    Ok(entries)
}

/// Helper to extract entries from an in-memory byte buffer
pub fn extract_zip_bytes(
    data: &[u8],
    user_password: Option<&str>,
) -> Result<Vec<ArchiveEntry>, String> {
    let cursor = Cursor::new(data);
    extract_zip(cursor, user_password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_zip_detection() {
        assert!(is_zip(b"PK\x03\x04\x14\x00..."));
        assert!(!is_zip(b"MZ\x90\x00..."));
        assert!(!is_zip(b"\x7fELF..."));
    }

    #[test]
    fn test_real_malware_archive_extraction() {
        let zip_path = "samples/malware/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.zip";
        if !std::path::Path::new(zip_path).exists() {
            return;
        }
        let file = std::fs::File::open(zip_path).expect("Archive should open");
        let entries = extract_zip(file, Some("infected")).expect("Should extract with password 'infected'");
        assert_eq!(entries.len(), 1);
        eprintln!("Extracted entry name: '{}'", entries[0].name);
        assert!(entries[0].name.ends_with(".exe"));
        assert_eq!(entries[0].data.len(), 3514368);
        assert_eq!(&entries[0].data[0..2], b"MZ");
    }
}
