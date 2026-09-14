// src/deobfuscate/mod.rs
//
// Automated Multi-Byte XOR / Rolling-Key / Base64 Decryption Loop Hunting for Raya 2.0
// Statically probes obfuscated memory, data sections, and scripts to recover plaintext
// strings, C2 URLs, and API names hidden behind XOR and Base64 encoding.

use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecryptedPayload {
    pub offset: usize,
    pub algorithm: String,
    pub key_repr: String,
    pub plaintext: String,
}

#[derive(Clone, Copy)]
enum CipherType {
    SingleByte(u8),
    RollingInc(u8),
    RollingDec(u8),
}

struct HunterAutomaton {
    ac: AhoCorasick,
    meta: Vec<CipherType>,
}

static HUNTER: OnceLock<HunterAutomaton> = OnceLock::new();

const INDICATORS: &[&str] = &[
    "http://",
    "https://",
    "cmd.exe",
    "powershell",
    "/bin/sh",
    "/bin/bash",
    "VirtualAlloc",
    "VirtualProtect",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "LoadLibrary",
    "GetProcAddress",
    "WinExec",
    "ShellExecute",
    "URLDownloadToFile",
    "IsDebuggerPresent",
    "\\CurrentVersion\\Run",
    "wscript.shell",
    "Mozilla/5.0",
];

fn get_hunter() -> &'static HunterAutomaton {
    HUNTER.get_or_init(|| {
        let mut patterns = Vec::new();
        let mut meta = Vec::new();

        for &ind in INDICATORS {
            let ind_bytes = ind.as_bytes();

            // 1. Single-byte XOR: keys 1..=255
            for key in 1u8..=255u8 {
                let xored: Vec<u8> = ind_bytes.iter().map(|b| b ^ key).collect();
                patterns.push(xored);
                meta.push(CipherType::SingleByte(key));
            }

            // 2. Rolling XOR (+1): start keys 0..=255
            for init_key in 0u8..=255u8 {
                let mut xored = Vec::with_capacity(ind_bytes.len());
                let mut k = init_key;
                for &b in ind_bytes {
                    xored.push(b ^ k);
                    k = k.wrapping_add(1);
                }
                patterns.push(xored);
                meta.push(CipherType::RollingInc(init_key));
            }

            // 3. Rolling XOR (-1): start keys 0..=255
            for init_key in 0u8..=255u8 {
                let mut xored = Vec::with_capacity(ind_bytes.len());
                let mut k = init_key;
                for &b in ind_bytes {
                    xored.push(b ^ k);
                    k = k.wrapping_sub(1);
                }
                patterns.push(xored);
                meta.push(CipherType::RollingDec(init_key));
            }
        }

        let ac = AhoCorasick::new(&patterns).expect("Failed to build Aho-Corasick automaton");
        HunterAutomaton { ac, meta }
    })
}

struct MultiByteAutomata {
    ac2: AhoCorasick,
    meta2: Vec<&'static str>,
    ac4: AhoCorasick,
    meta4: Vec<&'static str>,
}

static MULTIBYTE_HUNTER: OnceLock<MultiByteAutomata> = OnceLock::new();

fn get_multibyte_hunter() -> &'static MultiByteAutomata {
    MULTIBYTE_HUNTER.get_or_init(|| {
        let mut p2 = Vec::new();
        let mut m2 = Vec::new();
        let mut p4 = Vec::new();
        let mut m4 = Vec::new();

        for &ind in INDICATORS {
            let b = ind.as_bytes();
            if b.len() >= 6 {
                let diff2: Vec<u8> = (0..b.len() - 2).map(|i| b[i] ^ b[i + 2]).collect();
                p2.push(diff2);
                m2.push(ind);
            }
            if b.len() >= 8 {
                let diff4: Vec<u8> = (0..b.len() - 4).map(|i| b[i] ^ b[i + 4]).collect();
                p4.push(diff4);
                m4.push(ind);
            }
        }

        let ac2 = AhoCorasick::new(&p2).expect("Failed to build stride-2 automaton");
        let ac4 = AhoCorasick::new(&p4).expect("Failed to build stride-4 automaton");

        MultiByteAutomata {
            ac2,
            meta2: m2,
            ac4,
            meta4: m4,
        }
    })
}

/// Scans binary data for single-byte, multi-byte (2/4-byte), rolling XOR, and Base64 encoded strings.
pub fn hunt_deobfuscated_strings(data: &[u8]) -> Vec<DecryptedPayload> {
    let mut results = Vec::new();
    let mut seen_plaintexts = HashSet::new();

    // 1. Single-byte and rolling XOR
    let hunter = get_hunter();
    for mat in hunter.ac.find_iter(data) {
        let pattern_id = mat.pattern();
        let hit_start = mat.start();
        let cipher = hunter.meta[pattern_id];

        let (algo_name, key_repr) = match cipher {
            CipherType::SingleByte(k) => ("Single-Byte XOR".to_string(), format!("0x{:02x}", k)),
            CipherType::RollingInc(k) => {
                ("Rolling XOR (+1)".to_string(), format!("init=0x{:02x}", k))
            }
            CipherType::RollingDec(k) => {
                ("Rolling XOR (-1)".to_string(), format!("init=0x{:02x}", k))
            }
        };

        // Decrypt surrounding bytes
        let window_start = hit_start.saturating_sub(128);
        let window_end = (mat.end() + 128).min(data.len());
        let window_bytes = &data[window_start..window_end];

        let mut decrypted = Vec::with_capacity(window_bytes.len());
        for (i, &b) in window_bytes.iter().enumerate() {
            let abs_pos = window_start + i;
            let dec = match cipher {
                CipherType::SingleByte(k) => b ^ k,
                CipherType::RollingInc(k) => {
                    if abs_pos >= hit_start {
                        let diff = (abs_pos - hit_start) as u8;
                        b ^ k.wrapping_add(diff)
                    } else {
                        let diff = (hit_start - abs_pos) as u8;
                        b ^ k.wrapping_sub(diff)
                    }
                }
                CipherType::RollingDec(k) => {
                    if abs_pos >= hit_start {
                        let diff = (abs_pos - hit_start) as u8;
                        b ^ k.wrapping_sub(diff)
                    } else {
                        let diff = (hit_start - abs_pos) as u8;
                        b ^ k.wrapping_add(diff)
                    }
                }
            };
            decrypted.push(dec);
        }

        let local_hit_pos = hit_start - window_start;
        let string_val = extract_surrounding_ascii(&decrypted, local_hit_pos);

        if string_val.len() >= 6 && seen_plaintexts.insert(string_val.clone()) {
            results.push(DecryptedPayload {
                offset: hit_start,
                algorithm: algo_name,
                key_repr,
                plaintext: string_val,
            });
            if results.len() >= 50 {
                return results;
            }
        }
    }

    // 2. Multi-byte XOR (2-byte and 4-byte key hunting via stride differentials)
    if results.len() < 50 && data.len() >= 8 {
        let mb = get_multibyte_hunter();

        // 2a. 2-Byte XOR
        let diff2: Vec<u8> = data.windows(3).map(|w| w[0] ^ w[2]).collect();
        for mat in mb.ac2.find_iter(&diff2) {
            let hit_start = mat.start();
            let ind_bytes = mb.meta2[mat.pattern()].as_bytes();
            if hit_start + ind_bytes.len() > data.len() {
                continue;
            }

            let k0 = data[hit_start] ^ ind_bytes[0];
            let k1 = data[hit_start + 1] ^ ind_bytes[1];
            if k0 == k1 {
                continue; // Single byte XOR already checked
            }

            // Verify against full indicator pattern
            let mut matches = true;
            for (i, &expected) in ind_bytes.iter().enumerate() {
                let k = if i % 2 == 0 { k0 } else { k1 };
                if (data[hit_start + i] ^ k) != expected {
                    matches = false;
                    break;
                }
            }
            if !matches {
                continue;
            }

            let window_start = hit_start.saturating_sub(128);
            let window_end = (hit_start + ind_bytes.len() + 128).min(data.len());
            let window_bytes = &data[window_start..window_end];

            let mut decrypted = Vec::with_capacity(window_bytes.len());
            for (i, &b) in window_bytes.iter().enumerate() {
                let abs_pos = window_start + i;
                let k = if abs_pos % 2 == hit_start % 2 { k0 } else { k1 };
                decrypted.push(b ^ k);
            }

            let local_hit_pos = hit_start - window_start;
            let string_val = extract_surrounding_ascii(&decrypted, local_hit_pos);

            if string_val.len() >= 6 && seen_plaintexts.insert(string_val.clone()) {
                results.push(DecryptedPayload {
                    offset: hit_start,
                    algorithm: "2-Byte XOR".to_string(),
                    key_repr: format!("0x{:02x}{:02x}", k0, k1),
                    plaintext: string_val,
                });
                if results.len() >= 50 {
                    return results;
                }
            }
        }

        // 2b. 4-Byte XOR
        if results.len() < 50 && data.len() >= 12 {
            let diff4: Vec<u8> = data.windows(5).map(|w| w[0] ^ w[4]).collect();
            for mat in mb.ac4.find_iter(&diff4) {
                let hit_start = mat.start();
                let ind_bytes = mb.meta4[mat.pattern()].as_bytes();
                if hit_start + ind_bytes.len() > data.len() {
                    continue;
                }

                let k0 = data[hit_start] ^ ind_bytes[0];
                let k1 = data[hit_start + 1] ^ ind_bytes[1];
                let k2 = data[hit_start + 2] ^ ind_bytes[2];
                let k3 = data[hit_start + 3] ^ ind_bytes[3];

                if k0 == k1 && k1 == k2 && k2 == k3 {
                    continue; // Single-byte
                }
                if k0 == k2 && k1 == k3 {
                    continue; // 2-byte
                }

                let key = [k0, k1, k2, k3];
                let mut matches = true;
                for (i, &expected) in ind_bytes.iter().enumerate() {
                    let k = key[i % 4];
                    if (data[hit_start + i] ^ k) != expected {
                        matches = false;
                        break;
                    }
                }
                if !matches {
                    continue;
                }

                let window_start = hit_start.saturating_sub(128);
                let window_end = (hit_start + ind_bytes.len() + 128).min(data.len());
                let window_bytes = &data[window_start..window_end];

                let mut decrypted = Vec::with_capacity(window_bytes.len());
                for (i, &b) in window_bytes.iter().enumerate() {
                    let abs_pos = window_start + i;
                    let k_idx = (abs_pos + 4 - (hit_start % 4)) % 4;
                    decrypted.push(b ^ key[k_idx]);
                }

                let local_hit_pos = hit_start - window_start;
                let string_val = extract_surrounding_ascii(&decrypted, local_hit_pos);

                if string_val.len() >= 6 && seen_plaintexts.insert(string_val.clone()) {
                    results.push(DecryptedPayload {
                        offset: hit_start,
                        algorithm: "4-Byte XOR".to_string(),
                        key_repr: format!("0x{:02x}{:02x}{:02x}{:02x}", k0, k1, k2, k3),
                        plaintext: string_val,
                    });
                    if results.len() >= 50 {
                        return results;
                    }
                }
            }
        }
    }

    // 3. Base64 encoded payload & command hunting
    if results.len() < 50 {
        hunt_base64_payloads(data, &mut seen_plaintexts, &mut results);
    }

    results
}

fn extract_surrounding_ascii(buf: &[u8], hit_pos: usize) -> String {
    let mut start = hit_pos;
    while start > 0 && buf[start - 1] >= 0x20 && buf[start - 1] <= 0x7e {
        start -= 1;
    }
    let mut end = hit_pos;
    while end < buf.len() && buf[end] >= 0x20 && buf[end] <= 0x7e {
        end += 1;
    }

    String::from_utf8_lossy(&buf[start..end]).to_string()
}

fn is_b64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'-' || b == b'_' || b == b'='
}

fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    let mut clean = Vec::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_whitespace() {
            continue;
        }
        clean.push(b);
    }
    if clean.is_empty() {
        return None;
    }

    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }

    let pad_count = clean.iter().rev().take_while(|&&c| c == b'=').count();
    let unpadded_len = clean.len() - pad_count;
    if unpadded_len % 4 == 1 {
        return None;
    }

    let mut out = Vec::with_capacity((clean.len() * 3) / 4);
    for chunk in clean.chunks(4) {
        if chunk.len() < 2 {
            break;
        }
        let b0 = val(chunk[0])?;
        let b1 = val(chunk[1])?;
        let b2 = if chunk.len() > 2 && chunk[2] != b'=' {
            val(chunk[2])?
        } else {
            0
        };
        let b3 = if chunk.len() > 3 && chunk[3] != b'=' {
            val(chunk[3])?
        } else {
            0
        };

        out.push((b0 << 2) | (b1 >> 4));
        if chunk.len() > 2 && chunk[2] != b'=' {
            out.push(((b1 & 0x0F) << 4) | (b2 >> 2));
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            out.push(((b2 & 0x03) << 6) | b3);
        }
    }
    Some(out)
}

fn is_likely_utf16le(buf: &[u8]) -> bool {
    if buf.len() < 8 || buf.len() % 2 != 0 {
        return false;
    }
    let zero_count = buf.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
    let total_odd = buf.len() / 2;
    zero_count * 10 >= total_odd * 7
}

fn is_interesting_string(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    let has_keyword = lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("ftp://")
        || lower.contains("cmd")
        || lower.contains("powershell")
        || lower.contains("pwsh")
        || lower.contains("bash")
        || lower.contains("sh ")
        || lower.contains("/bin/")
        || lower.contains("download")
        || lower.contains("iex")
        || lower.contains("invoke-")
        || lower.contains("webclient")
        || lower.contains("virtualalloc")
        || lower.contains("virtualprotect")
        || lower.contains("loadlibrary")
        || lower.contains("getprocaddress")
        || lower.contains("createremotethread")
        || lower.contains("writeprocessmemory")
        || lower.contains("vssadmin")
        || lower.contains("certutil")
        || lower.contains("reg add")
        || lower.contains("net user")
        || lower.contains("schtasks")
        || lower.contains("rundll32")
        || lower.contains("wscript")
        || lower.contains(".exe")
        || lower.contains(".dll")
        || lower.contains(".ps1")
        || lower.contains(".bat");

    has_keyword && s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
}

fn hunt_base64_payloads(
    data: &[u8],
    seen_plaintexts: &mut HashSet<String>,
    results: &mut Vec<DecryptedPayload>,
) {
    let mut i = 0;
    while i < data.len() {
        if is_b64_char(data[i]) {
            let start = i;
            while i < data.len() && is_b64_char(data[i]) {
                i += 1;
            }
            let len = i - start;
            if (16..=65536).contains(&len) {
                let candidate = &data[start..i];
                if let Some(decoded) = decode_base64(candidate) {
                    if decoded.len() >= 8 {
                        // Check 1: Embedded PE or ELF
                        if decoded.starts_with(b"MZ") && decoded.len() >= 64 {
                            let text = format!(
                                "Embedded PE Executable (MZ header, size: {} bytes)",
                                decoded.len()
                            );
                            if seen_plaintexts.insert(text.clone()) {
                                results.push(DecryptedPayload {
                                    offset: start,
                                    algorithm: "Base64 (Embedded PE)".to_string(),
                                    key_repr: "Standard Base64".to_string(),
                                    plaintext: text,
                                });
                            }
                        } else if decoded.starts_with(b"\x7fELF") && decoded.len() >= 64 {
                            let text =
                                format!("Embedded ELF Binary (size: {} bytes)", decoded.len());
                            if seen_plaintexts.insert(text.clone()) {
                                results.push(DecryptedPayload {
                                    offset: start,
                                    algorithm: "Base64 (Embedded ELF)".to_string(),
                                    key_repr: "Standard Base64".to_string(),
                                    plaintext: text,
                                });
                            }
                        } else if decoded.len() >= 12
                            && decoded.len() % 2 == 0
                            && is_likely_utf16le(&decoded)
                        {
                            // Check 2: UTF-16LE text (PowerShell -EncodedCommand)
                            let u16s: Vec<u16> = decoded
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            if let Ok(s) = String::from_utf16(&u16s) {
                                let clean = s.trim();
                                if clean.len() >= 8 && is_interesting_string(clean) {
                                    if seen_plaintexts.insert(clean.to_string()) {
                                        results.push(DecryptedPayload {
                                            offset: start,
                                            algorithm: "Base64 (UTF-16LE)".to_string(),
                                            key_repr: "PowerShell EncodedCommand".to_string(),
                                            plaintext: clean.chars().take(256).collect(),
                                        });
                                    }
                                }
                            }
                        } else if let Ok(s) = std::str::from_utf8(&decoded) {
                            // Check 3: Standard UTF-8 / ASCII text
                            let clean = s.trim();
                            if clean.len() >= 8 && is_interesting_string(clean) {
                                if seen_plaintexts.insert(clean.to_string()) {
                                    results.push(DecryptedPayload {
                                        offset: start,
                                        algorithm: "Base64".to_string(),
                                        key_repr: "Standard Base64".to_string(),
                                        plaintext: clean.chars().take(256).collect(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            if results.len() >= 50 {
                return;
            }
        } else {
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_byte_xor_deobfuscation() {
        let target = "https://c2.malicious-domain.com/beacon.php";
        let key = 0x5a;
        let mut obfuscated = Vec::new();
        for b in target.bytes() {
            obfuscated.push(b ^ key);
        }

        let mut data = vec![0x90; 128];
        data.extend_from_slice(&obfuscated);
        data.extend_from_slice(&[0xcc; 128]);

        let recovered = hunt_deobfuscated_strings(&data);
        assert!(!recovered.is_empty());
        assert!(recovered[0]
            .plaintext
            .contains("https://c2.malicious-domain.com"));
        assert_eq!(recovered[0].key_repr, "0x5a");
    }

    #[test]
    fn test_rolling_xor_deobfuscation() {
        let target = "VirtualAlloc";
        let init_key = 0x33;
        let mut obfuscated = Vec::new();
        let mut k = init_key;
        for b in target.bytes() {
            obfuscated.push(b ^ k);
            k = k.wrapping_add(1);
        }

        let mut data = vec![0x00; 64];
        data.extend_from_slice(&obfuscated);
        data.extend_from_slice(&[0x00; 64]);

        let recovered = hunt_deobfuscated_strings(&data);
        assert!(!recovered.is_empty());
        assert!(recovered
            .iter()
            .any(|r| r.plaintext.contains("VirtualAlloc")));
    }

    #[test]
    fn test_2byte_xor_deobfuscation() {
        let target = "https://c2.malicious-domain.com/beacon.php";
        let key = [0xbe, 0xef];
        let mut obfuscated = Vec::new();
        for (i, b) in target.bytes().enumerate() {
            obfuscated.push(b ^ key[i % 2]);
        }

        let mut data = vec![0x90; 64];
        data.extend_from_slice(&obfuscated);
        data.extend_from_slice(&[0xcc; 64]);

        let recovered = hunt_deobfuscated_strings(&data);
        assert!(!recovered.is_empty());
        let found = recovered.iter().find(|r| r.algorithm == "2-Byte XOR");
        assert!(found.is_some(), "Should detect 2-Byte XOR");
        let payload = found.unwrap();
        assert!(payload.plaintext.contains("https://c2.malicious-domain.com"));
        assert_eq!(payload.key_repr, "0xbeef");
    }

    #[test]
    fn test_4byte_xor_deobfuscation() {
        let target = "powershell -ExecutionPolicy Bypass -NoProfile";
        let key = [0xde, 0xad, 0xbe, 0xef];
        let mut obfuscated = Vec::new();
        for (i, b) in target.bytes().enumerate() {
            obfuscated.push(b ^ key[i % 4]);
        }

        let mut data = vec![0x00; 64];
        data.extend_from_slice(&obfuscated);
        data.extend_from_slice(&[0x00; 64]);

        let recovered = hunt_deobfuscated_strings(&data);
        assert!(!recovered.is_empty());
        let found = recovered.iter().find(|r| r.algorithm == "4-Byte XOR");
        assert!(found.is_some(), "Should detect 4-Byte XOR");
        let payload = found.unwrap();
        assert!(payload.plaintext.contains("powershell"));
        assert_eq!(payload.key_repr, "0xdeadbeef");
    }

    #[test]
    fn test_base64_ascii_deobfuscation() {
        // "https://malware-domain.com/update.php" in Base64
        let b64 = b"aHR0cHM6Ly9tYWx3YXJlLWRvbWFpbi5jb20vdXBkYXRlLnBocA==";
        let mut data = vec![0x20; 32];
        data.extend_from_slice(b64);
        data.extend_from_slice(&[0x20; 32]);

        let recovered = hunt_deobfuscated_strings(&data);
        assert!(!recovered.is_empty());
        let found = recovered.iter().find(|r| r.algorithm == "Base64");
        assert!(found.is_some(), "Should detect Base64 encoded URL");
        assert!(found.unwrap().plaintext.contains("https://malware-domain.com"));
    }

    #[test]
    fn test_base64_utf16le_powershell_deobfuscation() {
        // "powershell.exe -w hidden" in UTF-16LE
        let cmd = "powershell.exe -w hidden";
        let mut utf16_bytes = Vec::new();
        for u in cmd.encode_utf16() {
            utf16_bytes.extend_from_slice(&u.to_le_bytes());
        }

        // Custom base64 encode for test
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut b64 = String::new();
        for chunk in utf16_bytes.chunks(3) {
            let b0 = chunk[0];
            let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
            b64.push(ALPHABET[(b0 >> 2) as usize] as char);
            b64.push(ALPHABET[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
            if chunk.len() > 1 {
                b64.push(ALPHABET[(((b1 & 0xF) << 2) | (b2 >> 6)) as usize] as char);
            } else {
                b64.push('=');
            }
            if chunk.len() > 2 {
                b64.push(ALPHABET[(b2 & 0x3F) as usize] as char);
            } else {
                b64.push('=');
            }
        }

        let mut data = vec![0x00; 32];
        data.extend_from_slice(b64.as_bytes());
        data.extend_from_slice(&[0x00; 32]);

        let recovered = hunt_deobfuscated_strings(&data);
        assert!(!recovered.is_empty());
        let found = recovered.iter().find(|r| r.algorithm.contains("UTF-16LE"));
        assert!(found.is_some(), "Should detect PowerShell UTF-16LE Base64");
        assert!(found.unwrap().plaintext.contains("powershell.exe"));
    }
}
