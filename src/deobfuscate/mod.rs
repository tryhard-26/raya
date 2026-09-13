// src/deobfuscate/mod.rs
//
// Automated XOR / RC4 / Rolling-Key Decryption Loop Hunting for Raya 2.0
// Statically probes obfuscated memory and data sections to recover plaintext strings,
// C2 URLs, and API names hidden behind XOR encoding using Aho-Corasick multi-pattern search.

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

fn get_hunter() -> &'static HunterAutomaton {
    HUNTER.get_or_init(|| {
        let indicators = [
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

        let mut patterns = Vec::new();
        let mut meta = Vec::new();

        for &ind in &indicators {
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

/// Scans binary data for single-byte and rolling XOR obfuscated strings using Aho-Corasick.
pub fn hunt_deobfuscated_strings(data: &[u8]) -> Vec<DecryptedPayload> {
    let mut results = Vec::new();
    let mut seen_plaintexts = HashSet::new();
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
}
