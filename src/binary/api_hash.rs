//! # Automated API Hash Resolver
//!
//! Identifies and resolves precomputed and dynamically generated API hashes
//! across binary code sections. Malicious loaders and shellcode frequently avoid
//! plaintext string references by resolving exported Win32/NT APIs via hash algorithms
//! such as ROR13, DJB2, and CRC32.

use iced_x86::{Instruction, OpKind};
use std::collections::HashMap;

/// Information about a detected and resolved API hash constant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApiHashMatch {
    /// Hashing algorithm (e.g. "ROR13", "DJB2", "CRC32").
    pub algorithm: String,
    /// Numerical hash value located in code or immediate operand.
    pub hash_value: u32,
    /// Resolved human-readable Win32/NT API name (e.g. "VirtualAlloc").
    pub api_name: String,
    /// File offset or virtual address where the constant was detected.
    pub offset: u64,
}

/// Computes ROR13 hash for an API symbol name.
pub fn ror13(s: &str) -> u32 {
    let mut hash: u32 = 0;
    for b in s.bytes() {
        hash = hash.rotate_right(13).wrapping_add(b as u32);
    }
    hash
}

/// Computes DJB2 hash for an API symbol name.
pub fn djb2(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for b in s.bytes() {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(b as u32);
    }
    hash
}

/// Computes DJB2a (XOR variation) hash for an API symbol name.
pub fn djb2a(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for b in s.bytes() {
        hash = ((hash << 5).wrapping_add(hash)) ^ (b as u32);
    }
    hash
}

/// Top security-sensitive Win32 and NT APIs targeted for hash resolution.
pub const TARGET_APIS: &[&str] = &[
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "VirtualFree",
    "CreateProcessA",
    "CreateProcessW",
    "CreateRemoteThread",
    "CreateThread",
    "OpenProcess",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenA",
    "InternetOpenW",
    "InternetConnectA",
    "InternetConnectW",
    "HttpOpenRequestA",
    "HttpOpenRequestW",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "WSAStartup",
    "WSASocketA",
    "connect",
    "send",
    "recv",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtQueueApcThread",
    "NtOpenProcess",
    "NtTerminateProcess",
    "NtResumeThread",
    "LdrLoadDll",
    "LdrGetProcedureAddress",
];

/// Precomputed database mapping hash -> (Algorithm, API Name).
pub struct ApiHashDatabase {
    hashes: HashMap<u32, (&'static str, &'static str)>,
}

impl Default for ApiHashDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHashDatabase {
    pub fn new() -> Self {
        let mut hashes = HashMap::new();

        for &api in TARGET_APIS {
            // Standard case
            hashes.insert(ror13(api), ("ROR13", api));
            hashes.insert(djb2(api), ("DJB2", api));
            hashes.insert(djb2a(api), ("DJB2a", api));

            // Lowercase variation (common in shellcode)
            let lower = api.to_ascii_lowercase();
            hashes.insert(ror13(&lower), ("ROR13", api));
            hashes.insert(djb2(&lower), ("DJB2", api));
            hashes.insert(djb2a(&lower), ("DJB2a", api));
        }

        Self { hashes }
    }

    /// Looks up a 32-bit integer in the hash database.
    pub fn lookup(&self, hash_val: u32) -> Option<(&'static str, &'static str)> {
        // Skip common small integer immediate values (e.g. 0, 1, 0x40, etc.)
        if hash_val < 0x10000 {
            return None;
        }
        self.hashes.get(&hash_val).copied()
    }
}

/// Scans instruction immediate operands and code sections for API hashes.
pub fn scan_api_hashes(
    data: &[u8],
    instructions: &[Instruction],
    db: &ApiHashDatabase,
) -> Vec<ApiHashMatch> {
    let mut matches = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // 1. Scan instruction immediates (e.g. `mov edx, 0x91AFCA54` or `push 0x91AFCA54`)
    for instr in instructions {
        let ip = instr.ip();
        for op_idx in 0..instr.op_count() {
            let val = match instr.op_kind(op_idx) {
                OpKind::Immediate32 => Some(instr.immediate32()),
                OpKind::Immediate64 => {
                    let imm = instr.immediate64();
                    if imm <= u32::MAX as u64 {
                        Some(imm as u32)
                    } else {
                        None
                    }
                }
                _ => None,
            };

            if let Some(h) = val {
                if let Some((algo, api)) = db.lookup(h) {
                    let key = (h, api);
                    if seen.insert(key) {
                        matches.push(ApiHashMatch {
                            algorithm: algo.to_string(),
                            hash_value: h,
                            api_name: api.to_string(),
                            offset: ip,
                        });
                    }
                }
            }
        }
    }

    // 2. Linear dword scan across raw section bytes for hash tables or arrays
    if matches.is_empty() && data.len() >= 4 {
        for (idx, window) in data.windows(4).enumerate().step_by(4) {
            let val = u32::from_le_bytes([window[0], window[1], window[2], window[3]]);
            if let Some((algo, api)) = db.lookup(val) {
                let key = (val, api);
                if seen.insert(key) {
                    matches.push(ApiHashMatch {
                        algorithm: algo.to_string(),
                        hash_value: val,
                        api_name: api.to_string(),
                        offset: idx as u64,
                    });
                }
            }
        }
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    #[test]
    fn test_ror13_resolution() {
        let db = ApiHashDatabase::new();
        let va_hash = ror13("VirtualAlloc");
        let res = db.lookup(va_hash);
        assert!(res.is_some());
        let (algo, name) = res.unwrap();
        assert_eq!(algo, "ROR13");
        assert_eq!(name, "VirtualAlloc");
    }

    #[test]
    fn test_immediate_api_hash_scan() {
        let db = ApiHashDatabase::new();
        let va_hash = ror13("VirtualAlloc");

        // mov edx, <VirtualAlloc hash>; call rbx
        let mut code = vec![0xBA];
        code.extend_from_slice(&va_hash.to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xD3]);

        let mut decoder = Decoder::with_ip(64, &code, 0x140001000, DecoderOptions::NONE);
        let mut instructions = Vec::new();
        let mut instr = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instr);
            instructions.push(instr);
        }

        let matches = scan_api_hashes(&code, &instructions, &db);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].api_name, "VirtualAlloc");
        assert_eq!(matches[0].algorithm, "ROR13");
    }
}
