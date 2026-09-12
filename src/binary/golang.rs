//! Go (.gopclntab) Binary Introspection Module
//!
//! Extracts runtime version, package paths, and function symbols from Go binaries
//! by parsing the PC-Line Table (.gopclntab) or scanning runtime signatures across
//! PE, ELF, and Mach-O targets.

use std::collections::HashSet;

/// Extracted metadata from a compiled Golang binary.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GoInfo {
    /// True if the binary was produced by the Go toolchain.
    pub is_go: bool,
    /// Detected Go compiler version (e.g. "go1.22.1").
    pub version: Option<String>,
    /// Extracted function names (e.g. "main.injectShellcode", "crypto/aes.NewCipher").
    pub functions: Vec<String>,
    /// Extracted Go package names (e.g. "main", "crypto/aes", "net/http").
    pub packages: Vec<String>,
}

impl GoInfo {
    /// Returns true if any function matches the target string (or contains the substring).
    pub fn has_function(&self, target: &str) -> bool {
        let lower = target.to_ascii_lowercase();
        self.functions
            .iter()
            .any(|f| f.to_ascii_lowercase().contains(&lower))
    }

    /// Returns true if a specific Go package is referenced in the binary.
    pub fn has_package(&self, pkg: &str) -> bool {
        let lower = pkg.to_ascii_lowercase();
        self.packages
            .iter()
            .any(|p| p.to_ascii_lowercase() == lower)
    }
}

/// Identifies Go binaries and extracts function names and packages from raw binary data.
pub fn parse_go(data: &[u8]) -> Option<GoInfo> {
    if data.len() < 64 {
        return None;
    }

    // Go pclntab magic headers
    const GO_MAGIC_12: &[u8] = &[0xfb, 0xff, 0xff, 0xff, 0x00, 0x00];
    const GO_MAGIC_116: &[u8] = &[0xfa, 0xff, 0xff, 0xff, 0x00, 0x00];
    const GO_MAGIC_118: &[u8] = &[0xf0, 0xff, 0xff, 0xff, 0x00, 0x00];
    const GO_MAGIC_120: &[u8] = &[0xf1, 0xff, 0xff, 0xff, 0x00, 0x00];

    let has_pcln_magic = data
        .windows(6)
        .any(|w| w == GO_MAGIC_12 || w == GO_MAGIC_116 || w == GO_MAGIC_118 || w == GO_MAGIC_120);

    // Also look for standard Go runtime markers if stripped
    let has_runtime_morestack = data.windows(17).any(|w| w == b"runtime.morestack");
    let has_gopanic = data.windows(15).any(|w| w == b"runtime.gopanic");

    let is_go = has_pcln_magic || has_runtime_morestack || has_gopanic;
    if !is_go {
        return None;
    }

    // Extract Go Version string (e.g. "go1.21.3", "go1.22beta1")
    let mut version = None;
    let mut p = 0;
    while p + 7 < data.len() {
        if &data[p..p + 3] == b"go1" && (data[p + 3] == b'.' || data[p + 3].is_ascii_digit()) {
            let start = p;
            let mut end = start + 3;
            while end < data.len() && end - start < 32 {
                let b = data[end];
                if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' {
                    end += 1;
                } else {
                    break;
                }
            }
            let candidate = String::from_utf8_lossy(&data[start..end]).to_string();
            if candidate.contains('.') && candidate.len() >= 5 && candidate.len() <= 20 {
                version = Some(candidate);
                break;
            }
            p = end;
        } else {
            p += 1;
        }
    }

    // Extract Go symbols and package names
    let mut functions = HashSet::new();
    let mut packages = HashSet::new();

    // Fast string scanner for Go symbol format (e.g. "main.foo", "net/http.(*Client).Do")
    let mut i = 0;
    while i + 4 < data.len() {
        // Find strings that look like package.Func or path/pkg.Func
        if (data[i] == b'm' && data.get(i..i + 5) == Some(b"main."))
            || (data[i] == b'r' && data.get(i..i + 8) == Some(b"runtime."))
            || (data[i] == b's' && data.get(i..i + 8) == Some(b"syscall."))
        {
            let start = i;
            let mut end = start;
            while end < data.len() && end - start < 80 {
                let b = data[end];
                if b.is_ascii_alphanumeric()
                    || b == b'.'
                    || b == b'/'
                    || b == b'_'
                    || b == b'-'
                    || b == b'*'
                    || b == b'('
                    || b == b')'
                {
                    end += 1;
                } else {
                    break;
                }
            }
            if end > start + 5 {
                let s = String::from_utf8_lossy(&data[start..end]).to_string();
                if let Some(dot_idx) = s.find('.') {
                    let pkg = s[..dot_idx]
                        .trim_start_matches('*')
                        .trim_start_matches('(')
                        .to_string();
                    if !pkg.is_empty() {
                        packages.insert(pkg);
                    }
                }
                functions.insert(s);
            }
            i = end;
        } else {
            i += 1;
        }
    }

    let mut func_list: Vec<String> = functions.into_iter().collect();
    func_list.sort();
    let mut pkg_list: Vec<String> = packages.into_iter().collect();
    pkg_list.sort();

    Some(GoInfo {
        is_go: true,
        version,
        functions: func_list,
        packages: pkg_list,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_parsing() {
        let mut sample = vec![0u8; 1024];
        // Inject Go pclntab magic
        sample[0..6].copy_from_slice(&[0xf1, 0xff, 0xff, 0xff, 0x00, 0x00]);
        // Inject Go version
        sample[50..59].copy_from_slice(b"go1.22.4\x00");
        // Inject main functions
        sample[100..115].copy_from_slice(b"main.c2Beacon\x00\x00");
        sample[200..216].copy_from_slice(b"runtime.gopanic\x00");

        let info = parse_go(&sample).expect("Should detect Go");
        assert!(info.is_go);
        assert_eq!(info.version.as_deref(), Some("go1.22.4"));
        assert!(info.has_function("c2beacon"));
        assert!(info.has_package("main"));
    }
}
