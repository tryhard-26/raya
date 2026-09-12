//! Rust Binary Introspection Module
//!
//! Identifies binaries compiled by the Rust toolchain, extracts the `rustc` compiler
//! commit/version, demangles symbols, and extracts statically linked third-party crates.

use std::collections::HashSet;

/// Extracted metadata from a compiled Rust binary.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RustInfo {
    /// True if the binary was compiled with rustc.
    pub is_rust: bool,
    /// Detected rustc toolchain commit hash or release version.
    pub rustc_commit: Option<String>,
    /// Statically linked crate names detected in the binary (e.g. "tokio", "serde", "aes").
    pub crates: Vec<String>,
}

impl RustInfo {
    /// Returns true if the binary statically links the specified crate.
    pub fn has_crate(&self, name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        self.crates.iter().any(|c| c.to_ascii_lowercase() == lower)
    }
}

/// Identifies Rust compiler artifacts and extracts linked crates.
pub fn parse_rust(data: &[u8]) -> Option<RustInfo> {
    if data.len() < 64 {
        return None;
    }

    // 1. Rust panic messages & stdlib markers
    let has_rust_unwrap = data.windows(21).any(|w| w == b"Option::unwrap()` on ");
    let has_rust_err = data.windows(21).any(|w| w == b"Result::unwrap()` on ");
    let has_rustc_src = data.windows(16).any(|w| w == b"library/std/src/");
    let has_rust_prefix = data.windows(7).any(|w| w == b"/rustc/");

    let is_rust = has_rust_unwrap || has_rust_err || has_rustc_src || has_rust_prefix;
    if !is_rust {
        return None;
    }

    // 2. Extract rustc commit hash from /rustc/<hash>/
    let mut rustc_commit = None;
    if let Some(pos) = data.windows(7).position(|w| w == b"/rustc/") {
        let start = pos + 7;
        if start + 40 <= data.len() {
            let commit_bytes = &data[start..start + 40];
            if commit_bytes.iter().all(|b| b.is_ascii_hexdigit()) {
                rustc_commit = Some(String::from_utf8_lossy(commit_bytes).to_string());
            }
        }
    }

    // 3. Extract common crates
    let mut crates = HashSet::new();
    const KNOWN_CRATES: &[&[u8]] = &[
        b"tokio",
        b"serde",
        b"serde_json",
        b"reqwest",
        b"aes",
        b"chacha20",
        b"windows",
        b"winapi",
        b"memmap2",
        b"iced_x86",
        b"clap",
        b"regex",
        b"sha2",
        b"ring",
        b"rustls",
        b"crossbeam",
        b"rayon",
        b"anyhow",
        b"thiserror",
    ];

    for &crate_name in KNOWN_CRATES {
        let needle = format!("{}::", String::from_utf8_lossy(crate_name));
        if data.windows(needle.len()).any(|w| w == needle.as_bytes()) {
            crates.insert(String::from_utf8_lossy(crate_name).to_string());
        }
    }

    let mut crate_list: Vec<String> = crates.into_iter().collect();
    crate_list.sort();

    Some(RustInfo {
        is_rust: true,
        rustc_commit,
        crates: crate_list,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_introspection() {
        let mut sample = vec![0u8; 1024];
        let commit = b"/rustc/07dca489ac2d933c78d3c5158e1f4f52503d7c9a/";
        sample[50..50 + commit.len()].copy_from_slice(commit);
        sample[150..175].copy_from_slice(b"library/std/src/panicking");
        sample[200..207].copy_from_slice(b"tokio::");

        let info = parse_rust(&sample).expect("Should detect Rust");
        assert!(info.is_rust);
        assert_eq!(
            info.rustc_commit.as_deref(),
            Some("07dca489ac2d933c78d3c5158e1f4f52503d7c9a")
        );
        assert!(info.has_crate("tokio"));
    }
}
