//! Cryptographic Constant & S-Box Identifier Module
//!
//! Scans binary payloads for compiled cryptographic primitives, substitution boxes,
//! and initialization vectors (AES, ChaCha20, MD5, SHA-256, CRC32, SM4) without relying
//! on dynamic execution or symbol tables.

use aho_corasick::AhoCorasick;

/// Represents a detected cryptographic constant or algorithm signature.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CryptoMatch {
    pub algorithm: String,
    pub description: String,
    pub offset: usize,
}

/// Aggregated cryptographic findings for a binary sample.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CryptoAnalysis {
    pub has_aes: bool,
    pub has_chacha20: bool,
    pub has_md5: bool,
    pub has_sha256: bool,
    pub has_crc32: bool,
    pub has_sm4: bool,
    pub matches: Vec<CryptoMatch>,
}

impl CryptoAnalysis {
    /// Returns true if any cryptographic primitive constant was detected.
    pub fn has_any(&self) -> bool {
        self.has_aes
            || self.has_chacha20
            || self.has_md5
            || self.has_sha256
            || self.has_crc32
            || self.has_sm4
    }
}

/// Identifies cryptographic constants within arbitrary binary data.
pub fn analyze_crypto(data: &[u8]) -> CryptoAnalysis {
    if data.len() < 16 {
        return CryptoAnalysis::default();
    }

    // 1. AES Forward S-Box prefix (16 bytes)
    const AES_SBOX_16: [u8; 16] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76,
    ];

    // 2. AES Inverse S-Box prefix (16 bytes)
    const AES_INV_SBOX_16: [u8; 16] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
        0xfb,
    ];

    // 3. ChaCha20 constants
    const CHACHA20_32: &[u8] = b"expand 32-byte k";
    const CHACHA20_16: &[u8] = b"expand 16-byte k";

    // 4. MD5 IV (little-endian & big-endian)
    const MD5_IV_LE: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    const MD5_IV_BE: [u8; 16] = [
        0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54,
        0x76,
    ];

    // 5. SHA-256 IV (first 16 bytes)
    const SHA256_IV_LE: [u8; 16] = [
        0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f,
        0xa5,
    ];
    const SHA256_IV_BE: [u8; 16] = [
        0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5,
        0x3a,
    ];

    // 6. CRC32 Table prefix (IEEE 802.3, first 16 bytes)
    const CRC32_IEEE_16: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee, 0xba, 0x51, 0x09,
        0x99,
    ];

    // 7. SM4 S-Box prefix (16 bytes)
    const SM4_SBOX_16: [u8; 16] = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c,
        0x05,
    ];

    let patterns: Vec<&[u8]> = vec![
        &AES_SBOX_16,
        &AES_INV_SBOX_16,
        CHACHA20_32,
        CHACHA20_16,
        &MD5_IV_LE,
        &MD5_IV_BE,
        &SHA256_IV_LE,
        &SHA256_IV_BE,
        &CRC32_IEEE_16,
        &SM4_SBOX_16,
    ];

    let mut analysis = CryptoAnalysis::default();

    if let Ok(ac) = AhoCorasick::new(patterns) {
        for mat in ac.find_iter(data) {
            let offset = mat.start();
            match mat.pattern().as_usize() {
                0 => {
                    analysis.has_aes = true;
                    analysis.matches.push(CryptoMatch {
                        algorithm: "AES".to_string(),
                        description: "AES Forward S-Box table detected".to_string(),
                        offset,
                    });
                }
                1 => {
                    analysis.has_aes = true;
                    analysis.matches.push(CryptoMatch {
                        algorithm: "AES".to_string(),
                        description: "AES Inverse S-Box table detected".to_string(),
                        offset,
                    });
                }
                2 => {
                    analysis.has_chacha20 = true;
                    analysis.matches.push(CryptoMatch {
                        algorithm: "ChaCha20".to_string(),
                        description: "ChaCha20 'expand 32-byte k' constant detected".to_string(),
                        offset,
                    });
                }
                3 => {
                    analysis.has_chacha20 = true;
                    analysis.matches.push(CryptoMatch {
                        algorithm: "ChaCha20".to_string(),
                        description: "ChaCha20 'expand 16-byte k' constant detected".to_string(),
                        offset,
                    });
                }
                4 | 5 => {
                    analysis.has_md5 = true;
                    analysis.matches.push(CryptoMatch {
                        algorithm: "MD5".to_string(),
                        description: "MD5 initial state constants (A,B,C,D) detected".to_string(),
                        offset,
                    });
                }
                6 | 7 => {
                    analysis.has_sha256 = true;
                    analysis.matches.push(CryptoMatch {
                        algorithm: "SHA-256".to_string(),
                        description: "SHA-256 initial state constants (H0-H3) detected".to_string(),
                        offset,
                    });
                }
                8 => {
                    analysis.has_crc32 = true;
                    analysis.matches.push(CryptoMatch {
                        algorithm: "CRC32".to_string(),
                        description: "CRC32 IEEE 802.3 lookup table detected".to_string(),
                        offset,
                    });
                }
                9 => {
                    analysis.has_sm4 = true;
                    analysis.matches.push(CryptoMatch {
                        algorithm: "SM4".to_string(),
                        description: "SM4 cryptographic S-Box table detected".to_string(),
                        offset,
                    });
                }
                _ => {}
            }
        }
    }

    analysis
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_constant_detection() {
        let mut sample = vec![0u8; 1024];
        // Inject ChaCha20 constant at offset 100
        sample[100..116].copy_from_slice(b"expand 32-byte k");
        // Inject AES S-Box at offset 300
        sample[300..316].copy_from_slice(&[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ]);

        let analysis = analyze_crypto(&sample);
        assert!(analysis.has_chacha20);
        assert!(analysis.has_aes);
        assert!(!analysis.has_md5);
        assert_eq!(analysis.matches.len(), 2);
    }
}
