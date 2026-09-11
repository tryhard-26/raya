use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileHashes {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub ssdeep: Option<String>,
    pub imphash: Option<String>,
    pub exphash: Option<String>,
}

impl fmt::Display for FileHashes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = format!(
            "SHA256:  {}\nSHA1:    {}\nMD5:     {}",
            self.sha256, self.sha1, self.md5
        );
        if let Some(ref imp) = self.imphash {
            s.push_str(&format!("\nIMPHASH: {}", imp));
        }
        if let Some(ref exp) = self.exphash {
            s.push_str(&format!("\nEXPHASH: {}", exp));
        }
        if let Some(ref ssd) = self.ssdeep {
            s.push_str(&format!("\nSSDEEP:  {}", ssd));
        }
        write!(f, "{}", s)
    }
}

pub fn compute_hashes(data: &[u8]) -> FileHashes {
    let sha256_hash = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    };

    let sha1_hash = {
        let mut hasher = Sha1::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    };

    let md5_hash = {
        let mut hasher = Md5::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    };

    let ssdeep_hash = if data.len() >= 32 {
        Some(compute_ssdeep(data))
    } else {
        None
    };

    FileHashes {
        sha256: sha256_hash,
        sha1: sha1_hash,
        md5: md5_hash,
        ssdeep: ssdeep_hash,
        imphash: None,
        exphash: None,
    }
}

pub fn compute_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

struct RollState {
    window: [u8; 7],
    h1: u32,
    h2: u32,
    h3: u32,
    n: usize,
}

impl RollState {
    fn new() -> Self {
        Self {
            window: [0; 7],
            h1: 0,
            h2: 0,
            h3: 0,
            n: 0,
        }
    }

    fn update(&mut self, b: u8) -> u32 {
        let old = self.window[self.n % 7];
        self.h2 = self.h2.wrapping_add(self.h1);
        self.h2 = self.h2.wrapping_sub((old as u32) * 7);
        self.h1 = self.h1.wrapping_add(b as u32);
        self.h1 = self.h1.wrapping_sub(old as u32);
        self.window[self.n % 7] = b;
        self.n += 1;
        self.h3 = (self.h3 << 5) ^ (b as u32);
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

pub fn compute_ssdeep(data: &[u8]) -> String {
    if data.is_empty() {
        return "3::".to_string();
    }

    let mut min_block_size = 3usize;
    while min_block_size * 64 < data.len() {
        min_block_size *= 2;
    }

    let mut roll = RollState::new();
    let mut str1 = String::with_capacity(64);
    let mut str2 = String::with_capacity(64);

    let mut h1: u32 = 0x2802418f;
    let mut h2: u32 = 0x2802418f;

    let b1 = min_block_size;
    let b2 = min_block_size * 2;

    for &byte in data {
        let r = roll.update(byte);

        h1 = (h1 ^ (byte as u32)).wrapping_mul(0x01000193);
        h2 = (h2 ^ (byte as u32)).wrapping_mul(0x01000193);

        if (r as usize) % b1 == (b1 - 1) {
            if str1.len() < 64 {
                let idx = (h1 as usize) % 64;
                str1.push(B64_CHARS[idx] as char);
            }
            h1 = 0x2802418f;
        }

        if (r as usize) % b2 == (b2 - 1) {
            if str2.len() < 32 {
                let idx = (h2 as usize) % 64;
                str2.push(B64_CHARS[idx] as char);
            }
            h2 = 0x2802418f;
        }
    }

    if str1.len() < 64 {
        let idx = (h1 as usize) % 64;
        str1.push(B64_CHARS[idx] as char);
    }
    if str2.len() < 32 {
        let idx = (h2 as usize) % 64;
        str2.push(B64_CHARS[idx] as char);
    }

    format!("{}:{}:{}", b1, str1, str2)
}

fn parse_ssdeep_sig(s: &str) -> Option<(usize, &str, &str)> {
    let mut parts = s.split(':');
    let bs: usize = parts.next()?.parse().ok()?;
    let s1 = parts.next()?;
    let s2 = parts.next()?;
    Some((bs, s1, s2))
}

pub fn ssdeep_compare(sig1: &str, sig2: &str) -> u32 {
    let (b1, s1_a, s1_b) = match parse_ssdeep_sig(sig1) {
        Some(v) => v,
        None => return 0,
    };
    let (b2, s2_a, s2_b) = match parse_ssdeep_sig(sig2) {
        Some(v) => v,
        None => return 0,
    };

    let (str1, str2) = if b1 == b2 {
        (s1_a, s2_a)
    } else if b1 * 2 == b2 {
        (s1_b, s2_a)
    } else if b2 * 2 == b1 {
        (s1_a, s2_b)
    } else {
        return 0;
    };

    if str1.is_empty() || str2.is_empty() {
        return 0;
    }

    let v1: Vec<char> = str1.chars().collect();
    let v2: Vec<char> = str2.chars().collect();
    let m = v1.len();
    let n = v2.len();

    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    #[allow(clippy::needless_range_loop)]
    for i in 0..=m {
        dp[i][0] = i;
    }
    #[allow(clippy::needless_range_loop)]
    for j in 0..=n {
        dp[0][j] = j;
    }

    for i in 1..=m {
        for j in 1..=n {
            let cost = if v1[i - 1] == v2[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }

    let dist = dp[m][n];
    let max_len = m.max(n);
    if dist >= max_len {
        0
    } else {
        (((max_len - dist) as f64 / max_len as f64) * 100.0) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hashes() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let hashes = compute_hashes(data);
        assert_eq!(
            hashes.sha256,
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
        assert_eq!(hashes.sha1, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
        assert_eq!(hashes.md5, "9e107d9d372bb6826bd81d3542a419d6");
        assert!(hashes.ssdeep.is_some());
    }

    #[test]
    fn test_ssdeep_fuzzy_hash() {
        let sample1 = b"Hello world! This is a long sample string used to compute context triggered piecewise hashing.";
        let mut sample2 = sample1.to_vec();
        // Modify a few bytes
        sample2[10] = b'Z';
        sample2[11] = b'Y';

        let sig1 = compute_ssdeep(sample1);
        let sig2 = compute_ssdeep(&sample2);

        let score = ssdeep_compare(&sig1, &sig2);
        assert!(
            score >= 80,
            "Expected high similarity score between variants, got {}",
            score
        );

        let distant = b"A completely different payload with totally distinct structure and byte distribution completely unrelated.";
        let sig3 = compute_ssdeep(distant);
        let distant_score = ssdeep_compare(&sig1, &sig3);
        assert!(distant_score < score);
    }
}
