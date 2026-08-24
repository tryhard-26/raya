use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileHashes {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
}

impl fmt::Display for FileHashes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SHA256: {}\nSHA1:   {}\nMD5:    {}",
            self.sha256, self.sha1, self.md5
        )
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

    FileHashes {
        sha256: sha256_hash,
        sha1: sha1_hash,
        md5: md5_hash,
    }
}

pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
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
        assert_eq!(
            hashes.sha1,
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
        assert_eq!(
            hashes.md5,
            "9e107d9d372bb6826bd81d3542a419d6"
        );
    }
}
