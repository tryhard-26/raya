/// Calculates the Shannon entropy of a byte slice.
/// Returns a value between 0.0 (completely uniform/zero information) and 8.0 (maximum randomness/compressed/encrypted).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_zero_entropy() {
        let zeros = vec![0u8; 1000];
        assert_eq!(shannon_entropy(&zeros), 0.0);
    }

    #[test]
    fn test_max_entropy() {
        // Uniform distribution of all 256 bytes
        let mut data = Vec::with_capacity(256 * 10);
        for _ in 0..10 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let ent = shannon_entropy(&data);
        // Shannon entropy of uniform distribution over 256 values is exactly log2(256) = 8.0
        assert!((ent - 8.0).abs() < 1e-6);
    }

    #[test]
    fn test_text_entropy() {
        let text = b"This is a normal English sentence with typical ASCII letters and spaces.";
        let ent = shannon_entropy(text);
        // Natural English text is typically between 3.5 and 4.8
        assert!(ent > 3.0 && ent < 5.5);
    }
}
