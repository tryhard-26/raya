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

/// Computes Shannon entropy over sliding windows across the data slice.
/// Returns a vector of tuples `(offset, entropy)`.
pub fn sliding_window_entropy(data: &[u8], window_size: usize, step_size: usize) -> Vec<(usize, f64)> {
    if data.is_empty() || window_size == 0 {
        return Vec::new();
    }
    let actual_step = step_size.max(1);
    let mut results = Vec::new();

    if data.len() <= window_size {
        results.push((0, shannon_entropy(data)));
        return results;
    }

    let mut offset = 0;
    while offset + window_size <= data.len() {
        let chunk = &data[offset..offset + window_size];
        let ent = shannon_entropy(chunk);
        results.push((offset, ent));
        offset += actual_step;
    }

    results
}

/// Finds the maximum window entropy across the data and returns `(max_entropy, offset)`.
pub fn max_window_entropy(data: &[u8], window_size: usize) -> (f64, usize) {
    if data.is_empty() || window_size == 0 {
        return (0.0, 0);
    }
    if data.len() <= window_size {
        return (shannon_entropy(data), 0);
    }

    let step = (window_size / 4).max(1);
    let windows = sliding_window_entropy(data, window_size, step);
    let mut max_ent = 0.0f64;
    let mut best_offset = 0;

    for (off, ent) in windows {
        if ent > max_ent {
            max_ent = ent;
            best_offset = off;
        }
    }

    (max_ent, best_offset)
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

    #[test]
    fn test_sliding_window_entropy() {
        let mut mixed = vec![0u8; 1000];
        // Inject 256 bytes of high entropy in the middle (500..756)
        for i in 0..256 {
            mixed[500 + i] = i as u8;
        }

        let (max_ent, max_off) = max_window_entropy(&mixed, 256);
        assert!(max_ent > 7.0, "Expected high entropy window, got {}", max_ent);
        assert!((max_off as isize - 500).abs() <= 64, "Expected max offset near 500, got {}", max_off);
    }
}
