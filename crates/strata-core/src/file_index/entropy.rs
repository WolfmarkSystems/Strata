//! Shannon entropy for file-content classification.
//!
//! Used to flag encrypted / packed / obfuscated content in the master
//! index. We operate on byte distributions only — no attempt at full
//! compression testing — so the result is a cheap proxy signal.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

/// Shannon entropy in bits/byte over the given buffer. Returns 0.0
/// for empty input.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut h = 0.0f64;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        h -= p * p.log2();
    }
    h
}

/// Streaming entropy — fold byte counts across chunks without
/// materialising the whole file.
#[derive(Debug, Clone)]
pub struct EntropyAccumulator {
    counts: [u64; 256],
    total: u64,
}

impl Default for EntropyAccumulator {
    fn default() -> Self {
        Self {
            counts: [0u64; 256],
            total: 0,
        }
    }
}

impl EntropyAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.counts[b as usize] += 1;
        }
        self.total += bytes.len() as u64;
    }

    pub fn finalize(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let total = self.total as f64;
        let mut h = 0.0f64;
        for &c in &self.counts {
            if c == 0 {
                continue;
            }
            let p = c as f64 / total;
            h -= p * p.log2();
        }
        h
    }
}

/// Heuristic tier label based on entropy.
pub fn classify(entropy: f64) -> &'static str {
    if entropy > 7.9 {
        "VeryHigh"
    } else if entropy > 7.5 {
        "High"
    } else if entropy > 5.0 {
        "Medium"
    } else {
        "Low"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_entropy_bounds() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0u8; 32]), 0.0);
        let uniform: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&uniform);
        assert!((e - 8.0).abs() < 0.001);
    }

    #[test]
    fn streaming_matches_direct_computation() {
        let sample = (0..256u32).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let direct = shannon_entropy(&sample);
        let mut acc = EntropyAccumulator::new();
        for chunk in sample.chunks(17) {
            acc.update(chunk);
        }
        let streamed = acc.finalize();
        assert!((direct - streamed).abs() < 1e-9);
    }

    #[test]
    fn classify_tiers_threshold_correctly() {
        assert_eq!(classify(0.0), "Low");
        assert_eq!(classify(6.0), "Medium");
        assert_eq!(classify(7.6), "High");
        assert_eq!(classify(7.95), "VeryHigh");
    }
}
