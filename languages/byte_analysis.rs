//! ITzMeow80 — snippet di esempio in Rust
//! Utilità per l'analisi forense di file sospetti.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

/// Conta la distribuzione dei byte in un buffer (chiavi esadecimali).
pub fn byte_histogram(data: &[u8]) -> HashMap<u8, usize> {
    let mut hist = HashMap::with_capacity(256);
    for &b in data {
        *hist.entry(b).or_insert(0) += 1;
    }
    hist
}

/// Entropia di Shannon calcolata su un buffer (indicatore di packing/criptazione).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut hist = [0usize; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let len = data.len() as f64;
    hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Cerca sequenze sospette (placeholder comuni nelle shellcode).
pub fn find_suspicious_patterns(data: &[u8]) -> Vec<(usize, &'static str)> {
    let signatures: &[(&[u8], &str)] = &[
        (&[0x4D, 0x5A], "MZ header (PE executable)"),
        (&[0x50, 0x45, 0x00, 0x00], "PE signature"),
        (&[0xE8, 0xE9], "CALL/JMP relativo (possibile shellcode)"),
        (&[0xFF, 0x15], "INDIRECT CALL (API resolution)"),
        (&[0x31, 0xC0], "XOR EAX,EAX (zero-register)"),
    ];
    let mut hits = Vec::new();
    for (pat, name) in signatures {
        for (i, w) in data.windows(pat.len()).enumerate() {
            if w == *pat {
                hits.push((i, *name));
            }
        }
    }
    hits
}

/// Legge un file e ne restituisce l'istogramma e l'entropia.
pub fn analyze_file(path: &Path) -> io::Result<(HashMap<u8, usize>, f64)> {
    let data = fs::read(path)?;
    Ok((byte_histogram(&data), shannon_entropy(&data)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_uniform_data_is_max() {
        let data: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&data) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn detects_mz_header() {
        let data = [0x4D, 0x5A, 0x90, 0x00];
        assert_eq!(find_suspicious_patterns(&data)[0].1, "MZ header (PE executable)");
    }
}
