use crate::{MaskedByte, Pattern};

pub type AtomQuality = usize;

pub const ATOM_QUALITY_THRESHOLD: AtomQuality = 40;

fn evaluate_atom_quality<'a>(pattern: Pattern<'a>) -> AtomQuality {
    // Precondition: all bytes are unmasked

    // Ideas are kindly borrowed from YARA.
    // See: https://github.com/VirusTotal/yara

    fn evaluate_byte_quality(byte: u8) -> AtomQuality {
        match byte {
            0x00 | 0xFF => 12,
            0x80 | 0x7F | 0x20 | 0xCC => 15,
            _ => 20,
        }
    }

    pattern.iter().map(|b| evaluate_byte_quality(b.byte)).sum()
}

fn find_largest_sequences_of_unmasked_bytes(masked_bytes: &[MaskedByte]) -> Vec<(usize, usize)> {
    let mut res = Vec::new();
    let mut start = 0;

    for (i, b) in masked_bytes.iter().enumerate() {
        if !b.is_unmasked() {
            if i != start {
                res.push((start, i));
            }
            start = i + 1;
        }
    }

    if start != masked_bytes.len() {
        res.push((start, masked_bytes.len()));
    }

    res
}

pub fn find_best_atom<'a>(pattern: Pattern<'a>) -> Option<(usize, usize, AtomQuality)> {
    // From all possible atoms, find the atom with highest quality.

    find_largest_sequences_of_unmasked_bytes(pattern)
        .into_iter()
        .map(|(start, end)| (start, end, evaluate_atom_quality(&pattern[start..end])))
        .max_by_key(|&(_, _, quality)| quality)
}
