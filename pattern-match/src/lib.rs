pub use pattern_match_macros::ida;

use crate::atom::{find_best_atom, ATOM_QUALITY_THRESHOLD};

mod atom;

#[derive(Debug)]
pub struct MaskedByte {
    byte: u8,
    mask: u8,
}

impl MaskedByte {
    pub const fn masked() -> Self {
        Self { byte: 0, mask: 0 }
    }

    pub const fn full(byte: u8) -> Self {
        Self { byte, mask: 0xFF }
    }

    pub const fn new(byte: u8, mask: u8) -> Self {
        Self { byte, mask }
    }

    pub const fn is_unmasked(&self) -> bool {
        self.mask == 0xFF
    }

    pub const fn match_haystack(&self, other: &u8) -> bool {
        self.mask & *other == self.byte & self.mask
    }
}

pub type Pattern<'a> = &'a [MaskedByte];

// Matches Pattern against a haystack.
// Pattern length must be equal to haystack length.
fn match_haystack(pattern: Pattern<'_>, haystack: &[u8]) -> bool {
    assert_eq!(pattern.len(), haystack.len());

    pattern
        .iter()
        .zip(haystack.iter())
        .all(|(p, h)| p.match_haystack(h))
}

fn pattern_to_bytes(pat: Pattern<'_>) -> Vec<u8> {
    pat.into_iter().map(|x| x.byte).collect()
}

pub fn find_overlapping_all(pattern: Pattern<'_>, haystack: &[u8]) -> Vec<usize> {
    // For each pattern, find the best representing atom to search for.
    let (start, end, quality) = find_best_atom(pattern).unwrap();
    // TODO: fallback
    assert!(quality >= ATOM_QUALITY_THRESHOLD);
    let atom_bytes = pattern_to_bytes(&pattern[start..end]);

    // Find atom matches.
    let ac = aho_corasick::AhoCorasick::new(&[atom_bytes.as_ref() as &[u8]]).unwrap();
    let mut matches = Vec::new();

    for m in ac.find_overlapping_iter(haystack) {
        let offset = m.start() - start;
        if match_haystack(pattern, &haystack[offset..offset + pattern.len()]) {
            matches.push(offset);
        }
    }

    matches
}

pub fn find_one(pattern: Pattern<'_>, haystack: &[u8]) -> Option<usize> {
    // For each pattern, find the best representing atom to search for.
    let (start, end, quality) = find_best_atom(pattern).unwrap();
    // TODO: fallback
    assert!(quality >= ATOM_QUALITY_THRESHOLD);
    let atom_bytes = pattern_to_bytes(&pattern[start..end]);

    // Find atom matches.
    let ac = aho_corasick::AhoCorasick::new(&[atom_bytes.as_ref() as &[u8]]).unwrap();

    for m in ac.find_overlapping_iter(haystack) {
        let offset = m.start() - start;
        if match_haystack(pattern, &haystack[offset..offset + pattern.len()]) {
            return Some(offset);
        }
    }

    None
}

pub fn find_multiple_overlapping(patterns: &[Pattern<'_>], haystack: &[u8]) -> Vec<Vec<usize>> {
    // For each pattern, find the best representing atom to search for.
    let best_atoms: Vec<(usize, Vec<u8>)> = patterns
        .into_iter()
        .map(|pat| {
            let (start, end, quality) = find_best_atom(pat).unwrap();
            // TODO: fallback
            assert!(quality >= ATOM_QUALITY_THRESHOLD);
            (start, pattern_to_bytes(&pat[start..end]))
        })
        .collect();

    // Convert into Vec<&[u8]>, for seach_multiple expects &[&[u8]].
    let best_atoms_ref: Vec<&[u8]> = best_atoms.iter().map(|(_, v)| v.as_ref()).collect();

    // Find atom matches.
    let ac = aho_corasick::AhoCorasick::new(&best_atoms_ref).unwrap();
    let mut matches = vec![Vec::new(); patterns.len()];

    for m in ac.find_overlapping_iter(haystack) {
        let pattern_id = m.pattern().as_usize();
        let pat = patterns[pattern_id];
        let atom_start = best_atoms[pattern_id].0;
        let offset = m.start() - atom_start;
        if match_haystack(pat, &haystack[offset..offset + pat.len()]) {
            matches[pattern_id].push(offset);
        }
    }

    matches
}
