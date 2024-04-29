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

trait MultipleSearch {
    // Search for multiple byte-patterns.
    // Returns the list of matches M, where i is the index of the pattern in `patterns`,
    // j is the index of the match, M[i][j] is the offset in the haystack of the start of the match.
    fn search_multiple(&self, haystack: &[u8], patterns: &[&[u8]]) -> Vec<Vec<usize>>;
}

trait SingleSearch {
    #[allow(dead_code)]
    fn search_single(&self, haystack: &[u8], pattern: Pattern<'_>) -> Vec<usize>;
}

struct AhoCorasickMultipleSearch;

impl MultipleSearch for AhoCorasickMultipleSearch {
    fn search_multiple(&self, haystack: &[u8], patterns: &[&[u8]]) -> Vec<Vec<usize>> {
        let ac = aho_corasick::AhoCorasick::new(patterns).unwrap();
        let mut matches = vec![Vec::new(); patterns.len()];

        for m in ac.find_overlapping_iter(haystack) {
            let pattern_id = m.pattern().as_usize();
            matches[pattern_id].push(m.start());
        }

        matches
    }
}

struct KmpMultipleSearch;

impl MultipleSearch for KmpMultipleSearch {
    fn search_multiple(&self, haystack: &[u8], patterns: &[&[u8]]) -> Vec<Vec<usize>> {
        patterns
            .into_iter()
            .map(|&pat| kmp::kmp_match(pat, haystack))
            .collect()
    }
}

struct UnimplementedSingleSearch;

impl SingleSearch for UnimplementedSingleSearch {
    fn search_single(&self, _haystack: &[u8], _pattern: Pattern<'_>) -> Vec<usize> {
        unimplemented!()
    }
}

// Searches for multiple masked byte patterns.
fn find_multiple_overlapping_inner(
    haystack: &[u8],
    patterns: &[Pattern<'_>],
    multiple: impl MultipleSearch,
    _fallback: impl SingleSearch,
) -> Vec<Vec<usize>> {
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
    let mut matches = multiple.search_multiple(haystack, &best_atoms_ref);

    // Perform exactt pattern matches.
    matches.iter_mut().enumerate().for_each(|(i, m)| {
        let pat = patterns[i];
        let atom_start = best_atoms[i].0;

        // Filter out atom matches that do not match the entire pattern.
        m.retain_mut(|offset| {
            *offset -= atom_start;
            let offset = *offset;
            match_haystack(pat, &haystack[offset..offset + pat.len()])
        });
    });

    matches
}

fn find_single_overlapping_inner(
    haystack: &[u8],
    pattern: Pattern<'_>,
    multiple: impl MultipleSearch,
    _fallback: impl SingleSearch,
) -> Vec<usize> {
    let (start, end, quality) = find_best_atom(pattern).unwrap();
    // TODO: fallback
    assert!(quality >= ATOM_QUALITY_THRESHOLD);
    let atom_bytes = pattern_to_bytes(&pattern[start..end]);

    // Find atom matches.
    let mut m = multiple
        .search_multiple(haystack, &[atom_bytes.as_ref()])
        .pop()
        .unwrap();

    // Perform exact pattern matches.
    // Filter out atom matches that do not match the entire pattern.
    m.retain_mut(|offset| {
        *offset -= start;
        let offset = *offset;
        match_haystack(pattern, &haystack[offset..offset + pattern.len()])
    });

    m
}

pub fn find_overlapping(pattern: Pattern<'_>, haystack: &[u8]) -> Vec<usize> {
    find_single_overlapping_inner(
        haystack,
        pattern,
        KmpMultipleSearch,
        UnimplementedSingleSearch,
    )
}

pub fn find_multiple_overlapping(patterns: &[Pattern<'_>], haystack: &[u8]) -> Vec<Vec<usize>> {
    find_multiple_overlapping_inner(
        haystack,
        patterns,
        AhoCorasickMultipleSearch,
        UnimplementedSingleSearch,
    )
}
