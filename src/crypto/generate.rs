//! Drawing new passwords from random bytes, and measuring their strength.
//!
//! Every choice, whether a character, a word, a separator, or the word to
//! capitalize, is "pick one of `n`". [`below`] makes that pick without bias,
//! and [`pick`] reads the chosen entry by scanning its whole table with a
//! mask, so no memory access depends on the secret index.
//!
//! The one branch on secret data is the decision to draw again. [`below`]
//! draws again when a 16-bit value falls in the biased remainder, and
//! [`password`] draws a whole password again when it misses a required set
//! or repeats a character too often. Each decision depends on a value that
//! is then thrown away, so its timing says nothing about the value kept.
//! `AGENTS.md` names this exception beside scrypt's lookups.

use std::io;

use super::ct_eq_mask;

/// The 32 ASCII punctuation characters, the default symbols.
pub const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
pub const DIGITS: &[u8] = b"0123456789";
pub const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

/// The EFF's large word list, one lowercase word per line.
const EFF_LARGE: &str = include_str!("wordlist/eff_large.txt");
/// The longest word in [`EFF_LARGE`], which `tests::eff_list_is_the_published_one`
/// checks.
const WORD_WIDTH: usize = 9;

/// What to draw. A recipe holds no secret, so it can be printed and compared.
#[derive(Debug, Clone, PartialEq)]
pub enum Recipe {
    Chars(Chars),
    Words(Words),
    Pin { length: usize },
}

/// Random characters drawn from the union of `cells`.
#[derive(Debug, Clone, PartialEq)]
pub struct Chars {
    /// Disjoint sets of distinct characters.
    pub cells: Vec<Cell>,
    /// How many requirements the cells' `satisfies` bits name. A password is
    /// kept only when its characters satisfy every one.
    pub requirements: u32,
    pub length: usize,
    /// The most times one character may appear in a row, or `None` for no
    /// limit.
    pub max_consecutive: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cell {
    pub chars: Vec<u8>,
    /// Bit `i` is set when a character from this cell meets requirement `i`.
    pub satisfies: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Words {
    pub count: usize,
    pub separator: Separator,
    pub capitalize: Capitalize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Separator {
    /// The same character between every pair of words.
    Fixed(u8),
    /// A new random digit in each gap.
    Digit,
    /// A new random digit or symbol from [`SYMBOLS`] in each gap.
    DigitOrSymbol,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Capitalize {
    None,
    /// The first letter of every word.
    First,
    /// The first letter of one word, chosen at random.
    One,
}

/// A drawn password: the first `len` bytes of `bytes` are ASCII. The buffer's
/// size depends only on the recipe.
pub struct Generated {
    pub bytes: Vec<u8>,
    pub len: usize,
}

/// The number of entries in the word list.
pub fn word_count() -> usize {
    EFF_LARGE.lines().count()
}

/// Draws a password from the operating system's generator.
pub fn password(recipe: &Recipe) -> io::Result<Generated> {
    password_from(recipe, &mut super::random::fill)
}

/// Draws a password from the bytes `fill` supplies, so tests can feed a
/// fixed stream.
pub fn password_from(
    recipe: &Recipe,
    fill: &mut dyn FnMut(&mut [u8]) -> io::Result<()>,
) -> io::Result<Generated> {
    let mut source = Source::new(fill);
    match recipe {
        Recipe::Chars(chars) => draw_chars(chars, &mut source),
        Recipe::Pin { length } => draw_chars(&pin_chars(*length), &mut source),
        Recipe::Words(words) => draw_words(words, &mut source),
    }
}

/// The strength of `recipe` in bits: `log2` of the number of passwords it
/// can produce, each equally likely. Negative infinity means it can produce
/// none.
pub fn entropy(recipe: &Recipe) -> f64 {
    match recipe {
        Recipe::Chars(chars) => chars_entropy(chars),
        Recipe::Pin { length } => chars_entropy(&pin_chars(*length)),
        Recipe::Words(words) => {
            let gaps = words.count.saturating_sub(1) as f64;
            let separator = match words.separator {
                Separator::Fixed(_) => 0.0,
                Separator::Digit => (DIGITS.len() as f64).log2(),
                Separator::DigitOrSymbol => ((DIGITS.len() + SYMBOLS.len()) as f64).log2(),
            };
            let capitalize = match words.capitalize {
                Capitalize::One => (words.count as f64).log2(),
                Capitalize::None | Capitalize::First => 0.0,
            };
            words.count as f64 * (word_count() as f64).log2() + gaps * separator + capitalize
        }
    }
}

/// The share of uniformly drawn strings of `chars.length` characters that
/// meet every requirement and the run limit. [`password`] draws again for
/// the rest, so this is the chance that one draw is kept.
pub fn acceptance(chars: &Chars) -> f64 {
    let alphabet: usize = chars.cells.iter().map(|cell| cell.chars.len()).sum();
    if alphabet == 0 || chars.length == 0 {
        return 0.0;
    }
    let full = (1u32 << chars.requirements) - 1;
    // The run length is tracked only up to the limit; with no limit, every
    // state has run 1.
    let runs = match chars.max_consecutive {
        Some(limit) if limit < chars.length => limit,
        _ => 1,
    };
    let limited = runs > 1 || chars.max_consecutive == Some(1);
    let cells = chars.cells.len();
    let index =
        |mask: u32, run: usize, cell: usize| ((mask as usize * runs) + run - 1) * cells + cell;
    let size = (1usize << chars.requirements) * runs * cells;
    let a = alphabet as f64;

    // p[mask, run, cell] is the probability that the characters so far meet
    // the requirements in `mask`, end in a run of `run` equal characters,
    // and end with a character from `cell`.
    let mut p = vec![0.0f64; size];
    for (c, cell) in chars.cells.iter().enumerate() {
        p[index(cell.satisfies, 1, c)] += cell.chars.len() as f64 / a;
    }
    for _ in 1..chars.length {
        let mut next = vec![0.0f64; size];
        for mask in 0..=full {
            for run in 1..=runs {
                for prev in 0..cells {
                    let v = p[index(mask, run, prev)];
                    if v == 0.0 {
                        continue;
                    }
                    for (c, cell) in chars.cells.iter().enumerate() {
                        let m = mask | cell.satisfies;
                        let s = cell.chars.len() as f64;
                        if limited {
                            // Any other character of this cell starts a new
                            // run; the same character extends this one.
                            let others = if c == prev { s - 1.0 } else { s };
                            next[index(m, 1, c)] += v * others / a;
                            if c == prev && run < runs {
                                next[index(m, run + 1, c)] += v / a;
                            }
                        } else {
                            next[index(m, 1, c)] += v * s / a;
                        }
                    }
                }
            }
        }
        p = next;
    }
    (1..=runs)
        .flat_map(|run| (0..cells).map(move |c| (run, c)))
        .map(|(run, c)| p[index(full, run, c)])
        .sum()
}

fn chars_entropy(chars: &Chars) -> f64 {
    let alphabet: usize = chars.cells.iter().map(|cell| cell.chars.len()).sum();
    chars.length as f64 * (alphabet as f64).log2() + acceptance(chars).log2()
}

fn pin_chars(length: usize) -> Chars {
    Chars {
        cells: vec![Cell {
            chars: DIGITS.to_vec(),
            satisfies: 0,
        }],
        requirements: 0,
        length,
        max_consecutive: None,
    }
}

/// Random bytes, read from `fill` 64 at a time.
struct Source<'a> {
    fill: &'a mut dyn FnMut(&mut [u8]) -> io::Result<()>,
    buf: [u8; 64],
    pos: usize,
}

impl<'a> Source<'a> {
    fn new(fill: &'a mut dyn FnMut(&mut [u8]) -> io::Result<()>) -> Self {
        Source {
            fill,
            buf: [0; 64],
            pos: 64,
        }
    }

    fn u16(&mut self) -> io::Result<u16> {
        if self.pos + 2 > self.buf.len() {
            (self.fill)(&mut self.buf)?;
            self.pos = 0;
        }
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
}

/// Maps a 16-bit value to an index below `n`, or `None` when the value falls
/// in the remainder that would favor some indexes. This is Lemire's method:
/// the high half of `v × n` is the index, and the low half tells whether `v`
/// is one of the `65536 mod n` values to reject. It multiplies rather than
/// divides, because division takes longer for some values on some CPUs.
fn reduce(v: u16, n: u32) -> Option<u32> {
    debug_assert!((1..=1 << 16).contains(&n));
    let m = v as u32 * n;
    let threshold = (1u32 << 16) % n;
    if (m & 0xffff) < threshold {
        None
    } else {
        Some(m >> 16)
    }
}

/// An index below `n`, every one equally likely.
fn below(n: usize, source: &mut Source) -> io::Result<usize> {
    loop {
        if let Some(i) = reduce(source.u16()?, n as u32) {
            return Ok(i as usize);
        }
    }
}

/// All ones when `a < b`, and zero otherwise, for values below `2^63`.
fn ct_lt_mask(a: usize, b: usize) -> usize {
    0usize.wrapping_sub(a.wrapping_sub(b) >> (usize::BITS - 1))
}

/// `table[i]`, read by scanning every entry.
fn pick(table: &[u8], i: usize) -> u8 {
    table
        .iter()
        .enumerate()
        .fold(0u8, |acc, (j, &b)| acc | (b & ct_eq_mask(i, j) as u8))
}

fn draw_chars(chars: &Chars, source: &mut Source) -> io::Result<Generated> {
    let alphabet: Vec<u8> = chars
        .cells
        .iter()
        .flat_map(|cell| cell.chars.clone())
        .collect();
    let mut bounds = Vec::with_capacity(chars.cells.len());
    let mut start = 0;
    for cell in &chars.cells {
        bounds.push((start, start + cell.chars.len(), cell.satisfies as usize));
        start += cell.chars.len();
    }
    let full = (1usize << chars.requirements) - 1;
    let limit = chars.max_consecutive.unwrap_or(usize::MAX >> 1);
    let mut indexes = vec![0usize; chars.length];
    loop {
        let mut met = 0usize;
        let mut run = 0usize;
        let mut too_long = 0usize;
        for k in 0..chars.length {
            let i = below(alphabet.len(), source)?;
            for &(lo, hi, satisfies) in &bounds {
                let inside = !ct_lt_mask(i, lo) & ct_lt_mask(i, hi);
                met |= satisfies & inside;
            }
            let same = if k == 0 {
                0
            } else {
                ct_eq_mask(i, indexes[k - 1])
            };
            run = ((run + 1) & same) | (1 & !same);
            too_long |= ct_lt_mask(limit, run);
            indexes[k] = i;
        }
        if met == full && too_long == 0 {
            break;
        }
    }
    let bytes: Vec<u8> = indexes.iter().map(|&i| pick(&alphabet, i)).collect();
    let len = bytes.len();
    Ok(Generated { bytes, len })
}

/// The word list as fixed-width rows, padded with zero bytes, and each
/// word's length.
fn word_table() -> (Vec<[u8; WORD_WIDTH]>, Vec<usize>) {
    let mut rows = Vec::new();
    let mut lens = Vec::new();
    for word in EFF_LARGE.lines() {
        let mut row = [0u8; WORD_WIDTH];
        row[..word.len()].copy_from_slice(word.as_bytes());
        rows.push(row);
        lens.push(word.len());
    }
    (rows, lens)
}

/// Row `i` and its length, read by scanning every row.
fn pick_word(rows: &[[u8; WORD_WIDTH]], lens: &[usize], i: usize) -> ([u8; WORD_WIDTH], usize) {
    let mut out = [0u8; WORD_WIDTH];
    let mut len = 0usize;
    for (j, (row, &l)) in rows.iter().zip(lens).enumerate() {
        let mask = ct_eq_mask(i, j);
        for (o, &b) in out.iter_mut().zip(row) {
            *o |= b & mask as u8;
        }
        len |= l & mask;
    }
    (out, len)
}

fn draw_words(words: &Words, source: &mut Source) -> io::Result<Generated> {
    let (rows, lens) = word_table();
    let separators: Vec<u8> = match words.separator {
        Separator::Fixed(b) => vec![b],
        Separator::Digit => DIGITS.to_vec(),
        Separator::DigitOrSymbol => [DIGITS, SYMBOLS].concat(),
    };
    let capitalized = match words.capitalize {
        Capitalize::One => below(words.count, source)?,
        Capitalize::None | Capitalize::First => 0,
    };

    // Each word fills a slot of WORD_WIDTH bytes followed by one separator
    // byte. `real` marks the bytes that belong to the password, so the
    // padding can be squeezed out below without a branch.
    let slot = WORD_WIDTH + 1;
    let width = words.count * slot - 1;
    let mut bytes = vec![0u8; width];
    let mut real = vec![0usize; width];
    for w in 0..words.count {
        let (mut word, len) = pick_word(&rows, &lens, below(rows.len(), source)?);
        let upper = match words.capitalize {
            Capitalize::None => 0,
            Capitalize::First => usize::MAX,
            Capitalize::One => ct_eq_mask(w, capitalized),
        };
        // Every word starts with a lowercase ASCII letter, which this makes
        // uppercase.
        word[0] -= 0x20 & upper as u8;
        for (b, &byte) in word.iter().enumerate() {
            bytes[w * slot + b] = byte;
            real[w * slot + b] = ct_lt_mask(b, len);
        }
        if w + 1 < words.count {
            let s = below(separators.len(), source)?;
            bytes[w * slot + WORD_WIDTH] = pick(&separators, s);
            real[w * slot + WORD_WIDTH] = usize::MAX;
        }
    }

    // Moves each real byte to its rank among the real bytes: output byte k
    // takes the real byte that has k real bytes before it.
    let mut ranks = vec![0usize; width];
    let mut len = 0usize;
    for j in 0..width {
        ranks[j] = len;
        len += real[j] & 1;
    }
    let mut out = vec![0u8; width];
    for (k, o) in out.iter_mut().enumerate() {
        for j in 0..width {
            *o |= bytes[j] & (ct_eq_mask(ranks[j], k) & real[j]) as u8;
        }
    }
    Ok(Generated { bytes: out, len })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;
    use crate::crypto::hmac::Digest;
    use crate::crypto::sha256::Sha256;

    /// A repeatable stream of random-looking bytes, SHA-256 of a seed and a
    /// counter, so tests never read `/dev/urandom`.
    fn stream(seed: u8) -> impl FnMut(&mut [u8]) -> io::Result<()> {
        let mut counter = 0u64;
        move |buf: &mut [u8]| {
            for chunk in buf.chunks_mut(32) {
                let mut input = vec![seed];
                input.extend_from_slice(&counter.to_le_bytes());
                let block = Sha256::digest(&input);
                chunk.copy_from_slice(&block[..chunk.len()]);
                counter += 1;
            }
            Ok(())
        }
    }

    fn draw(recipe: &Recipe, fill: &mut dyn FnMut(&mut [u8]) -> io::Result<()>) -> String {
        let g = password_from(recipe, fill).unwrap();
        String::from_utf8(g.bytes[..g.len].to_vec()).unwrap()
    }

    fn sets(lists: &[&[u8]]) -> Chars {
        Chars {
            cells: lists
                .iter()
                .enumerate()
                .map(|(i, chars)| Cell {
                    chars: chars.to_vec(),
                    satisfies: 1 << i,
                })
                .collect(),
            requirements: lists.len() as u32,
            length: 20,
            max_consecutive: None,
        }
    }

    fn default_chars(length: usize) -> Chars {
        Chars {
            length,
            ..sets(&[UPPERCASE, LOWERCASE, DIGITS, SYMBOLS])
        }
    }

    fn bits(recipe: &Recipe) -> String {
        format!("{:.1}", entropy(recipe))
    }

    #[test]
    fn every_16_bit_value_maps_evenly() {
        // Feeding each 16-bit value once must hit every index equally often.
        // A plain `v % n` would hit the first `65536 mod n` indexes once more.
        for n in [10u32, 94, 2000, 7776] {
            let mut counts = vec![0u32; n as usize];
            for v in 0..=u16::MAX {
                if let Some(i) = reduce(v, n) {
                    counts[i as usize] += 1;
                }
            }
            let each = (1u32 << 16) / n;
            assert!(counts.iter().all(|&c| c == each), "n = {n}");
        }
    }

    #[test]
    fn rejects_only_the_biased_remainder() {
        // Exactly `65536 mod n` values are drawn again, and every kept value
        // maps below n. Rejecting more wastes draws; rejecting fewer leaves
        // bias, which `every_16_bit_value_maps_evenly` catches.
        for n in [10u32, 94, 7776, 1 << 16] {
            let kept: Vec<u32> = (0..=u16::MAX).filter_map(|v| reduce(v, n)).collect();
            assert_eq!(65536 - kept.len() as u32, (1u32 << 16) % n, "n = {n}");
            assert!(kept.iter().all(|&i| i < n), "n = {n}");
        }
    }

    #[test]
    fn draws_are_uniform() {
        let mut fill = stream(1);
        let mut source = Source::new(&mut fill);
        let draws = 1_000_000;
        let mut counts = [0u32; 94];
        for _ in 0..draws {
            counts[below(94, &mut source).unwrap()] += 1;
        }
        let expected = draws as f64 / 94.0;
        let sd = (expected * (1.0 - 1.0 / 94.0)).sqrt();
        for (i, &c) in counts.iter().enumerate() {
            assert!((c as f64 - expected).abs() < 5.0 * sd, "index {i}: {c}");
        }
    }

    #[test]
    fn masked_reads_match_plain_indexing() {
        let table: Vec<u8> = (0..=255).collect();
        for i in 0..256 {
            assert_eq!(pick(&table, i), i as u8);
        }
        let (rows, lens) = word_table();
        for (i, word) in EFF_LARGE.lines().enumerate() {
            let (row, len) = pick_word(&rows, &lens, i);
            assert_eq!(&row[..len], word.as_bytes(), "index {i}");
        }
    }

    #[test]
    fn eff_list_is_the_published_one() {
        // The EFF's file with the dice numbers and tabs removed. A changed
        // list would make the strength line wrong.
        assert_eq!(
            Sha256::digest(EFF_LARGE.as_bytes()).to_vec(),
            hex("6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522")
        );
        let words: Vec<&str> = EFF_LARGE.lines().collect();
        assert_eq!(words.len(), 7776);
        let distinct: std::collections::BTreeSet<&str> = words.iter().copied().collect();
        assert_eq!(distinct.len(), 7776);
        assert!(words.iter().all(|w| {
            w.starts_with(|c: char| c.is_ascii_lowercase())
                && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        }));
        assert_eq!(words.iter().map(|w| w.len()).max(), Some(WORD_WIDTH));
    }

    #[test]
    fn counts_passwords_that_meet_requirements() {
        // Four characters over {a, 1} with both required: 16 minus aaaa and
        // 1111.
        let chars = Chars {
            length: 4,
            ..sets(&[b"a", b"1"])
        };
        assert!((entropy(&Recipe::Chars(chars)) - 14f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn counts_match_brute_force() {
        // Every string over a small alphabet, checked by hand against the
        // requirements and the run limit.
        let cells: [&[u8]; 4] = [b"ABC", b"de", b"45", b"!"];
        for limit in [None, Some(1), Some(2)] {
            let chars = Chars {
                length: 4,
                max_consecutive: limit,
                ..sets(&cells)
            };
            let alphabet: Vec<u8> = cells.concat();
            let mut count = 0u32;
            for n in 0..alphabet.len().pow(4) {
                let s: Vec<u8> = (0..4)
                    .map(|k| alphabet[n / alphabet.len().pow(k) % alphabet.len()])
                    .collect();
                let all_sets = cells.iter().all(|cell| s.iter().any(|b| cell.contains(b)));
                let mut longest = 1;
                let mut run = 1;
                for k in 1..4 {
                    run = if s[k] == s[k - 1] { run + 1 } else { 1 };
                    longest = longest.max(run);
                }
                if all_sets && limit.is_none_or(|l| longest <= l) {
                    count += 1;
                }
            }
            let expected = (count as f64).log2();
            assert!(
                (entropy(&Recipe::Chars(chars)) - expected).abs() < 1e-9,
                "limit {limit:?}: {count}"
            );
        }
    }

    #[test]
    fn counts_runs() {
        // Three characters over {a, b} with at most two in a row: 8 minus
        // aaa and bbb.
        let chars = Chars {
            cells: vec![Cell {
                chars: b"ab".to_vec(),
                satisfies: 0,
            }],
            requirements: 0,
            length: 3,
            max_consecutive: Some(2),
        };
        assert!((entropy(&Recipe::Chars(chars.clone())) - 6f64.log2()).abs() < 1e-9);
        let mut fill = stream(2);
        let recipe = Recipe::Chars(Chars {
            length: 12,
            ..chars
        });
        for _ in 0..10_000 {
            let s = draw(&recipe, &mut fill);
            assert!(!s.contains("aaa") && !s.contains("bbb"), "{s}");
        }
    }

    #[test]
    fn states_the_plans_strengths() {
        assert_eq!(bits(&Recipe::Chars(default_chars(20))), "130.9");
        let words = |separator, capitalize| {
            Recipe::Words(Words {
                count: 5,
                separator,
                capitalize,
            })
        };
        assert_eq!(
            bits(&words(Separator::Fixed(b'-'), Capitalize::None)),
            "64.6"
        );
        assert_eq!(bits(&words(Separator::Digit, Capitalize::One)), "80.2");
        assert_eq!(bits(&Recipe::Pin { length: 6 }), "19.9");
        // The plan's rules example: 16 characters, lower, upper, and digits
        // required, four symbols allowed, at most two in a row.
        let rules = Chars {
            cells: vec![
                Cell {
                    chars: LOWERCASE.to_vec(),
                    satisfies: 1,
                },
                Cell {
                    chars: UPPERCASE.to_vec(),
                    satisfies: 2,
                },
                Cell {
                    chars: DIGITS.to_vec(),
                    satisfies: 4,
                },
                Cell {
                    chars: b"-!#$".to_vec(),
                    satisfies: 0,
                },
            ],
            requirements: 3,
            length: 16,
            max_consecutive: Some(2),
        };
        assert_eq!(bits(&Recipe::Chars(rules)), "96.6");
    }

    #[test]
    fn redraws_about_one_in_nine_default_passwords() {
        let missed = 1.0 - acceptance(&default_chars(20));
        assert!((0.10..0.12).contains(&missed), "{missed}");
    }

    #[test]
    fn random_passwords_hold_every_required_set() {
        let mut fill = stream(3);
        let recipe = Recipe::Chars(default_chars(4));
        for _ in 0..2000 {
            let s = draw(&recipe, &mut fill);
            assert_eq!(s.len(), 4);
            for set in [UPPERCASE, LOWERCASE, DIGITS, SYMBOLS] {
                assert!(s.bytes().any(|b| set.contains(&b)), "{s}");
            }
        }
    }

    #[test]
    fn memorable_passwords_join_listed_words() {
        let mut fill = stream(4);
        let list: std::collections::BTreeSet<&str> = EFF_LARGE.lines().collect();
        for (separator, capitalize) in [
            (Separator::Fixed(b' '), Capitalize::None),
            (Separator::Digit, Capitalize::First),
            (Separator::DigitOrSymbol, Capitalize::One),
        ] {
            let recipe = Recipe::Words(Words {
                count: 5,
                separator,
                capitalize,
            });
            for _ in 0..200 {
                let s = draw(&recipe, &mut fill);
                // Words hold only letters and hyphens. A separator can be a
                // hyphen too, so split on the gaps' known positions instead:
                // each word is the longest run of letters and inner hyphens
                // that the list holds.
                let parts = split_words(&s, &list);
                assert_eq!(parts.len(), 5, "{s}");
                let capitals = parts
                    .iter()
                    .filter(|w| w.starts_with(|c: char| c.is_ascii_uppercase()))
                    .count();
                let expected = match capitalize {
                    Capitalize::None => 0,
                    Capitalize::First => 5,
                    Capitalize::One => 1,
                };
                assert_eq!(capitals, expected, "{s}");
                for part in parts {
                    assert!(list.contains(part.to_ascii_lowercase().as_str()), "{s}");
                }
            }
        }
    }

    /// Splits a memorable password back into its words, trying the longest
    /// listed word at each position, so a hyphen inside `t-shirt` and a
    /// hyphen separator are told apart.
    fn split_words<'a>(s: &'a str, list: &std::collections::BTreeSet<&str>) -> Vec<&'a str> {
        let mut parts = Vec::new();
        let mut rest = s;
        while !rest.is_empty() {
            let end = (1..=rest.len().min(WORD_WIDTH))
                .rev()
                .find(|&n| list.contains(rest[..n].to_ascii_lowercase().as_str()))
                .unwrap_or_else(|| panic!("no word starts {rest:?} in {s:?}"));
            parts.push(&rest[..end]);
            // Skip the one separator character after the word.
            rest = rest.get(end + 1..).unwrap_or("");
        }
        parts
    }

    #[test]
    fn pins_are_digits() {
        let mut fill = stream(5);
        let s = draw(&Recipe::Pin { length: 6 }, &mut fill);
        assert_eq!(s.len(), 6);
        assert!(s.bytes().all(|b| b.is_ascii_digit()), "{s}");
    }
}
