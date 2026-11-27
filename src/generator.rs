//! The command line's password options: turning them into a
//! `crypto::generate::Recipe`, describing the recipe's strength, and turning
//! a drawn password into text.

use crate::crypto::generate::{
    self, Capitalize, Cell, Chars, DIGITS, LOWERCASE, Recipe, SYMBOLS, Separator, UPPERCASE,
    WordList, Words,
};

/// Characters that are easy to misread for one another.
const LOOKALIKES: &[u8] = b"0Oo1lI|";
/// Below this strength the line warns, because a password an attacker can
/// guess offline at full speed needs at least this much.
const WEAK_BITS: f64 = 64.0;
/// A recipe whose draws are kept less often than this would loop for a long
/// time, so it is refused as too narrow.
const MIN_ACCEPTANCE: f64 = 1e-6;

/// The options as given. Each is `None` or `false` when absent, so errors
/// can name the option that does not fit.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Options {
    pub length: Option<usize>,
    pub no_uppercase: bool,
    pub no_lowercase: bool,
    pub no_digits: bool,
    pub no_symbols: bool,
    pub symbols: Option<String>,
    pub exclude: Option<String>,
    pub no_lookalikes: bool,
    /// `Some(None)` for `--words` without a count.
    pub words: Option<Option<usize>>,
    pub separator: Option<String>,
    pub capitalize: Option<String>,
    pub syllables: bool,
    /// `Some(None)` for `--pin` without a length.
    pub pin: Option<Option<usize>>,
}

impl Options {
    pub fn is_empty(&self) -> bool {
        *self == Options::default()
    }

    /// The options for random characters that were given, by name.
    fn random_flags(&self) -> Vec<&'static str> {
        [
            (self.length.is_some(), "--length"),
            (self.no_uppercase, "--no-uppercase"),
            (self.no_lowercase, "--no-lowercase"),
            (self.no_digits, "--no-digits"),
            (self.no_symbols, "--no-symbols"),
            (self.symbols.is_some(), "--symbols"),
            (self.exclude.is_some(), "--exclude"),
            (self.no_lookalikes, "--no-lookalikes"),
        ]
        .into_iter()
        .filter_map(|(given, flag)| given.then_some(flag))
        .collect()
    }

    fn word_flags(&self) -> Vec<&'static str> {
        [
            (self.separator.is_some(), "--separator"),
            (self.capitalize.is_some(), "--capitalize"),
            (self.syllables, "--syllables"),
        ]
        .into_iter()
        .filter_map(|(given, flag)| given.then_some(flag))
        .collect()
    }

    pub fn recipe(&self) -> Result<Recipe, String> {
        if self.words.is_some() && self.pin.is_some() {
            return Err("--words and --pin cannot be used together".into());
        }
        let kind = if self.words.is_some() {
            Some("--words")
        } else if self.pin.is_some() {
            Some("--pin")
        } else {
            None
        };
        if let (Some(kind), Some(flag)) = (kind, self.random_flags().first()) {
            return Err(format!("{flag} applies to random characters, not {kind}"));
        }
        if self.words.is_none()
            && let Some(flag) = self.word_flags().first()
        {
            return Err(format!("{flag} needs --words"));
        }
        let recipe = if let Some(count) = self.words {
            self.words_recipe(count.unwrap_or(5))?
        } else if let Some(length) = self.pin {
            let length = length.unwrap_or(6);
            in_range("--pin", length, 4, 64)?;
            Recipe::Pin { length }
        } else {
            self.chars_recipe()?
        };
        if let Recipe::Chars(chars) = &recipe
            && generate::acceptance(chars) < MIN_ACCEPTANCE
        {
            return Err("these options leave too few passwords to draw from".into());
        }
        Ok(recipe)
    }

    fn words_recipe(&self, count: usize) -> Result<Recipe, String> {
        in_range("--words", count, 3, 15)?;
        let separator = match self.separator.as_deref().unwrap_or("hyphen") {
            "hyphen" => Separator::Fixed(b'-'),
            "space" => Separator::Fixed(b' '),
            "period" => Separator::Fixed(b'.'),
            "comma" => Separator::Fixed(b','),
            "underscore" => Separator::Fixed(b'_'),
            "digit" => Separator::Digit,
            "digit-or-symbol" => Separator::DigitOrSymbol,
            other => {
                return Err(format!(
                    "unknown separator {other}; use hyphen, space, period, comma, underscore, digit or digit-or-symbol"
                ));
            }
        };
        let capitalize = match self.capitalize.as_deref().unwrap_or("none") {
            "none" => Capitalize::None,
            "first" => Capitalize::First,
            "one" => Capitalize::One,
            other => {
                return Err(format!(
                    "unknown --capitalize value {other}; use none, first or one"
                ));
            }
        };
        Ok(Recipe::Words(Words {
            count,
            list: if self.syllables {
                WordList::Syllables
            } else {
                WordList::Eff
            },
            separator,
            capitalize,
        }))
    }

    fn chars_recipe(&self) -> Result<Recipe, String> {
        let length = self.length.unwrap_or(20);
        in_range("--length", length, 4, 128)?;
        let symbols = match &self.symbols {
            Some(_) if self.no_symbols => {
                return Err("--symbols and --no-symbols cannot be used together".into());
            }
            Some(chars) => {
                if chars.is_empty() || !chars.bytes().all(|b| SYMBOLS.contains(&b)) {
                    return Err("--symbols takes ASCII punctuation only".into());
                }
                chars.as_bytes().to_vec()
            }
            None => SYMBOLS.to_vec(),
        };
        let mut excluded: Vec<u8> = self.exclude.as_deref().unwrap_or("").bytes().collect();
        if self.no_lookalikes {
            excluded.extend_from_slice(LOOKALIKES);
        }
        let sets = [
            (!self.no_uppercase, UPPERCASE, "uppercase letters"),
            (!self.no_lowercase, LOWERCASE, "lowercase letters"),
            (!self.no_digits, DIGITS, "digits"),
            (!self.no_symbols, &symbols[..], "symbols"),
        ];
        let mut cells = Vec::new();
        for (on, chars, what) in sets {
            if !on {
                continue;
            }
            let mut kept = Vec::new();
            for &b in chars {
                if !excluded.contains(&b) && !kept.contains(&b) {
                    kept.push(b);
                }
            }
            if kept.is_empty() {
                return Err(format!(
                    "the excluded characters leave no {what}; leave the set out instead"
                ));
            }
            cells.push(Cell {
                chars: kept,
                satisfies: 1 << cells.len(),
            });
        }
        if cells.is_empty() {
            return Err(
                "at least one of uppercase, lowercase, digits and symbols must remain".into(),
            );
        }
        Ok(Recipe::Chars(Chars {
            requirements: cells.len() as u32,
            cells,
            length,
            max_consecutive: None,
        }))
    }
}

fn in_range(flag: &str, value: usize, min: usize, max: usize) -> Result<(), String> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(format!("{flag} must be from {min} to {max}"))
    }
}

/// Draws a password and returns it as text.
pub fn password(recipe: &Recipe) -> Result<String, String> {
    let drawn =
        generate::password(recipe).map_err(|e| format!("could not read random bytes: {e}"))?;
    String::from_utf8(drawn.bytes[..drawn.len].to_vec())
        .map_err(|_| "the generator made a password that is not ASCII".into())
}

/// The strength line, such as `random characters, 20 from 94, each set
/// present: 130.9 bits`. It depends only on the recipe, so it reveals nothing
/// about the password.
pub fn strength(recipe: &Recipe) -> String {
    let what = match recipe {
        Recipe::Chars(chars) => {
            let alphabet: usize = chars.cells.iter().map(|cell| cell.chars.len()).sum();
            format!(
                "random characters, {} from {alphabet}, each set present",
                chars.length
            )
        }
        Recipe::Words(words) => {
            let separator = match words.separator {
                Separator::Fixed(b'-') => "hyphens",
                Separator::Fixed(b' ') => "spaces",
                Separator::Fixed(b'.') => "periods",
                Separator::Fixed(b',') => "commas",
                Separator::Fixed(b'_') => "underscores",
                Separator::Fixed(_) => "a separator",
                Separator::Digit => "digits",
                Separator::DigitOrSymbol => "digits or symbols",
            };
            let capitalize = match words.capitalize {
                Capitalize::None => "",
                Capitalize::First => ", each capitalized",
                Capitalize::One => ", one capitalized",
            };
            let unit = match words.list {
                WordList::Eff => "words",
                WordList::Syllables => "syllables",
            };
            format!(
                "memorable, {} {unit} from {} with {separator}{capitalize}",
                words.count,
                thousands(generate::word_count(words.list))
            )
        }
        Recipe::Pin { length } => format!("PIN, {length} digits"),
    };
    let bits = generate::entropy(recipe);
    let weak = if bits < WEAK_BITS {
        " -- weak for a password you cannot rate-limit"
    } else {
        ""
    };
    format!("{what}: {bits:.1} bits{weak}")
}

fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strength_of(options: Options) -> String {
        strength(&options.recipe().unwrap())
    }

    #[test]
    fn describes_the_plans_examples() {
        assert_eq!(
            strength_of(Options::default()),
            "random characters, 20 from 94, each set present: 130.9 bits"
        );
        assert_eq!(
            strength_of(Options {
                words: Some(Some(5)),
                ..Options::default()
            }),
            "memorable, 5 words from 7,776 with hyphens: 64.6 bits"
        );
        assert_eq!(
            strength_of(Options {
                words: Some(None),
                separator: Some("digit".into()),
                capitalize: Some("one".into()),
                ..Options::default()
            }),
            "memorable, 5 words from 7,776 with digits, one capitalized: 80.2 bits"
        );
        assert_eq!(
            strength_of(Options {
                pin: Some(None),
                ..Options::default()
            }),
            "PIN, 6 digits: 19.9 bits -- weak for a password you cannot rate-limit"
        );
        assert_eq!(
            strength_of(Options {
                words: Some(Some(6)),
                syllables: true,
                ..Options::default()
            }),
            "memorable, 6 syllables from 2,000 with hyphens: 65.8 bits"
        );
    }

    #[test]
    fn narrows_the_character_sets() {
        let recipe = Options {
            no_symbols: true,
            exclude: Some("xyz".into()),
            no_lookalikes: true,
            length: Some(16),
            ..Options::default()
        }
        .recipe()
        .unwrap();
        let Recipe::Chars(chars) = recipe else {
            panic!("{recipe:?}")
        };
        let all: Vec<u8> = chars.cells.iter().flat_map(|c| c.chars.clone()).collect();
        // 62 letters and digits, minus x, y and z, minus 0, O, o, 1, l and I.
        assert_eq!(all.len(), 62 - 3 - 6);
        assert!(!all.iter().any(|b| b"xyz0Oo1lI|".contains(b)));
        assert_eq!(chars.cells.len(), 3);
        assert_eq!(chars.length, 16);
    }

    #[test]
    fn rejects_options_that_do_not_fit() {
        let err = |options: Options| options.recipe().unwrap_err();
        assert_eq!(
            err(Options {
                length: Some(3),
                ..Options::default()
            }),
            "--length must be from 4 to 128"
        );
        assert_eq!(
            err(Options {
                separator: Some("space".into()),
                ..Options::default()
            }),
            "--separator needs --words"
        );
        assert_eq!(
            err(Options {
                syllables: true,
                ..Options::default()
            }),
            "--syllables needs --words"
        );
        assert_eq!(
            err(Options {
                words: Some(None),
                length: Some(10),
                ..Options::default()
            }),
            "--length applies to random characters, not --words"
        );
        assert_eq!(
            err(Options {
                words: Some(None),
                pin: Some(None),
                ..Options::default()
            }),
            "--words and --pin cannot be used together"
        );
        assert_eq!(
            err(Options {
                no_uppercase: true,
                no_lowercase: true,
                no_digits: true,
                no_symbols: true,
                ..Options::default()
            }),
            "at least one of uppercase, lowercase, digits and symbols must remain"
        );
        assert_eq!(
            err(Options {
                symbols: Some("!a".into()),
                ..Options::default()
            }),
            "--symbols takes ASCII punctuation only"
        );
        assert_eq!(
            err(Options {
                no_digits: false,
                exclude: Some("0123456789".into()),
                ..Options::default()
            }),
            "the excluded characters leave no digits; leave the set out instead"
        );
        assert_eq!(
            err(Options {
                words: Some(Some(2)),
                ..Options::default()
            }),
            "--words must be from 3 to 15"
        );
        assert_eq!(
            err(Options {
                pin: Some(Some(3)),
                ..Options::default()
            }),
            "--pin must be from 4 to 64"
        );
    }

    #[test]
    fn draws_text_of_the_recipes_length() {
        let pin = password(&Recipe::Pin { length: 8 }).unwrap();
        assert_eq!(pin.len(), 8);
        assert!(pin.bytes().all(|b| b.is_ascii_digit()));
    }
}
