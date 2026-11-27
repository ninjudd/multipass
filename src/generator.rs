//! The command line's password options: turning them into a
//! `crypto::generate::Recipe`, describing the recipe's strength, and turning
//! a drawn password into text.

use crate::crypto::generate::{
    self, Capitalize, Cell, Chars, DIGITS, LOWERCASE, Recipe, SYMBOLS, Separator, UPPERCASE,
    WordList, Words,
};
use crate::generate_rules;

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
    pub rules: Option<String>,
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
            (self.rules.is_some(), "--rules"),
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
            // 5 syllables are only 54.8 bits, so the default for syllables is
            // the 6 that clear 64 bits, as 5 words do.
            let default = if self.syllables { 6 } else { 5 };
            self.words_recipe(count.unwrap_or(default))?
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

    /// The characters `--exclude` and `--no-lookalikes` leave out.
    fn excluded(&self) -> Vec<u8> {
        let mut excluded: Vec<u8> = self.exclude.as_deref().unwrap_or("").bytes().collect();
        if self.no_lookalikes {
            excluded.extend_from_slice(LOOKALIKES);
        }
        excluded
    }

    /// Random characters that follow a site's `--rules`. The rules replace
    /// the set options, and `--exclude` and `--no-lookalikes` narrow them.
    fn rules_recipe(&self, text: &str) -> Result<Recipe, String> {
        let replaced = [
            (self.no_uppercase, "--no-uppercase"),
            (self.no_lowercase, "--no-lowercase"),
            (self.no_digits, "--no-digits"),
            (self.no_symbols, "--no-symbols"),
            (self.symbols.is_some(), "--symbols"),
        ];
        if let Some((_, flag)) = replaced.iter().find(|(given, _)| *given) {
            return Err(format!(
                "--rules replaces {flag}; say it in the rules instead"
            ));
        }
        let rules = generate_rules::parse(text)?;
        // The strength count tracks every subset of the requirements met so
        // far, so it grows as 2 to the number of required rules.
        if rules.required.len() > 8 {
            return Err("multipass follows at most 8 required rules".into());
        }
        let length = match self.length {
            Some(length) => {
                in_range("--length", length, 4, 128)?;
                length
            }
            None => 20,
        };
        let min = rules.min_length.unwrap_or(0).max(4);
        let max = rules.max_length.unwrap_or(128).min(128);
        if min > max {
            return Err(format!(
                "the rules allow no length multipass can make: from {} to {}, and multipass makes 4 to 128",
                rules.min_length.unwrap_or(0),
                rules
                    .max_length
                    .map_or("any".to_string(), |m| m.to_string())
            ));
        }
        let length = length.clamp(min, max);
        // A space at the start or end of a password is easy to lose when it
        // is pasted, so it is never drawn even where a site allows it.
        let mut excluded = self.excluded();
        excluded.push(b' ');
        // Group the allowed characters by which requirements each meets, so
        // that the cells are disjoint even when required classes overlap.
        let mut cells: Vec<Cell> = Vec::new();
        for &b in &rules.allowed {
            if excluded.contains(&b) {
                continue;
            }
            let satisfies = rules
                .required
                .iter()
                .enumerate()
                .filter(|(_, set)| set.contains(&b))
                .fold(0u32, |bits, (i, _)| bits | 1 << i);
            match cells.iter_mut().find(|cell| cell.satisfies == satisfies) {
                Some(cell) => cell.chars.push(b),
                None => cells.push(Cell {
                    chars: vec![b],
                    satisfies,
                }),
            }
        }
        for (i, _) in rules.required.iter().enumerate() {
            if !cells.iter().any(|cell| cell.satisfies & 1 << i != 0) {
                return Err(format!(
                    "required rule {} has no character left to draw",
                    i + 1
                ));
            }
        }
        if cells.is_empty() {
            return Err("the rules leave no character to draw".into());
        }
        Ok(Recipe::Chars(Chars {
            cells,
            requirements: rules.required.len() as u32,
            length,
            max_consecutive: rules.max_consecutive,
        }))
    }

    fn chars_recipe(&self) -> Result<Recipe, String> {
        if let Some(text) = &self.rules {
            return self.rules_recipe(text);
        }
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
        let excluded = self.excluded();
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
            // The set options make one requirement per cell; anything else
            // came from --rules.
            let one_per_cell = chars.requirements as usize == chars.cells.len()
                && chars
                    .cells
                    .iter()
                    .enumerate()
                    .all(|(i, cell)| cell.satisfies == 1 << i);
            let how = if chars.max_consecutive.is_none() && one_per_cell {
                ", each set present"
            } else if chars.max_consecutive.is_none() && chars.requirements == 0 {
                ""
            } else {
                ", with rules"
            };
            format!("random characters, {} from {alphabet}{how}", chars.length)
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
        assert_eq!(
            strength_of(Options {
                words: Some(None),
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

    fn rules(text: &str) -> Options {
        Options {
            rules: Some(text.into()),
            ..Options::default()
        }
    }

    #[test]
    fn follows_password_rules() {
        assert_eq!(
            strength_of(rules(
                "minlength: 8; maxlength: 16; required: lower; required: upper; required: digit; allowed: [-!#$]; max-consecutive: 2;"
            )),
            "random characters, 16 from 66, with rules: 96.6 bits"
        );
        // With no class named, every printable character but the space.
        assert_eq!(
            strength_of(rules("minlength: 24")),
            "random characters, 24 from 94: 157.3 bits"
        );
        // --length is kept when it fits the bounds, and moved to the nearer
        // bound when it does not.
        let length = |text: &str, length: Option<usize>| match (Options {
            length,
            ..rules(text)
        })
        .recipe()
        .unwrap()
        {
            Recipe::Chars(chars) => chars.length,
            other => panic!("{other:?}"),
        };
        assert_eq!(length("minlength: 8; maxlength: 16", Some(12)), 12);
        assert_eq!(length("minlength: 8; maxlength: 16", Some(30)), 16);
        assert_eq!(length("minlength: 32", None), 32);
    }

    #[test]
    fn splits_overlapping_requirements_into_disjoint_cells() {
        // `required: upper; required: [A-]` overlaps on A: one requirement
        // is met by any capital, the other by A or -, and the cells must not
        // count A twice.
        let Recipe::Chars(chars) = rules("required: upper; required: [-A]").recipe().unwrap()
        else {
            panic!()
        };
        let all: Vec<u8> = chars.cells.iter().flat_map(|c| c.chars.clone()).collect();
        assert_eq!(all.len(), 27);
        let a = chars
            .cells
            .iter()
            .find(|c| c.chars.contains(&b'A'))
            .unwrap();
        assert_eq!((a.chars.clone(), a.satisfies), (b"A".to_vec(), 0b11));
    }

    #[test]
    fn narrows_rules_with_exclude_but_not_with_set_options() {
        let Recipe::Chars(chars) = Options {
            exclude: Some("$".into()),
            no_lookalikes: true,
            ..rules("required: digit; allowed: [$%]")
        }
        .recipe()
        .unwrap() else {
            panic!()
        };
        let all: Vec<u8> = chars.cells.iter().flat_map(|c| c.chars.clone()).collect();
        assert_eq!(all, b"%23456789".to_vec());
        assert_eq!(
            Options {
                no_digits: true,
                ..rules("required: digit")
            }
            .recipe()
            .unwrap_err(),
            "--rules replaces --no-digits; say it in the rules instead"
        );
        assert_eq!(
            Options {
                words: Some(None),
                ..rules("required: digit")
            }
            .recipe()
            .unwrap_err(),
            "--rules applies to random characters, not --words"
        );
        assert_eq!(
            Options {
                exclude: Some("0123456789".into()),
                ..rules("required: digit; allowed: lower")
            }
            .recipe()
            .unwrap_err(),
            "required rule 1 has no character left to draw"
        );
        assert_eq!(
            rules("maxlength: 3").recipe().unwrap_err(),
            "the rules allow no length multipass can make: from 0 to 3, and multipass makes 4 to 128"
        );
        // Four required classes in four characters is possible but narrow;
        // five in four is not.
        assert!(
            rules(
                "maxlength: 4; required: upper; required: lower; required: digit; required: special"
            )
            .recipe()
            .is_ok()
        );
        assert_eq!(
            rules("maxlength: 4; required: upper; required: lower; required: digit; required: [!]; required: [?]")
                .recipe()
                .unwrap_err(),
            "these options leave too few passwords to draw from"
        );
    }

    #[test]
    fn draws_text_of_the_recipes_length() {
        let pin = password(&Recipe::Pin { length: 8 }).unwrap();
        assert_eq!(pin.len(), 8);
        assert!(pin.bytes().all(|b| b.is_ascii_digit()));
    }
}
