//! Parsing a site's password rules, written in the language Apple defined for
//! the `passwordrules` HTML attribute, such as
//! `minlength: 8; required: digit; allowed: lower, [-!#$];`.
//!
//! The rules are public text, so this module branches on every byte freely.
//! It follows Apple's parser in `password-manager-resources`
//! (`tools/PasswordRulesParser/PasswordRulesParser.js`) except where that
//! parser skips input it cannot read: here, anything it would skip is an
//! error, because a silently dropped character would change what the
//! password may hold.

use crate::crypto::generate::{DIGITS, LOWERCASE, SYMBOLS, UPPERCASE};

/// The rules a site states, combined as Apple's parser combines them.
#[derive(Debug, Default, PartialEq)]
pub struct Rules {
    /// One set per `required` rule: the password needs a character from
    /// each.
    pub required: Vec<Vec<u8>>,
    /// Every character the password may hold, in ASCII order.
    pub allowed: Vec<u8>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub max_consecutive: Option<usize>,
}

pub fn parse(text: &str) -> Result<Rules, String> {
    if !text.is_ascii() {
        return Err("password rules must be ASCII".into());
    }
    let mut rules = Rules::default();
    let mut allowed = [false; 128];
    let mut any_class = false;
    for statement in statements(text)? {
        let statement = statement.trim_matches(is_space);
        if statement.is_empty() {
            continue;
        }
        let (name, value) = statement
            .split_once(':')
            .ok_or_else(|| format!("password rule {statement:?} needs a colon after its name"))?;
        let value = value.trim_matches(is_space);
        // An empty value is ignored, as Apple's parser ignores it.
        if value.is_empty() {
            continue;
        }
        match name.trim_matches(is_space) {
            "required" => {
                let set = classes(value)?;
                for &b in &set {
                    allowed[b as usize] = true;
                }
                rules.required.push(set);
                any_class = true;
            }
            "allowed" => {
                for b in classes(value)? {
                    allowed[b as usize] = true;
                }
                any_class = true;
            }
            "minlength" => {
                let n = integer(name, value)?;
                rules.min_length = Some(rules.min_length.map_or(n, |m| m.max(n)));
            }
            "maxlength" => {
                let n = integer(name, value)?;
                rules.max_length = Some(rules.max_length.map_or(n, |m| m.min(n)));
            }
            "max-consecutive" => {
                let n = integer(name, value)?;
                if n == 0 {
                    return Err("max-consecutive must be at least 1".into());
                }
                rules.max_consecutive = Some(rules.max_consecutive.map_or(n, |m| m.min(n)));
            }
            "max-repeating" | "max-sequential" => {
                return Err(format!(
                    "multipass does not support the {name} password rule"
                ));
            }
            other => return Err(format!("unknown password rule {other}")),
        }
    }
    if !any_class {
        for b in printable() {
            allowed[b as usize] = true;
        }
    }
    rules.allowed = (0..128u8).filter(|&b| allowed[b as usize]).collect();
    Ok(rules)
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c')
}

/// Splits the text at each `;` that is outside a custom class.
fn statements(text: &str) -> Result<Vec<&str>, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => i = class_end(bytes, i)?,
            b';' => {
                out.push(&text[start..i]);
                start = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    out.push(&text[start..]);
    Ok(out)
}

/// The index just past the custom class that opens at `open`. The class ends
/// at the first `]` followed by the end of the text, a space, a comma, or a
/// semicolon, so a literal `]` is written as `]]` at the end of a class.
fn class_end(bytes: &[u8], open: usize) -> Result<usize, String> {
    let mut i = open + 1;
    while i < bytes.len() {
        let ends = bytes[i] == b']'
            && bytes
                .get(i + 1)
                .is_none_or(|&next| is_space(next as char) || next == b',' || next == b';');
        if ends {
            return Ok(i + 1);
        }
        i += 1;
    }
    Err("a character class in the password rules has no closing ]".into())
}

/// The characters a `required` or `allowed` value names, in ASCII order.
fn classes(value: &str) -> Result<Vec<u8>, String> {
    let mut set = [false; 128];
    let bytes = value.as_bytes();
    let mut i = 0;
    loop {
        while i < bytes.len() && is_space(bytes[i] as char) {
            i += 1;
        }
        if i >= bytes.len() {
            return Err(format!("password rule value {value:?} ends with a comma"));
        }
        if bytes[i] == b'[' {
            let end = class_end(bytes, i)?;
            let inner = &bytes[i + 1..end - 1];
            for (k, &b) in inner.iter().enumerate() {
                if !(b' '..=b'~').contains(&b) {
                    return Err("a character class may hold only printable ASCII".into());
                }
                if b == b'-' && k > 0 {
                    return Err(format!(
                        "a - in the class [{}] must come first",
                        String::from_utf8_lossy(inner)
                    ));
                }
                set[b as usize] = true;
            }
            i = end;
        } else {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'-') {
                i += 1;
            }
            let name = value[start..i].to_ascii_lowercase();
            let chars: Vec<u8> = match name.as_str() {
                "upper" => UPPERCASE.to_vec(),
                "lower" => LOWERCASE.to_vec(),
                "digit" => DIGITS.to_vec(),
                "special" => [b" ", SYMBOLS].concat(),
                "ascii-printable" => printable().collect(),
                "unicode" => {
                    return Err(
                        "multipass draws only ASCII, so it cannot follow the unicode class".into(),
                    );
                }
                "" => {
                    return Err(format!(
                        "password rule value {value:?} has something other than a class at {:?}",
                        &value[start..]
                    ));
                }
                other => return Err(format!("unknown character class {other}")),
            };
            for b in chars {
                set[b as usize] = true;
            }
        }
        while i < bytes.len() && is_space(bytes[i] as char) {
            i += 1;
        }
        match bytes.get(i) {
            None => break,
            Some(b',') => i += 1,
            Some(_) => {
                return Err(format!(
                    "password rule value {value:?} needs a comma between classes"
                ));
            }
        }
    }
    Ok((0..128u8).filter(|&b| set[b as usize]).collect())
}

/// Every printable ASCII character, from the space to `~`.
fn printable() -> impl Iterator<Item = u8> {
    b' '..=b'~'
}

fn integer(name: &str, value: &str) -> Result<usize, String> {
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{name} needs a whole number, not {value}"));
    }
    value
        .parse()
        .map_err(|_| format!("{name} is too large: {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_plans_example() {
        let rules = parse(
            "minlength: 8; maxlength: 16; required: lower; required: upper; required: digit; allowed: [-!#$]; max-consecutive: 2;",
        )
        .unwrap();
        assert_eq!(
            rules.required,
            vec![LOWERCASE.to_vec(), UPPERCASE.to_vec(), DIGITS.to_vec()]
        );
        assert_eq!(rules.allowed.len(), 66);
        assert!(b"-!#$".iter().all(|b| rules.allowed.contains(b)));
        assert_eq!(rules.min_length, Some(8));
        assert_eq!(rules.max_length, Some(16));
        assert_eq!(rules.max_consecutive, Some(2));
    }

    #[test]
    fn parses_apples_examples() {
        // Rules from Apple's documentation and its quirks list.
        let rules = parse("required: upper; required: digit; allowed: [-().&@?'#,/\"+];").unwrap();
        assert_eq!(rules.required.len(), 2);
        assert_eq!(rules.allowed.len(), 26 + 10 + 13);
        let rules = parse(
            "minlength: 6; maxlength: 15; required: lower, upper; required: digit; allowed: [-_]",
        )
        .unwrap();
        // One requirement satisfied by either case.
        assert_eq!(rules.required[0], [UPPERCASE, LOWERCASE].concat());
        assert!(rules.allowed.contains(&b'_'));
    }

    #[test]
    fn defaults_to_every_printable_character() {
        let rules = parse("minlength: 12;").unwrap();
        assert_eq!(rules.allowed, (b' '..=b'~').collect::<Vec<u8>>());
        assert!(rules.required.is_empty());
    }

    #[test]
    fn combines_repeated_rules_as_apple_does() {
        let rules =
            parse("minlength: 8; minlength: 10; maxlength: 20; maxlength: 16; max-consecutive: 3; max-consecutive: 2").unwrap();
        assert_eq!(rules.min_length, Some(10));
        assert_eq!(rules.max_length, Some(16));
        assert_eq!(rules.max_consecutive, Some(2));
    }

    #[test]
    fn reads_custom_classes() {
        // A semicolon inside a class does not end the rule, and a literal ]
        // is written ]] at the end.
        let rules = parse("allowed: [;a]; required: [-]]").unwrap();
        assert_eq!(rules.allowed, b"-;]a".to_vec());
        assert_eq!(rules.required, vec![b"-]".to_vec()]);
        // Identifiers ignore case, and an empty value is ignored.
        assert_eq!(
            parse("required: DIGIT; allowed: ;").unwrap().allowed,
            DIGITS.to_vec()
        );
    }

    #[test]
    fn refuses_what_apple_would_skip() {
        let err = |text: &str| parse(text).unwrap_err();
        assert_eq!(
            err("required: unicode;"),
            "multipass draws only ASCII, so it cannot follow the unicode class"
        );
        assert_eq!(err("must-have: digit"), "unknown password rule must-have");
        assert_eq!(err("required: digits"), "unknown character class digits");
        assert_eq!(
            err("allowed: [a-z]"),
            "a - in the class [a-z] must come first"
        );
        assert_eq!(
            err("minlength: eight"),
            "minlength needs a whole number, not eight"
        );
        assert_eq!(
            err("allowed: [abc"),
            "a character class in the password rules has no closing ]"
        );
        assert_eq!(
            err("required digit"),
            "password rule \"required digit\" needs a colon after its name"
        );
        assert_eq!(
            err("max-repeating: 2"),
            "multipass does not support the max-repeating password rule"
        );
        assert_eq!(
            err("max-consecutive: 0"),
            "max-consecutive must be at least 1"
        );
        assert_eq!(
            err("required: upper lower"),
            "password rule value \"upper lower\" needs a comma between classes"
        );
    }
}
