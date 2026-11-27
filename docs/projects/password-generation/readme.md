---
status: ready
priority: now
---

# Password generation

multipass makes new passwords itself, as random characters, memorable words, or a PIN, with every option 1Password documents for its generator, and stores one in an entry without ever showing it. It leaves out the three-letter word list that 1Password's SDK names, because no 1Password page describes what that list produces, so multipass could not match it (§ 7).

## 1. Problem

multipass stores the secrets you give it, but cannot make one. `multipass add <name>` reads the secret from a hidden prompt or from stdin, so to set a new password you first make it somewhere else: in 1Password's generator, in a shell one-liner, or in your head. Each of those has a cost. A generator in another app puts the new password in that app's history and on its servers, which is what multipass exists to avoid. A shell one-liner such as `openssl rand -base64 15` is easy to get wrong, for example by picking characters with `% 94`, which favors some characters over others, and it prints the password on the terminal. A password you make up has far less randomness than it seems.

Moving a secret out of 1Password means changing it, because 1Password keeps item history, so making a new password is the first step of every move into multipass.

## 2. Solution

A new command, `multipass generate`, prints one new password and stores nothing. A new option, `multipass add <name> --generate`, makes the password and stores it in the entry without printing it, and with `--clip` it also copies it to the clipboard so you can paste it into the website's form. Both take the same options. There are three kinds: random characters, memorable words drawn from the EFF's large word list, and a PIN, with the settings that 1Password's generator has for each (§ 7) and a few that site password rules need. Every run prints the password's strength, in bits of entropy, on stderr. The randomness comes from `crypto::random::fill`, which reads `/dev/urandom`. The code that turns random bytes into a password lives in `src/crypto/generate.rs`, picks every character and word without bias, and follows the repository's constant-time rule: no branch or memory read depends on which character or word it picked.

```console
$ multipass generate
k7#Rv2!mQe9_Tz4@pLw8
multipass: random characters, 20 from 94, each set present: 130.9 bits

$ multipass generate --words 5
oxidize-tattered-flier-rebound-anyone
multipass: memorable, 5 words from 7,776 with hyphens: 64.6 bits

$ multipass generate --pin 6
480213
multipass: PIN, 6 digits: 19.9 bits -- weak for a password you cannot rate-limit

$ multipass add github.com --generate --clip
multipass: random characters, 20 from 94, each set present: 130.9 bits
multipass: copied the secret for github.com; the clipboard clears in 30 seconds
```

### 2.1 How a password is made

1. `parse` reads the kind and its options (§ 2.2), and rejects a combination that cannot make a password, such as `--length 3` with four required character sets, naming the options.
2. `main.rs` builds a `Recipe`, the kind and its settings. A recipe holds no secret. Per-site rules from `--rules` (§ 2.3) become part of the recipe at this step.
3. `crypto::generate::entropy(&recipe)` computes the strength, which depends only on the recipe, so printing it reveals nothing about the password.
4. `crypto::generate::password(&recipe)` draws the password:
   1. It draws each position's index below `n`, the size of that position's alphabet or word list, by rejection sampling. It reads two random bytes from `crypto::random::fill`, keeps the value when it is below the largest multiple of `n` that fits in 16 bits, and otherwise draws again. The kept value modulo `n` is uniform.
   2. It reads the character or word at that index by scanning the whole alphabet or word list and keeping the match with a mask, so the memory it reads does not depend on the index. A word is copied into a fixed buffer as wide as the longest word, with its length.
   3. When the recipe requires a character set, such as "at least one digit", or limits repeats with `max-consecutive`, it draws the whole password again until the password meets every rule. That keeps the result uniform over the passwords that satisfy the rules.
   4. It returns a fixed-capacity buffer and the password's length.
5. `main.rs` turns the buffer into a `String` and hands it on. `generate` prints it, or copies it with `--clip`. `add --generate` stores it as the entry's `secret`, and copies it too with `--clip`. Converting to text outside `src/crypto` follows the repository's rule for secrets kept as text, as the store's own parsing and escaping do.
6. It prints the strength line from step 3 on stderr, so a script that reads stdout gets only the password.

The loops in steps 4.1 and 4.3 decide whether to draw again from a value that is then thrown away. Their timing reveals how many draws were discarded, which says nothing about the draw that was kept. AGENTS.md names this as the second exception to the constant-time rule, beside scrypt's lookups.

### 2.2 Options

| Option | Kind | Default | Effect |
| --- | --- | --- | --- |
| `--length <n>` | random | `20` | Characters, from 4 to 128. With `--pin`, use `--pin <n>` instead. |
| `--no-uppercase`, `--no-lowercase`, `--no-digits`, `--no-symbols` | random | all four sets on | Leaves a set out. At least one set must remain. |
| `--symbols <chars>` | random | the 32 ASCII punctuation characters | The symbols to draw from, for a site that allows only some. |
| `--exclude <chars>` | random | none | Characters never to use, from any set. |
| `--no-lookalikes` | random | off | Leaves out characters that are easy to misread: `0 O o 1 l I \|`. |
| `--rules <rules>` | random | none | A site's password rules, as § 2.3 describes. |
| `--words <n>` | memorable | `5`, or `6` with `--syllables` | Words, from 3 to 15, the range a guide to 1Password gives (§ 7). The default clears 64 bits either way: 5 words are 64.6 bits, but 5 syllables would be only 54.8, so 6 syllables, 65.8 bits, is the default with `--syllables`. |
| `--separator <sep>` | memorable | `hyphen` | What goes between words: `hyphen`, `space`, `period`, `comma`, `underscore`, `digit`, or `digit-or-symbol`. The last two draw a new random character for each gap. |
| `--capitalize <which>` | memorable | `none` | `none`, `first` (the first letter of every word), or `one` (the first letter of one randomly chosen word). |
| `--syllables` | memorable | off | Uses short pronounceable syllables instead of full words (§ 2.4). |
| `--pin <n>` | PIN | `6` when given alone | Digits, from 4 to 64. |

With no kind option, `generate` and `add --generate` make random characters. An option for another kind is an error, such as `--separator` with `--length`. 1Password's random type has three toggles, letters, numbers, and symbols. Splitting letters into uppercase and lowercase gives sites that require both a way to say so, and each set that is on must appear at least once, as sites that list required characters expect. The strength line counts only the passwords that meet those requirements.

### 2.3 Per-site rules

Many sites limit what a password may hold. `--rules` takes those limits in the password rules language that Apple defined for its `passwordrules` HTML attribute, which Apple's open `password-manager-resources` repository uses to record the rules of hundreds of real sites:

```console
$ multipass add bank.example --generate --rules 'minlength: 8; maxlength: 16; required: lower; required: upper; required: digit; allowed: [-!#$]; max-consecutive: 2;'
multipass: random characters, 16 from 66, with rules: 96.6 bits
```

| Property | Effect |
| --- | --- |
| `required: <classes>` | At least one character from those classes. Repeat it for each class that must appear. |
| `allowed: <classes>` | Characters that may appear, beyond those required. |
| `minlength`, `maxlength` | The length is `--length` when it fits, and otherwise the nearest bound. |
| `max-consecutive: <n>` | No character repeats more than `n` times in a row. |

The classes are `upper`, `lower`, `digit`, `special` (ASCII punctuation), `ascii-printable`, and a custom set in brackets such as `[-!#$]`. `unicode` is refused, because multipass draws only ASCII. The rules replace the character-set options, so `--rules` with `--no-digits` or `--symbols` is an error. `--exclude` and `--no-lookalikes` still apply on top. Parsing the rules happens in `src/generate_rules.rs`, outside `src/crypto`, because the rules are public text and parsing them branches on every byte.

### 2.4 Word lists

| List | Entries | Bits each | Source |
| --- | --- | --- | --- |
| Full words | 7,776 | 12.9 | The EFF's large word list, `eff_large_wordlist.txt`, under CC BY 3.0 US |
| Syllables | 2,000 | 11.0 | Generated in code: a consonant, a vowel, and a consonant, from 20 consonants (all but `q`) and 5 vowels |

The word list ships as `src/crypto/wordlist/eff_large.txt`, compiled in with `include_str!`, without the dice numbers that start each line in the EFF's file. A test pins its SHA-256 and checks that it has 7,776 distinct words of lowercase ASCII letters. The README credits the EFF and names the license, as CC BY requires. 1Password's own word lists are not published, so a memorable password from multipass looks like one from 1Password but comes from a different list.

### 2.5 Strength

The strength line prints `log2` of the number of passwords the recipe can produce, to one decimal place:

| Recipe | Strength |
| --- | --- |
| Random characters, `n` long, from an alphabet of `a`, no requirements | `n × log2(a)` |
| The same, where sets must each appear | `log2` of the count from inclusion and exclusion over the sets |
| With `max-consecutive` | `log2` of the count from a small dynamic program over the run length |
| Memorable, `w` words | `w × log2(list)`, plus `(w − 1) × log2(10)` for `digit` separators or `(w − 1) × log2(10 + symbols)` for `digit-or-symbol`, plus `log2(w)` for `--capitalize one` |
| PIN, `n` digits | `n × log2(10)` |

The counts are exact, computed with 256-bit integers in `src/crypto/generate.rs`, because 128 characters from 94 is more than `u128` holds. When the strength is below 64 bits, the line ends with `-- weak for a password you cannot rate-limit`, which a 6-digit PIN always gets, and which is still right for a PIN that a bank's servers rate-limit.

### 2.6 Changes by file

| File | Change |
| --- | --- |
| `src/crypto/generate.rs` | New. `Recipe`, `password(&Recipe) -> Generated`, `entropy(&Recipe) -> f64`, the uniform index draw, the masked table read, and the exact counts. `Generated` holds a fixed buffer and a length. |
| `src/crypto/wordlist/eff_large.txt` | New. The EFF's large word list, one word per line. |
| `src/crypto/mod.rs` | Declares `generate`. |
| `src/generate_rules.rs` | New. Parses `--rules` into the recipe's sets, length bounds, and run limit. |
| `src/main.rs` | The `generate` command and `add --generate`, their options in `parse`, `--clip` on `add` when it comes with `--generate`, and `USAGE`. |
| `README.md` | A section on making passwords, the strength line, and the EFF credit. |
| `AGENTS.md` | Names rejection sampling as the second exception to the constant-time rule, and lists the word list's pinned digest with the test vectors. |

`add <name> --generate --force` on an entry that exists replaces its secret as `add --force` does. Once the mergeable store's password history lands, the old secret moves into history, so `get <name> --previous 1` gets it back. That needs nothing from this plan.

## 3. Why this design

- **One module draws every password.** Random characters, words, syllables, separators, and the one capitalized word are all "pick one of `n`", so one index draw and one masked read serve them all. That puts the only code where bias or a timing leak could hide in one file, under the vectors in § 4.
- **Rejection sampling, not `% n`.** Taking a random byte modulo 94 makes each of the first 68 characters 3 chances in 256 and each of the last 26 only 2, so the first 68 come up half again as often. Rejection costs on average under one extra draw.
- **Masked reads, even for a word list.** The rule exists because a lookup indexed by a secret can leak through the cache. Scanning 7,776 words of at most a few bytes each costs microseconds, so there is no reason to exempt it.
- **Draw again for requirements, rather than placing a required character.** Forcing a digit into a random position makes some passwords more likely than others, and the strength figure would be wrong. Drawing again keeps every valid password equally likely, and the count in § 2.5 is exact.
- **The password never prints in `add --generate`.** A password that appears on the terminal reaches the scrollback and any screen recording. `--clip` gives you the copy you need for the website's form.
- **Strength on stderr.** It depends only on the options, so it reveals nothing, and it leaves stdout holding only the password, for scripts.
- **Apple's rules language for per-site rules.** It is an open, written-down format, and Apple's repository already holds the rules of many sites, so you can paste a site's line rather than translating it into flags.
- **Rejected: a dependency such as `rand`.** The repository has none, and drawing below `n` is a few lines.
- **Rejected: 1Password's "Smart Password".** 1Password guesses a site's rules from the page it is on. multipass sees no page, and `--rules` is the explicit form of the same thing.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| `multipass generate` | 20 characters on stdout, each set present, and `130.9 bits` on stderr |
| `multipass generate --words 5 --separator digit --capitalize one` | Five EFF words, a digit between each pair, one capitalized, and `80.2 bits` |
| `multipass generate --pin 6` | Six digits and `19.9 bits` ending in the weak warning |
| `multipass add x --generate`, then `multipass get x` | `add` prints no password on stdout or stderr. `get` prints a 20-character password. |
| `multipass add x --generate --clip` in a test, against the private pasteboard | The pasteboard holds the stored secret |
| `multipass generate --length 3` | Fails, naming `--length` and the four required sets |
| `multipass generate --separator space` | Fails: `--separator` needs `--words` |
| `multipass generate --rules 'required: unicode;'` | Fails, naming `unicode` |

Tests that must fail before the change and pass after it:

- **Uniform draws.** Draw 1,000,000 indexes below 94 with a fixed byte stream fed in place of `/dev/urandom`, and check that no count is off by more than five standard deviations. Catches a draw of one byte modulo `n`, which puts the first 68 counts about 10 percent high. The bias of a 16-bit value modulo `n` is too small for this test to see, which is why the next test exists.
- **Rejection bounds.** For `n` of 94, 7,776, and 10, a 16-bit value at the largest kept multiple minus one is kept, and the next is drawn again. Catches an off-by-one that keeps one biased value.
- **Exact counts.** The count of 4-character passwords over `{a, 1}` with both sets required is 14, and over 94 characters with all four sets required matches a brute-force count for length 4. Catches an inclusion and exclusion with a wrong sign, which would misstate strength.
- **`max-consecutive`.** The count of 3-character passwords over two characters with at most 2 in a row is 6, and 10,000 drawn passwords never break the limit. Catches a rule checked on the wrong run.
- **The word list.** The file's SHA-256 matches the pinned digest, and it has 7,776 distinct lowercase words. Catches a truncated or edited list, which would lower the strength the line claims.
- **The masked read** returns the same word as plain indexing for every index of the list. Catches a mask that picks the wrong entry.
- **Rules parsing.** Apple's examples parse to the expected sets and bounds, `unicode` is refused, and unknown properties are refused with their name. Catches a rule that is silently ignored.

## 5. Cost

A random password takes a few dozen two-byte reads and a scan of a 94-byte alphabet per character. A memorable one scans 7,776 words per word, about 60 kilobytes of reads, five times. Requirements add a redraw for about 1 in 9 random passwords at the default settings. All of it is under a millisecond, against about a third of a second of scrypt when `add` opens the store, and `generate` opens no store, so it never prompts for the passphrase.

## 6. Open questions

The owner has decided all three.

1. **The default with no options.** Decided: random characters, 20 long, from all four sets. Memorable words stay one option away, with `--words`.
2. **Syllables.** Decided: include `--syllables`, so the plan covers 1Password's "Use full words" switch when it is off. With no count it makes 6 syllables, as § 2.2 describes.
3. **Per-site rules.** Decided: both the simple options and `--rules`, as § 2.3 describes.

## 7. Background

1Password's generator, as its pages describe it in November 2026:

- **Types.** `https://1password.com/password-generator` offers Random, Memorable, and PIN. 1Password's SDK names the same three recipes (`https://www.1password.dev/sdks/manage-items`).
- **Random.** The web page has toggles for characters, numbers, and symbols. The SDK's random recipe has `length`, `includeDigits`, and `includeSymbols`. The CLI's `op item create --generate-password` takes a length from 1 to 64 and defaults to 32 characters of letters, digits, and the symbols `!@.-_*`.
- **Memorable.** The web page offers "Capitalize the first letter" and "Use full words". The SDK's recipe has `wordCount`, `capitalize` ("Whether to capitalize one section of the generated password"), `separatorType` with the values digits, digits and symbols, spaces, hyphens, underscores, periods, and commas, and `wordListType` with full words, syllables, and three letters. A 1Password staff reply on its community forum lists the same separators. An older guide on ScreenRant gives a range of 3 to 15 words, which no 1Password page confirms. multipass offers full words and syllables, and leaves out three letters: no 1Password page says what that list holds or how it draws from it, so multipass could not produce the same kind of password.
- **PIN.** The SDK's recipe has one field, `length`.
- **Not offered.** None of these pages mentions avoiding look-alike characters or excluding characters, and none gives a range or default beyond the CLI's. `--no-lookalikes`, `--exclude`, `--symbols`, and `--rules` go beyond 1Password, for the per-site rules the owner asked for.
- **The word list.** The EFF published its large list in 2016 for dice-based passphrases: 7,776 words, five dice rolls each, chosen to be easy to type and remember.
