---
status: draft
priority: next
---

# Websites

Each entry can list the websites where its password is used, any number of them, and `multipass find <url>` names the entries for a page, so a browser extension or the Mac and iPhone app can offer the right entry on the right site.

## 1. Problem

An entry has a name and five kinds of field: `secret`, `username`, `notes`, `otp`, and, with the mergeable store, earlier secrets. The name is only a label you choose, such as `github.com work`, and nothing in multipass reads it as a website. So no program can ask multipass which entries belong to the page it is showing.

That blocks two things you want. A browser extension that offers the right login on each site needs a list of sites per entry. The passkeys plan's app hosts an AutoFill credential provider extension, and macOS and iOS offer a provider's passwords on a site only when the provider registers each password with the site's domain (`ASCredentialServiceIdentifier`). Many accounts also sign in at more than one place, such as `accounts.example.com` and `portal.example.com`, or a company's separate admin and user portals, so one entry needs several websites.

## 2. Solution

A new repeatable field, `website`, holds one web address per line, in any number. `multipass add <name> --website <url>` sets them when you add an entry, and `multipass website <name>` lists, adds, and removes them later without touching the secret. `multipass find <url>` prints the names of the entries whose websites match a page. A website matches a page when the page uses the same host or a subdomain of it, with the same scheme and port, and a leading `www.` is ignored on both sides. The field needs a new store format number. Websites are not secrets, but they live inside the encrypted store like everything else, so the file on disk still reveals nothing about your accounts.

```console
$ multipass add "example work" --username sam --website accounts.example.com --website https://portal.example.com/login
$ multipass website "example work" --add admin.example.com
$ multipass website "example work"
https://accounts.example.com
https://portal.example.com/login
https://admin.example.com
$ multipass find https://portal.example.com/dashboard
example work
```

### 2.1 The field

```text
multipass 4
example work
	modified 1764260000000
	secret hunter2
	username sam
	website https://accounts.example.com
	website https://portal.example.com/login
	website https://admin.example.com
```

| Rule | Detail |
| --- | --- |
| Repeatable | An entry holds zero or more `website` lines, in the order you added them. A duplicate, after normalizing, is refused with `example work already lists https://admin.example.com`. |
| Normalized on input | A bare host such as `github.com` becomes `https://github.com`. The scheme and host are lowercased. A default port (`:443` for `https`, `:80` for `http`) is dropped. A path, query, or fragment is kept as you typed it, because it names the login page to open. |
| Allowed values | `https` and `http` addresses with an ASCII host. Any other scheme, a host with characters outside ASCII, or a value with a space or control character is refused, naming the value. A host in another script must be entered in its `xn--` form, because converting it needs Unicode's IDNA tables, which would be a large data file. |
| Not a secret | The field is ordinary text. It is escaped like every field, and it may appear in error messages, which name a website but never a secret. |

### 2.2 Matching

`find <url>` and every later caller use one function, `website::matches(stored, page)`:

1. Both addresses are normalized as § 2.1 says, and a leading `www.` is removed from each host.
2. The schemes must agree, except that a stored `http` address also matches an `https` page, since a site that moved to `https` is still that site. A stored `https` address never matches an `http` page, so a password is never offered over plain HTTP when you saved it for HTTPS.
3. The ports must agree.
4. The page's host must equal the stored host or end with `.` followed by it. So `example.com` matches `portal.example.com`, but `portal.example.com` does not match `example.com` or `admin.example.com`, and `example.com` never matches `notexample.com`.
5. The path is ignored.

`find` prints each matching entry's name once, sorted, and exits 1 when none matches, so a script can test it. It opens the store, so it asks for the passphrase like `get`.

The matching rule awaits the owner (§ 6).

### 2.3 Commands

| Command | Effect |
| --- | --- |
| `add <name> --website <url>` | Repeatable. Sets the new entry's websites. With `--force` on an existing entry, the websites you pass replace the old ones, and with no `--website` the old ones stay, as `--force` keeps the one-time password today. |
| `website <name>` | Lists the entry's websites, one per line. |
| `website <name> --add <url>` | Repeatable in one command. Appends websites. |
| `website <name> --remove <url>` | Repeatable. Removes websites, matching the normalized value exactly, and fails naming any that is not listed. |
| `find <url>` | Prints the names of the matching entries (§ 2.2). |
| `get <name> --field website` | Prints the websites, one per line, like `website <name>`. |

Changing websites is a change to the entry, so it takes a stamp from `Store::stamp` and merges like any other change. Two Macs that change the same entry's websites before seeing each other's change keep the newer one, as the mergeable store does for every field.

### 2.4 Store format

Adding a field means a new `multipass <n>` header, and `Store::from_text` keeps reading every earlier format. The passkeys plan, a draft waiting on a prototype, has claimed format 4. This plan is smaller and likely ships first, so it takes format 4 and the passkeys plan moves to 5, edited in this plan's pull request. If passkeys ships first, this plan takes the next number instead. Either way, an entry in the new format may hold `website` lines, and a store from an older format reads with none.

### 2.5 Changes by file

| File | Change |
| --- | --- |
| `src/website.rs` | New. `normalize(&str) -> Result<String>` and `matches(stored, page) -> bool`, with no cryptography, since websites are not secrets. |
| `src/store.rs` | `Entry::websites: Vec<String>`, the `website` field line, and the new format number. |
| `src/main.rs` | `--website` on `add`, the `website` and `find` commands, `--field website`, and `USAGE`. |
| `README.md` | A section on websites and `find`, and the recovery example shows a `website` line. |
| `AGENTS.md` | The store format note names the new number. |
| `docs/projects/passkeys/readme.md` | Format 4 becomes format 5, and § 2 notes that the app can register each entry's websites with the system's credential identity store for password AutoFill. |

## 3. Why this design

- **A repeatable field, not a list in one line.** Each `website` line is one value, like every other field, so the store text stays readable with `age -d` and needs no separator that a web address could contain.
- **Match by host and subdomain, without the Public Suffix List.** Matching every host under the same registrable domain, as some password managers do, needs the Public Suffix List to know that `example.co.uk` is one site but `co.uk` is not. That list is a data file of a few hundred kilobytes that its maintainers update often, so multipass would have to ship and refresh it. Matching the stored host and its subdomains needs no list. It also never offers a password across tenants of a shared host, such as two sites under `github.io`, because an entry stores the tenant's own host.
- **`www.` ignored.** Sites serve the same login with and without `www.`, so treating them as one host saves you a second line for nearly every site.
- **HTTPS never downgrades.** Offering a password saved for `https` to an `http` page would send it in the clear.
- **`find` in the CLI now.** A browser extension, and the app's AutoFill registration, both need "which entries belong to this page". Building it once in Rust, with tests, gives every later caller the same answer.
- **Deferred: the browser extension.** It needs a way for the browser to reach multipass, such as Chrome's native messaging host, and a decision about how it unlocks the store, which the session-unlock plan's agent may answer. Its own plan comes later.
- **Deferred: per-site password rules.** The password-generation plan's `--rules` could later look up a site's rules by an entry's website, from Apple's open `password-manager-resources` data. That needs this field first.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| `multipass add x --website github.com --website https://Gist.GitHub.com:443/` then `multipass website x` | `https://github.com` and `https://gist.github.com/` |
| `multipass website x --add github.com` | Fails: `x already lists https://github.com` |
| `multipass find https://www.github.com/login` | Prints `x` |
| `multipass find http://github.com` | Exits 1 with no output, because the entry stored `https` |
| `multipass find https://notgithub.com` | Exits 1 |
| `multipass website x --remove https://github.com`, then `age -d` on the store | The store shows only the `gist.github.com` line for `x`, and the entry's `modified` changed |
| `multipass add y --website ftp://example.com` | Fails, naming `ftp://example.com` |
| A store from the previous format | Opens, with no websites on any entry |

Tests that must fail before the change and pass after it:

- **Matching table.** Each row of § 2.2 as a pair that matches and one that does not, including `example.com` against `notexample.com`, `www.` on either side, a stored `http` against an `https` page, the reverse, and a different port. Catches a suffix test without the dot, which would offer a password to a look-alike domain.
- **Normalizing.** Uppercase hosts, default ports, a bare host, a trailing slash kept, and each refused value. Catches two spellings of one site that would both be stored.
- **Round trip.** An entry with three websites goes through `to_text` and `from_text` unchanged and in order, and a merge of two versions keeps the newer version's list whole. Catches a merge that interleaves two lists.

## 5. Cost

Each website adds one short line to its entry. `find` compares the page with every stored website, a few hundred string comparisons for a few hundred entries, against a third of a second of scrypt to open the store.

## 6. Open questions

1. **How strictly a website matches.** Recommended: the same host or any subdomain of it, with `www.` ignored, as § 2.2 describes. The alternative is the whole site, every host under the same registrable domain, which needs the Public Suffix List as a data file. Owner: the user.
